"""nb_curl.session —— requests 风格的 Session

关键设计：

* **连接池按指纹隔离**：每个 (指纹, verify, proxy, http_version) 组合对应一个
  native easy handle。TLS 指纹只在新建连接时生效，所以切换指纹必须换 handle，
  否则会复用到旧指纹的 TLS 连接（这是最容易踩的坑）。
* **每次请求全量重设 option**：不依赖任何跨请求残留，从根上避免"第二次请求
  丢 header"这类问题。
* **impersonate 先于用户头下发**：libcurl 内部把浏览器默认头放在
  CURLOPT_HTTPBASEHEADER，用户头放 CURLOPT_HTTPHEADER，两者按序合并。
* **cookie 只有一条通道**：内建 cookie 引擎负责把 cookie 拼进 ``Cookie:`` 头，
  Python 侧只管把"该有哪些 cookie"同步进引擎（``CURLOPT_COOKIELIST``）。两条路
  并存会让同一个 cookie 被拼两遍（``Cookie: sid=x; sid=x``），所以本模块**绝不**
  设置 ``CURLOPT_COOKIE``。
* **stream=True 是真流式**：请求体在后台线程里传，写回调把每一块当场交给
  Python（见 :class:`_StreamReader`），不经过 C 层缓冲，内存占用与响应体大小无关。

参数（``Session(...)`` / ``get(...)`` 能传什么、怎么给）统一在
:mod:`nb_curl.params` 声明与说明，本模块只管实现。
"""

from __future__ import annotations

import json as _json
import os
import threading
import time
import uuid
import weakref
from collections import deque
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Iterator, Mapping, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ._facade import (
    SessionShortcuts,
    delete,
    get,
    head,
    options,
    patch,
    post,
    put,
    request,
)
from ._native import lib
from .const import (
    CURLINFO_EFFECTIVE_URL,
    CURLINFO_HTTP_VERSION,
    CURLINFO_PRIMARY_IP,
    CURLINFO_PROXY_ERROR,
    CURLINFO_REDIRECT_COUNT,
    CURLINFO_RESPONSE_CODE,
    CURLINFO_TOTAL_TIME,
    http_version_name,
    resolve_http_version,
)
from .exceptions import (
    ConnectTimeout,
    FingerprintError,
    NbCurlError,
    ImpersonateError,
    ProxyError,
    RequestError,
    TCPShapeError,
    Timeout,
    TooManyRedirects,
    curl_error_detail,
)
from .fingerprint import Fingerprint, FingerprintOverrides, build_overrides
from .impersonate import is_available, resolve_target
from .models import (
    CookieJar,
    Headers,
    Request,
    Response,
    _netscape_cookie_line,
    expired_cookie_line,
    parse_cookie_line,
    parse_header_blocks,
)
from .options import CurlOpt, apply_curl_options
from .params import (
    REQUEST_KEYS,
    SESSION_DEFAULTS,
    SESSION_KEYS,
    RequestOptions,
    SessionOptions,
    Unpack,
    check_options,
)
from .tcp import (
    TcpProfile,
    build_tcp_profile,
    emit_warning,
    plan_rcvbuf,
    verify_actual,
)
from .xcctls import load_fp_snapshot

__all__ = ["Session", "request", "get", "post", "put", "patch", "delete", "head", "options"]

_DEFAULT_CA_ENV = "NB_CURL_CA_BUNDLE"

# libcurl 错误码
_CURLE_OPERATION_TIMEDOUT = 28
_CURLE_COULDNT_CONNECT = 7
_CURLE_COULDNT_RESOLVE_HOST = 6
_CURLE_COULDNT_RESOLVE_PROXY = 5
_CURLE_PROXY = 97
_CURLE_TOO_MANY_REDIRECTS = 47
# 写回调返回 0 让 libcurl 中止传输（我们主动 close 流式响应时就是这条）
_CURLE_WRITE_ERROR = 23

# "连接复用失败"类错误：服务端已经悄悄关了连接（或 GOAWAY 了 stream），
# 而 libcurl 仍尝试在旧连接上发请求。典型表现就是 HTTP2 framing layer 错误。
# 这类错误重试（并强制新建连接）几乎必然成功。
_CURLE_PARTIAL_FILE = 18
_CURLE_GOT_NOTHING = 52
_CURLE_SEND_ERROR = 55
_CURLE_RECV_ERROR = 56
_CURLE_HTTP2 = 16
_CURLE_HTTP2_STREAM = 92
_REUSE_FAILURE_CODES = frozenset({
    _CURLE_HTTP2, _CURLE_HTTP2_STREAM, _CURLE_SEND_ERROR,
    _CURLE_RECV_ERROR, _CURLE_GOT_NOTHING, _CURLE_PARTIAL_FILE,
})

# RFC 7231：安全/幂等方法，重发不会产生副作用
_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE"})

# 桌面浏览器预设名前缀（C 内核 impersonations[] 表的浏览器系）。
_BROWSER_PRESET_PREFIXES = (
    "chrome", "edge", "brave", "opera", "vivaldi", "firefox", "safari",
)

# 真实浏览器 HTTP/1.1 请求的第二行永远是 `Connection: keep-alive`（紧跟 Host）。
# 预设表里没有这一条；而 HTTP/2 下 libcurl 按 RFC 9113 会丢弃 Connection
# （真实 Chrome 也不发），所以补上不会改变 H2 报文。
_CONNECTION_ORDER = "Host,Connection"


# --------------------------------------------------------------------------- #
# 小工具
# --------------------------------------------------------------------------- #
def _pick(options: Mapping[str, Any], key: str, session_value: Any) -> Any:
    """请求级优先：传了（非 None）就用它，否则用会话级的值。"""
    value = options.get(key)
    return session_value if value is None else value


def _session_default(options: Mapping[str, Any], key: str) -> Any:
    """取会话级参数，缺省时回落到 :data:`nb_curl.params.SESSION_DEFAULTS`。"""
    value = options.get(key)
    return SESSION_DEFAULTS.get(key) if value is None else value


def _as_bytes(value: Any) -> bytes | None:
    """str -> utf-8 bytes；None / bytes 原样返回。"""
    if value is None:
        return None
    return value.encode("utf-8") if isinstance(value, str) else value


def _or_neg1(value: int | None) -> int:
    """C 层约定 ``-1`` = 这一项不设。"""
    return -1 if value is None else int(value)


# 判断"环境变量里的代理"时，必须用 C 端（libcurl）的读法，不能读 ``os.environ``。
#
# libcurl 取值走 ``curl_getenv()``（``lib/getenv.c``）：Windows 上是
# ``GetEnvironmentVariable``，**查表不分大小写**；其余平台是 ``getenv()``，**区分大小写**。
#
# 为什么不直接读 ``os.environ``：Windows 的环境块允许同名不同大小写的两项共存
# （``https_proxy`` 与 ``HTTPS_PROXY`` 是两条独立记录），``GetEnvironmentVariable``
# 大小写不敏感地查得到任意一条；``os.environ`` 却把键统一转成大写，``pop`` 只发一次
# ``unsetenv("HTTPS_PROXY")``，而 ``SetEnvironmentVariable(name, NULL)`` 一次只删掉一项
# —— 小写的 ``https_proxy`` 会活下来。于是出现"Python 里删了、libcurl 照样走代理"，
# 读数自然也对不上。所以这里直接问系统，与 C 端逐字一致。
if os.name == "nt":
    import ctypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _GetEnvironmentVariableW = _kernel32.GetEnvironmentVariableW
    _GetEnvironmentVariableW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    _GetEnvironmentVariableW.restype = ctypes.c_uint32

    def _env_lookup(name: str) -> str | None:
        """按 C 端的语义（``GetEnvironmentVariable``）读环境变量：不分大小写。"""
        size = 32768                       # 与 curl 里写死的上限一致
        buf = ctypes.create_unicode_buffer(size)
        n = _GetEnvironmentVariableW(name, buf, size)
        # n == 0 表示不存在；取到空串也当作不存在（curl 的处理相同）
        if n == 0 or n >= size:
            return None
        return buf.value or None
else:
    def _env_lookup(name: str) -> str | None:
        """按 C 端的语义（``getenv``）读环境变量：区分大小写。"""
        return os.environ.get(name) or None


def _env_proxy_names(url: str) -> list[str]:
    """按 libcurl 的查找顺序列出可能对这次请求生效的代理环境变量名。

    顺序照搬 libcurl ``lib/proxy.c``：先 scheme 专属（https/wss 看 ``https_proxy``
    与 ``HTTPS_PROXY``；http/ws **只看小写** ``http_proxy``，curl 有意忽略大写
    ``HTTP_PROXY`` 以免 CGI 环境被请求头带偏），都没有再看 ``all_proxy`` / ``ALL_PROXY``。
    """
    parts = urlsplit(url)
    scheme = (parts.scheme.lower() if "://" in url else "http") or "http"
    if scheme in ("https", "wss"):
        names = ["https_proxy", "HTTPS_PROXY"]
    elif scheme in ("http", "ws"):
        names = ["http_proxy"]
    else:
        names = ["%s_proxy" % scheme, "%s_PROXY" % scheme.upper()]
    return names + ["all_proxy", "ALL_PROXY"]


def _env_proxy_hint(url: str) -> str | None:
    """环境变量里有没有代理会拦到这次请求（TCP 画像必须走真实链路，见 _build_tcp）。

    返回形如 ``"http_proxy=http://127.0.0.1:7890"`` 的描述，没有则 None。
    尊重 ``no_proxy``。读法同 C 端（``_env_lookup``），见其上方说明。
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    no_proxy = _env_lookup("no_proxy") or _env_lookup("NO_PROXY") or ""
    bypass = {p.strip().lstrip(".") for p in no_proxy.split(",") if p.strip()}
    for env in _env_proxy_names(url):
        value = _env_lookup(env)
        if not value:
            continue
        if host and any(host == p or host.endswith("." + p) for p in bypass):
            continue
        return "%s=%s" % (env, value)
    return None


def _proxy_in_use(proxy: str | None, url: str) -> str | None:
    """这次请求实际会走的代理（描述串）；没配返回 None。

    装配结果优先，没有就看环境变量 —— 与 libcurl 的取值顺序一致。
    ``proxy=""`` 是"显式禁用"，此时连环境变量也不看。
    """
    if proxy is None:
        return _env_proxy_hint(url)
    return proxy or None


def _origin_of(url: str) -> tuple:
    """(scheme, host, port) —— 连接复用是以 origin 为单位的。"""
    parts = urlsplit(url)
    scheme = (parts.scheme or "https").lower()
    host = (parts.hostname or "").lower()
    port = parts.port or (443 if scheme == "https" else 80)
    return scheme, host, port


def _default_ca_path() -> str | None:
    """找一个可用的 CA bundle：环境变量 > certifi > 包内自带。"""
    env = os.environ.get(_DEFAULT_CA_ENV)
    if env and os.path.isfile(env):
        return env
    try:
        import certifi  # type: ignore

        path = certifi.where()
        if path and os.path.isfile(path):
            return path
    except Exception:  # noqa: BLE001
        pass
    bundled = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_lib", "cacert.pem")
    return bundled if os.path.isfile(bundled) else None


def _to_bytes(data: Any) -> bytes:
    if data is None:
        return b""
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    return data.encode("utf-8") if isinstance(data, str) else str(data).encode("utf-8")


def _merge_url(url: str, params: Any) -> str:
    if not params:
        return url
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query.extend(params.items() if isinstance(params, Mapping) else params)
    return urlunsplit(parts._replace(query=urlencode(query, doseq=True)))


def _merge_headers(base: Sequence[tuple[str, str]], extra: Any) -> list[tuple[str, str]]:
    """extra 覆盖 base 中的同名头（保持 base 的位置），新头追加在尾部。

    extra 可以是 Mapping 或 (name, value) 序列。
    """
    result = list(base)
    index: dict[str, int] = {}
    for i, (name, _) in enumerate(result):
        index.setdefault(name.lower(), i)
    pairs = list(extra.items()) if hasattr(extra, "items") else list(extra)
    for name, value in pairs:
        key = name.lower()
        if key in index:
            result[index[key]] = (name, value)
        else:
            index[key] = len(result)
            result.append((name, value))
    return result


def _is_browser_preset(spec: str | None) -> bool:
    """impersonate 说明是否指向桌面浏览器预设；`:no` 这种否定式不算。"""
    name, _, flag = (spec or "").partition(":")
    if flag.strip().lower() in ("no", "false", "0", "off"):
        return False
    return name.strip().lower().startswith(_BROWSER_PRESET_PREFIXES)


def _encode_multipart(fields: Mapping[str, Any], files: Mapping[str, Any],
                      boundary_style: str = "webkit") -> tuple[bytes, str]:
    """自己拼 multipart/form-data，避免依赖 CURLOPT_MIMEPOST。"""
    if boundary_style == "webkit":
        boundary = "----WebKitFormBoundary" + uuid.uuid4().hex[:16]
    else:
        boundary = "--------------------------" + uuid.uuid4().hex[:24]

    out = bytearray()

    def part_header(name: str, filename: str | None = None,
                    content_type: str | None = None) -> None:
        out.extend(b"--" + boundary.encode() + b"\r\n")
        disp = 'Content-Disposition: form-data; name="%s"' % name
        if filename is not None:
            disp += '; filename="%s"' % filename
        out.extend(disp.encode("utf-8") + b"\r\n")
        if content_type:
            out.extend(("Content-Type: %s" % content_type).encode("utf-8") + b"\r\n")
        out.extend(b"\r\n")

    for name, value in (fields or {}).items():
        if value is None:
            continue
        part_header(name)
        out.extend(_to_bytes(value) + b"\r\n")

    for name, file_value in (files or {}).items():
        if isinstance(file_value, tuple):
            filename = file_value[0]
            payload = file_value[1]
            content_type = file_value[2] if len(file_value) > 2 else None
        else:
            filename = os.path.basename(getattr(file_value, "name", name))
            payload = file_value
            content_type = None
        part_header(name, filename, content_type)
        out.extend(_to_bytes(payload) + b"\r\n")

    out.extend(b"--" + boundary.encode() + b"--\r\n")
    return bytes(out), boundary


def _build_body(options: Mapping[str, Any]) -> tuple[bytes | None, list[tuple[str, str]]]:
    """按 files > json > data 的优先级拼请求体，返回 (body, 需要补的 Content-Type)。"""
    files = options.get("files")
    data = options.get("data")
    if files:
        body, boundary = _encode_multipart(data if isinstance(data, Mapping) else {}, files)
        return body, [("Content-Type", "multipart/form-data; boundary=%s" % boundary)]
    payload = options.get("json")
    if payload is not None:
        return (_json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                [("Content-Type", "application/json")])
    if data is None:
        return None, []
    if isinstance(data, Mapping):
        return (urlencode(data, doseq=True).encode("utf-8"),
                [("Content-Type", "application/x-www-form-urlencoded")])
    return _to_bytes(data), []


def _pick_proxy(proxy: Any, proxies: Any, scheme: str) -> str | None:
    """从一组 (proxy, proxies) 里选出对 scheme 生效的代理；没给返回 None。

    返回 ``""`` 表示**显式禁用**（见 :meth:`Session._proxy_for`）。
    """
    if isinstance(proxy, Mapping):
        # 容错：proxy= 误传了 dict，按 proxies 语义处理
        proxies = proxy if proxies is None else proxies
        proxy = None
    if proxy is not None:
        return str(proxy)
    if isinstance(proxies, Mapping):
        picked = proxies.get(scheme) or proxies.get("all") or proxies.get("https")
    else:
        picked = proxies
    return str(picked) if picked else None


def _parse_cookie_pairs(value: str) -> list[tuple[str, str]]:
    """把用户显式给的 ``Cookie:`` 头值拆成 ``[(name, value), …]``。

    值原样保留（只有名字与分隔用的空白会被去掉），因为有些站点的签名 cookie
    里带 ``=`` 之类的字符。
    """
    pairs: list[tuple[str, str]] = []
    for item in value.split(";"):
        item = item.strip()
        if not item:
            continue
        name, _, val = item.partition("=")
        name = name.strip()
        if name:
            pairs.append((name, val))
    return pairs


def _header_lines_arg(pairs: Sequence[tuple[str, str]]) -> list[bytes]:
    """把 (name, value) 序列编码成 C 侧的 header 行数组（保序、保重复）。"""
    lines: list[bytes] = []
    for name, value in pairs:
        if value is None:
            lines.append(("%s:" % name).encode("utf-8"))  # value=None = 移除该默认头
            continue
        text = str(value)
        if "\r" in text or "\n" in text:
            raise NbCurlError("头部值不能包含换行: %r" % name)
        lines.append(("%s: %s" % (name, text)).encode("utf-8"))
    return lines


def _resolve_entries(resolve: Any) -> list[str]:
    """把 resolve 参数规范化成 CURLOPT_RESOLVE 的条目列表。

    ``{"example.com:443": "1.2.3.4"}``（值可以是地址序列）
    或已经是 ``"host:port:addr"`` 形式的字符串序列。
    """
    if not resolve:
        return []
    if isinstance(resolve, Mapping):
        entries: list[str] = []
        for host_port, addr in resolve.items():
            key = str(host_port)
            if ":" not in key:
                raise NbCurlError("resolve 的键要写成 'host:port'，收到 %r" % (host_port,))
            text = addr if isinstance(addr, str) else ",".join(str(a) for a in addr)
            entries.append("%s:%s" % (key, text))
        return entries
    if isinstance(resolve, str):
        return [resolve]
    return [str(item) for item in resolve]


def _ech_value(ech: Any) -> str | None:
    """把 ech 参数（bool/str）规范化成 curl CURLOPT_ECH 的字符串取值。"""
    if ech is None:
        return None
    if ech is True:
        return "true"
    if ech is False:
        return "false"
    return str(ech)


def _curl_opts_key(opts: Any) -> tuple:
    """把 curl_options dict 序列化成可哈希的 pool key 片段。"""
    if not opts:
        return ()
    items = opts.items() if hasattr(opts, "items") else opts
    return tuple(sorted((int(k), repr(v)) for k, v in items))


# --------------------------------------------------------------------------- #
# 连接池
# --------------------------------------------------------------------------- #
class _Handle:
    """一个 native easy handle + 它自己的连接缓存。"""

    __slots__ = ("ptr", "busy", "tcp_profile", "pushed_cookies")

    def __init__(self, ptr: Any = None):
        if ptr is None:
            ptr = lib.easy_init()
            if not ptr:
                raise NbCurlError("easy_init() 失败：native 句柄创建不成功")
        self.ptr = ptr
        self.busy = False
        # 当前这只 handle 上生效的 TCP 画像（tuple 或 None）；换了画像要强制新建连接
        self.tcp_profile: tuple | None = None
        # 已经同步进本 handle 的 cookie 引擎的 cookie（作用域键 -> 规范行）。
        # 用来做增量下发：只推引擎里还缺的，并据此删掉会话罐里已经不存在的。
        self.pushed_cookies: dict[tuple, str] = {}
        lib.easy_set_cookie_engine(ptr, 1)  # 开启内存 cookie 引擎，记录 Set-Cookie

    def close(self) -> None:
        if self.ptr:
            lib.easy_cleanup(self.ptr)
            self.ptr = None

    def __del__(self):  # pragma: no cover - 兜底
        try:
            self.close()
        except Exception:  # noqa: BLE001
            pass


class _Pool:
    """同一指纹下的 handle 池：优先复用空闲 handle，空闲不足则按上限新建。"""

    def __init__(self, max_size: int):
        self._cond = threading.Condition()
        self._handles: list[_Handle] = []
        self._max = max(1, int(max_size))
        self._draining = False

    def acquire(self) -> _Handle:
        with self._cond:
            while True:
                for handle in self._handles:
                    if not handle.busy:
                        handle.busy = True
                        return handle
                if len(self._handles) < self._max:
                    handle = _Handle()
                    handle.busy = True
                    self._handles.append(handle)
                    return handle
                self._cond.wait()

    def release(self, handle: _Handle) -> None:
        close_later = False
        with self._cond:
            handle.busy = False
            if self._draining:
                # close() 已把空闲 handle 拿走，但本 handle 当时 busy 被跳过；
                # 现在请求结束，补关掉它，否则它的连接会泄漏。
                self._handles.remove(handle)
                close_later = True
            self._cond.notify()
        if close_later:
            handle.close()

    def drain(self) -> list[_Handle]:
        """取出所有**空闲** handle 供 close；busy（正在请求）的跳过，
        由 release() 在请求结束后补关，避免与 curl_easy_perform 并发 free。"""
        with self._cond:
            self._draining = True
            idle = [h for h in self._handles if not h.busy]
            self._handles = [h for h in self._handles if h.busy]
            self._cond.notify_all()
        return idle

    def __len__(self) -> int:
        with self._cond:
            return len(self._handles)


# --------------------------------------------------------------------------- #
# 一次请求的装配结果
# --------------------------------------------------------------------------- #
@dataclass
class _Prep:
    """请求/握手准备阶段的产物：算好所有生效值，下发阶段直接取用。"""

    method: str
    url: str
    key: tuple
    fingerprint: Fingerprint
    verify: bool
    ca_path: str | None
    proxy: str | None
    resolve_entries: list[str]
    redirects: bool
    max_redirects: int
    http_version: Any
    timeout: float | None
    connect_timeout: float | None
    userpwd: str | None
    ech: Any
    doh: str | None
    dns_cache_ttl: int | None
    interface: str | None
    pinned_key: str | None
    max_download_speed: int | None
    max_upload_speed: int | None
    curl_options: Any
    headers: list[tuple[str, str]]
    cookie_pairs: list[tuple[str, str]]
    host: str
    stream: bool
    body: bytes | None


@dataclass(frozen=True)
class _Info:
    """perform 之后从 handle 上读回的信息（curl_getinfo_*）。"""

    url: str
    http_version: int
    primary_ip: str
    redirect_count: int
    total_time: float | None
    proxy_error: int | None = None   # CURLINFO_PROXY_ERROR，仅 CURLE_PROXY 时有意义


def _read_info(handle: _Handle) -> _Info:
    ptr = handle.ptr
    return _Info(
        url=lib.getinfo_string(ptr, CURLINFO_EFFECTIVE_URL) or "",
        http_version=lib.getinfo_long(ptr, CURLINFO_HTTP_VERSION) or 0,
        primary_ip=lib.getinfo_string(ptr, CURLINFO_PRIMARY_IP) or "",
        redirect_count=lib.getinfo_long(ptr, CURLINFO_REDIRECT_COUNT) or 0,
        total_time=lib.getinfo_double(ptr, CURLINFO_TOTAL_TIME),
        # 97 才有内容；其它错误码读回来是 0，直接换算成 None，免得干扰文案
        proxy_error=lib.getinfo_long(ptr, CURLINFO_PROXY_ERROR) or None,
    )


def _build_response(prep: _Prep, info: _Info, status: int, content: bytes,
                    raw_headers: bytes, wall: float, cookie_dump: str) -> Response:
    url = info.url or prep.url
    blocks = parse_header_blocks(raw_headers)
    if blocks:
        final_status, reason, final_headers = blocks[-1]
        history = [
            Response(status_code=c, headers=h, content=b"", url=url, reason=r, elapsed=0.0)
            for c, r, h in blocks[:-1]
        ]
    else:
        final_status, reason, final_headers = status, "", Headers()
        history = []

    return Response(
        status_code=final_status or status,
        headers=final_headers,
        content=content,
        url=url,
        reason=reason,
        http_version=http_version_name(int(info.http_version)),
        primary_ip=info.primary_ip,
        elapsed=info.total_time if info.total_time else wall,
        history=history,
        redirect_count=info.redirect_count,
        request=Request(prep.method, prep.url, Headers(prep.headers)),
        cookie_list=cookie_dump,
    )


# --------------------------------------------------------------------------- #
# 流式响应体（stream=True）
# --------------------------------------------------------------------------- #
#: 队列里最多先缓冲这么多字节：满了就把写回调卡住，消费者跟不上时靠 TCP 背压让
#: 服务端慢下来 —— 于是内存占用与响应体大小无关（跟得上时实际只缓冲几十 KB）。
_STREAM_HIGH_WATER = 1 << 20
#: 整体读（``Response.content``）时的分块大小
_STREAM_READ_CHUNK = 65536
#: close() 等后台线程收尾的秒数
_STREAM_CLOSE_GRACE = 1.0
#: 会被自动跟随的重定向状态码（判断"这个响应块是不是最终响应"用）
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


class _StreamReader:
    """``stream=True`` 的响应体：后台线程跑 perform，本类把 chunk 一块块交出去。

    * 后台线程只负责 ``perform``；写回调每收到一块就当场拷成 ``bytes`` 塞进队列
      （不经过 C 层缓冲），所以 ``iter_content()`` 拿到的是真·增量数据；
    * 队列到 ``_STREAM_HIGH_WATER`` 就卡住写回调 —— 靠 TCP 背压限速，而不是无限攒内存；
    * 响应头由 Python 侧的回调累积，因此 ``get(stream=True)`` 返回时 ``status_code`` /
      ``headers`` 就已经可用（对齐 requests），不必等整个响应体下载完；
    * 读取是个**游标**：``iter_content()`` 可以分几次接着读，中途 ``break`` 也不丢数据；
    * ``Response.close()`` 让写回调返回 0，libcurl 立即中止传输并释放连接；
      响应对象被回收（没人再用它）时也会中止 —— 不会留下后台线程和半开的连接。
    """

    def __init__(self, session: "Session", prep: _Prep, response: Response):
        self._session = session
        self._prep = prep
        # 弱引用：响应对象必须能在"没人用了"的时候被回收 —— 回收时它会回调
        # close(join=False) 通知我们中止传输。这里要是持强引用，响应就永远收不掉，
        # 后台线程会一直卡在背压上，线程和连接一起泄漏。
        self._response_ref = weakref.ref(response)
        self._handle: _Handle | None = None
        self._keepalive: Any = None          # 回调对象，必须活到 perform 结束
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._chunks: deque[bytes] = deque()
        self._buffered = 0
        self._done = False
        self._abort = False
        self._code = 0
        self._error: str | None = None
        self._pxcode: int | None = None          # CURLINFO_PROXY_ERROR（97 才有）
        self._exc: BaseException | None = None   # perform 之外冒出来的异常，原样抛回调用方
        self._status = 0
        self._wall = 0.0
        self._blocks: list[tuple[int, str, Headers]] = []
        self._raw_headers = bytearray()
        self._cookie_dump = ""
        self._transient: list[tuple] = []
        self._consumed = False
        self._thread: threading.Thread | None = None

    # -- 生命周期 ---------------------------------------------------------- #
    def start(self, tcp_profile: TcpProfile | None) -> None:
        """装配独立 handle、起后台线程，并等到**最终响应头**到达再返回。

        独立 handle（不占连接池）是有意的：这块连接完全属于这条流，``close()``
        能干净地中止它，也不会把"正在流式读"的状态留在池里。
        """
        session = self._session
        handle = _Handle()
        self._handle = handle
        session._apply_fingerprint(handle.ptr, self._prep.fingerprint)
        session._apply_tcp(handle, tcp_profile)
        session._apply_handle_options(handle.ptr, self._prep)
        self._transient = session._sync_cookies(
            handle.ptr, self._prep, handle.pushed_cookies)
        # 响应体/响应头回调换成 Python 的：数据不再进 C 层缓冲，边到边给
        self._keepalive = lib.install_stream_callbacks(
            handle.ptr, self._on_chunk, self._on_header)
        self._thread = threading.Thread(
            target=self._run, name="nb-curl-stream", daemon=True)
        session._streams.add(self)
        self._thread.start()
        self.wait_ready()

    def wait_ready(self) -> None:
        """等最终响应头到达（或传输结束）。

        此时 ``status_code`` / ``headers`` 可用，调用方可以据此决定要不要继续读；
        重定向中间跳不算数，等的是跳完之后那一次响应。
        """
        with self._cond:
            while not self._done and not self._abort and not self._status:
                self._cond.wait()
        self._raise_pending()

    def close(self, *, join: bool = True) -> None:
        """中止传输并释放连接；已经结束的流调用它没有副作用。

        ``join=False`` 只发中止信号、不等后台线程收尾（``Response.__del__`` 用）——
        句柄由后台线程自己在退出时释放，避免与正在跑的 ``perform`` 抢同一个 handle。
        """
        with self._cond:
            self._abort = True
            self._cond.notify_all()
        thread = self._thread
        if not join:
            return
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(_STREAM_CLOSE_GRACE)
        if thread is None or not thread.is_alive():
            self._release_handle()

    def _release_handle(self) -> None:
        """清理 native handle（幂等；后台线程收尾时也会调）。

        必须走 :meth:`_Handle.close`（它会把 ``ptr`` 置空）而不是直接
        ``easy_cleanup(handle.ptr)``：否则 ``_Handle`` 对象被回收时
        ``__del__`` 会拿着同一个指针再 free 一次 —— 双重释放，之后新建的
        handle 会踩到坏内存，表现为莫名其妙的下发失败。
        """
        with self._lock:
            handle, self._handle = self._handle, None
        self._session._streams.discard(self)
        if handle is not None:
            try:
                handle.close()
            except Exception:  # noqa: BLE001
                pass

    # -- 状态 -------------------------------------------------------------- #
    @property
    def response(self) -> Response | None:
        """对应的响应对象（已被回收时为 ``None`` —— 那时数据也没人接手了）。"""
        return self._response_ref()

    @property
    def finished(self) -> bool:
        """后台传输是否已经结束（不代表数据都被取走了）。"""
        with self._cond:
            return self._done

    @property
    def consumed(self) -> bool:
        """是否已经开始被读取过（流是游标，可以接着往下读）。"""
        return self._consumed

    # -- 回调（都在后台线程里被 native 层调用） ---------------------------- #
    def _on_chunk(self, data: bytes) -> bool:
        """写回调：收一块响应体。返回 False 中止传输。"""
        with self._cond:
            while self._buffered >= _STREAM_HIGH_WATER and not self._abort:
                self._cond.wait()            # 消费者还没取走，先卡住（TCP 背压）
            if self._abort:
                return False
            self._chunks.append(data)
            self._buffered += len(data)
            self._cond.notify_all()
        return True

    def _on_header(self, line: bytes) -> bool:
        """头回调：逐行累积响应头，攒完一块就刷新状态（含状态行）。"""
        with self._cond:
            if self._abort:
                return False
            self._raw_headers.extend(line)
            if line in (b"\r\n", b"\n"):
                self._blocks = parse_header_blocks(bytes(self._raw_headers))
                self._refresh_locked()
        return True

    def _refresh_locked(self) -> None:
        """把最新一个**最终**响应块刷进响应对象（调用方需持锁）。

        重定向的中间跳不刷 —— 否则调用方会先看到一个 302。响应对象已经没了
        （被回收）也照常推进状态，好让 ``wait_ready`` 不会一直等。
        """
        if not self._blocks:
            return
        status, reason, headers = self._blocks[-1]
        if (self._prep.redirects and status in _REDIRECT_CODES
                and headers.get("location")):
            return
        self._status = status
        resp = self._response_ref()
        if resp is not None:
            resp.status_code = status
            resp.reason = reason
            resp.headers = headers
            resp.history = [
                Response(status_code=c, headers=h, content=b"", url=self._prep.url,
                         reason=r, elapsed=0.0)
                for c, r, h in self._blocks[:-1]
            ]
        self._cond.notify_all()

    # -- 后台线程 ---------------------------------------------------------- #
    def _run(self) -> None:
        handle = self._handle
        started = time.perf_counter()
        try:
            code, status, _body, raw_headers, error = lib.perform(handle.ptr)
            pxcode = lib.getinfo_long(handle.ptr, CURLINFO_PROXY_ERROR) or None
            with self._cond:
                self._code = code
                self._error = error
                self._pxcode = pxcode
                if status and not self._status:
                    self._status = status      # 无响应体时（HEAD / 204）靠它兜底
                if raw_headers:
                    self._raw_headers.extend(raw_headers)
                self._cookie_dump = lib.get_cookies(handle.ptr)
            self._wall = time.perf_counter() - started
            self._finish()
        except BaseException as exc:  # noqa: BLE001
            with self._cond:
                self._exc = exc
        finally:
            with self._cond:
                self._done = True
                self._cond.notify_all()
            self._release_handle()

    def _finish(self) -> None:
        """传输结束：收尾 cookie（含撤掉本次专用项）并补上最终元信息。"""
        handle = self._handle
        session = self._session
        if handle is not None:
            if self._transient:
                session._drop_transient_cookies(
                    handle.ptr, self._transient, handle.pushed_cookies)
            resp = self._response_ref()
            if resp is not None:
                info = _read_info(handle)
                resp.url = info.url or resp.url
                resp.http_version = http_version_name(int(info.http_version))
                resp.primary_ip = info.primary_ip
                resp.redirect_count = info.redirect_count
                resp.elapsed = timedelta(seconds=info.total_time or self._wall)
        session.cookies._absorb(
            self._cookie_dump, time.time(), frozenset(self._transient))

    # -- 取数 -------------------------------------------------------------- #
    def iter_chunks(self, chunk_size: int = 8192) -> Iterator[bytes]:
        """逐块产出响应体。

        流是一个**游标**：可以分多次调用接着往下读（与 requests 一致），
        也可以中途 ``break`` —— 剩下的数据还在，交给 ``content`` 或下一次
        ``iter_content()`` 读走；真不要了用 ``Response.close()`` 释放连接。
        """
        self._consumed = True
        return self._iter_chunks(max(1, int(chunk_size)))

    def _iter_chunks(self, size: int) -> Iterator[bytes]:
        pending = bytearray()
        while True:
            data = self._take()
            if data is None:
                break
            pending += data
            while len(pending) >= size:
                yield bytes(pending[:size])
                del pending[:size]
        if pending:
            yield bytes(pending)
        self._raise_pending()

    def read_all(self) -> bytes:
        """把还没读的部分整体读出来（``Response.content`` 用）。"""
        out = bytearray()
        for part in self.iter_chunks(_STREAM_READ_CHUNK):
            out += part
        return bytes(out)

    def _take(self) -> bytes | None:
        """取一段已经到达的数据；``None`` = 传输结束且没有剩余。"""
        with self._cond:
            while True:
                if self._chunks:
                    data = self._chunks.popleft()
                    self._buffered -= len(data)
                    self._cond.notify_all()   # 唤醒可能正卡在水位上的写回调
                    return data
                if self._done:
                    return None
                self._cond.wait()

    def _raise_pending(self) -> None:
        """传输异常时抛对应的异常（正常结束 / 主动 close 不抛）。

        有数据可给时不在这里抛 —— 先把已经拿到的内容交给调用方，读完了再抛，
        与 requests 的流式语义一致。
        """
        with self._cond:
            exc, code, error = self._exc, self._code, self._error
            pxcode = self._pxcode
            abort, done, has_data = self._abort, self._done, bool(self._chunks)
        if exc is not None:
            raise exc
        if done and not has_data and not abort and code not in (0, _CURLE_WRITE_ERROR):
            self._session._raise_for_code(
                code, error or lib.strerror(code),
                proxy_error=pxcode,
                proxy_in_use=_proxy_in_use(self._prep.proxy, self._prep.url))


# --------------------------------------------------------------------------- #
# Session
# --------------------------------------------------------------------------- #
class Session(SessionShortcuts):
    """类 requests 的会话对象，支持浏览器指纹。

    所有参数都可以在会话级（``Session(...)``）或请求级（``get`` / ``post`` /
    ``request`` 等）给；请求级传了就覆盖会话级，没传就沿用会话级。

    参数说明与合法取值见 :mod:`nb_curl.params`（``help(nb_curl.params.RequestOptions)``
    或 ``nb_curl.params.describe()``）。常用写法：

    >>> import nb_curl
    >>> with nb_curl.Session(impersonate="chrome152") as s:
    ...     s.get("https://example.com", http_version="2", timeout=10)
    ...     s.post("https://example.com/api", json={"k": "v"},
    ...            tcp={"window": 64240, "wscale": 8}, ttl=64)
    """

    def __init__(self, **options: Unpack[SessionOptions]):
        check_options("Session()", options, SESSION_KEYS)

        # impersonate 也可直接传 Fingerprint 对象（等价于会话级快照）
        impersonate = options.get("impersonate")
        fp_snapshot_arg: Fingerprint | None = None
        if isinstance(impersonate, Fingerprint):
            fp_snapshot_arg = impersonate
            impersonate = None
        elif impersonate is not None:
            # 提前校验，避免每次请求才报错
            if not is_available(impersonate.partition(":")[0].strip()):
                raise ImpersonateError("未知或不可用的 impersonate target: %r" % (impersonate,))

        self.impersonate = impersonate
        self.ja3 = options.get("ja3")
        self.akamai = options.get("akamai")
        diy_fp = options.get("diy_fp")
        self.diy_fp = dict(diy_fp) if diy_fp else None
        self.default_headers = _session_default(options, "default_headers")
        self.h2_priority = options.get("h2_priority")

        # fp_file：浏览器指纹快照（xcctls.top/all 的响应）。
        # 会话级只解析一次（load_fp_snapshot 自带按 mtime+size 的缓存）；
        # 显式传 Fingerprint 对象优先于 fp_file。
        self.fp_file = options.get("fp_file")
        self._fp_snapshot = fp_snapshot_arg if fp_snapshot_arg is not None else (
            load_fp_snapshot(self.fp_file) if self.fp_file is not None else None)

        headers = options.get("headers")
        self.headers = Headers(list(headers.items())) if headers else Headers()
        # cookie 罐：表面仍是 name->value 的 dict，内部按作用域保管规范 cookie 行。
        # cookie 只走内建引擎这一条通道（见 CookieJar 的说明）。
        self.cookies = CookieJar(options.get("cookies"))
        self.auth = options.get("auth")
        self.proxy = options.get("proxy")
        self.proxies = options.get("proxies")
        self.resolve = options.get("resolve")
        self.verify = _session_default(options, "verify")
        ca_path = options.get("ca_path")
        self.ca_path = ca_path if ca_path is not None else (
            _default_ca_path() if self.verify else None)
        self.timeout = options.get("timeout")
        self.connect_timeout = options.get("connect_timeout")
        self.allow_redirects = _session_default(options, "allow_redirects")
        self.max_redirects = _session_default(options, "max_redirects")
        http_version = options.get("http_version")
        if http_version is not None:
            resolve_http_version(http_version)  # 提前校验，别等到发请求才报错
        self.http_version = http_version
        self.max_clients = max(1, int(_session_default(options, "max_clients")))
        self.max_retries = max(0, int(_session_default(options, "max_retries")))
        self.debug = _session_default(options, "debug")

        # 连接 / 解析类 option：影响句柄状态，所以都进连接池 key
        self.ech = options.get("ech")
        self.doh = options.get("doh")
        self.dns_cache_ttl = options.get("dns_cache_ttl")
        self.interface = options.get("interface")
        self.pinned_key = options.get("pinned_key")
        self.max_download_speed = options.get("max_download_speed")
        self.max_upload_speed = options.get("max_upload_speed")
        # 会话级默认是否流式下载（也可以只对某次请求传 stream=True）
        self.stream = options.get("stream")
        self.curl_options = options.get("curl_options")
        self.allow_dangerous_options = _session_default(options, "allow_dangerous_options")

        # TCP 画像：这里先"只校验参数本身"（写错了立刻报错）；
        # "本机做不到"的项留到真正发请求时发警告，免得构造时就炸。
        self.tcp = options.get("tcp")
        self.ttl = options.get("ttl")
        self.timestamps = options.get("timestamps")
        self.tcp_warn = options.get("tcp_warn")
        build_tcp_profile(self.tcp, self.ttl, self.timestamps, warn=False)

        # 会话级 overrides = 快照 overrides（若有）+ 显式 ja3/akamai/diy_fp
        overrides = build_overrides(ja3=self.ja3, akamai=self.akamai, diy_fp=self.diy_fp)
        self._session_overrides = (
            self._fp_snapshot.overrides.merge(overrides)
            if self._fp_snapshot is not None else overrides)

        self._pools: dict[tuple, _Pool] = {}
        self._pools_lock = threading.Lock()
        # 已知"复用会失败"的 origin：后续请求直接强制新建连接，不再每次白白失败一次
        self._no_reuse_origins: set[tuple] = set()
        self._no_reuse_lock = threading.Lock()
        # 还活着的流式响应（弱引用）：close() 时要把它们的后台传输一起中止
        self._streams: weakref.WeakSet = weakref.WeakSet()
        # stream=True 与 tcp= 同用时，事后校验做不了 —— 只提醒一次
        self._stream_tcp_warned = False
        self._closed = False

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #
    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        # 流式响应先收掉：它们的后台传输还占着连接，得先中止再关句柄
        for reader in list(self._streams):
            try:
                reader.close()
            except Exception:  # noqa: BLE001
                pass
        with self._pools_lock:
            pools = list(self._pools.values())
            self._pools.clear()
        for pool in pools:
            for handle in pool.drain():
                handle.close()
        self._closed = True

    def __del__(self):  # pragma: no cover - 兜底
        try:
            self.close()
        except Exception:  # noqa: BLE001
            pass

    @property
    def closed(self) -> bool:
        return self._closed

    # ------------------------------------------------------------------ #
    # 内部：指纹与连接池
    # ------------------------------------------------------------------ #
    def _build_fingerprint(self, options: Mapping[str, Any], h2_priority: Any) -> Fingerprint:
        """合并所有指纹来源，优先级（低 -> 高）：

        impersonate 底座 < 会话级 ja3/akamai/diy_fp < 请求级快照
        < 请求级 ja3/akamai/diy_fp < 显式 ``h2_priority``。

        - ``impersonate`` 传 :class:`Fingerprint` 对象（如 ``parse_xcctls()``
          的结果）-> 当作请求级快照参与合并；
        - ``fp_file``（xcctls.top/all 快照）-> 解析成完整指纹参与合并，
          其自带浏览器头作为最低层默认头（会被 Session/请求级 headers 覆盖）。
        """
        impersonate = options.get("impersonate")
        fp_file = options.get("fp_file")
        req_ja3, req_akamai, req_diy_fp = (
            options.get("ja3"), options.get("akamai"), options.get("diy_fp"))

        req_snap: Fingerprint | None = None
        if isinstance(impersonate, Fingerprint):
            req_snap = impersonate
            impersonate = None

        raw = impersonate if impersonate is not None else self.impersonate

        # 快照：请求级 fp_file / 请求级 Fingerprint 优先于会话级
        if fp_file is not None:
            snap = load_fp_snapshot(fp_file)
        elif req_snap is not None:
            snap = req_snap
        else:
            snap = self._fp_snapshot

        # 底座：显式 impersonate 优先，否则用快照自带的
        c_impersonate = raw
        if not raw and snap is not None and snap.impersonate:
            c_impersonate = snap.impersonate

        # Python 层浏览器默认头（快照自带）
        base_headers = list(snap.headers) if (snap and snap.headers) else []

        fp = Fingerprint(
            impersonate=c_impersonate,
            # 有 Python 层默认头时关掉 C 侧浏览器默认头，避免两套头打架
            default_headers=self.default_headers and not base_headers,
            ja3=_pick(options, "ja3", self.ja3),
            akamai=_pick(options, "akamai", self.akamai),
            diy_fp=_pick(options, "diy_fp", self.diy_fp),
            headers=base_headers or None,
        )

        overrides = self._session_overrides
        if snap is not None and (fp_file is not None or req_snap is not None):
            overrides = overrides.merge(snap.overrides)
        if req_ja3 or req_akamai or req_diy_fp:
            overrides = overrides.merge(
                build_overrides(ja3=req_ja3, akamai=req_akamai, diy_fp=req_diy_fp))
        # 显式参数优先级最高：h2_priority=True/False 直接压过预设与 diy_fp
        if h2_priority is not None:
            overrides = overrides.merge(
                FingerprintOverrides(http2_headers_priority=bool(h2_priority)))
        fp.overrides = overrides
        return fp

    def _proxy_for(self, url: str, proxy: Any, proxies: Any = None) -> str | None:
        """本次生效的代理：请求级 > 会话级，``proxy`` > ``proxies``。

        ``proxy=""`` 表示显式禁用（不读环境变量，CURLOPT_PROXY 传空串）。
        """
        scheme = urlsplit(url).scheme.lower()
        picked = _pick_proxy(proxy, proxies, scheme)
        if picked is None:
            picked = _pick_proxy(self.proxy, self.proxies, scheme)
        return picked

    def _pool_for(self, key: tuple) -> _Pool:
        with self._pools_lock:
            pool = self._pools.get(key)
            if pool is None:
                pool = _Pool(self.max_clients)
                self._pools[key] = pool
            return pool

    # ------------------------------------------------------------------ #
    # 内部：请求装配与下发
    # ------------------------------------------------------------------ #
    def _prepare(self, method: str, url: str, options: Mapping[str, Any]) -> _Prep:
        """算出一个请求的全部生效值（请求级 > 会话级），并定位连接池分区。"""
        fp = self._build_fingerprint(options, _pick(options, "h2_priority", self.h2_priority))

        verify = bool(_pick(options, "verify", self.verify))
        ca_path = _pick(options, "ca_path", self.ca_path)
        proxy = self._proxy_for(url, options.get("proxy"), options.get("proxies"))
        resolve_entries = _resolve_entries(_pick(options, "resolve", self.resolve))
        http_version = _pick(options, "http_version", self.http_version)
        if http_version is None and fp.force_http2():
            http_version = 20  # 预设本身要求 H2

        # --- 请求头（优先级：快照/预设浏览器头 < 会话头 < 请求头） ---
        merged = _merge_headers(fp.headers or [], self.headers.items())
        merged = _merge_headers(merged, options.get("headers") or {})
        # HTTP/1.1 的 Connection: keep-alive —— 真实浏览器必发且固定在 Host 之后。
        # 只写 "Connection" 会被顶到 Host 前面，所以要拿 Host 当锚点排。
        if _is_browser_preset(fp.impersonate):
            if not any(name.lower() == "connection" for name, _ in merged):
                merged.append(("Connection", "keep-alive"))
            if fp.overrides.header_order is None:
                fp.overrides = fp.overrides.merge(
                    FingerprintOverrides(header_order=_CONNECTION_ORDER))

        body, extra_headers = _build_body(options)
        if extra_headers:
            merged = _merge_headers(merged, dict(extra_headers))

        # 本次请求专用的 cookie（用完即从引擎里撤掉，不进会话罐）：
        #   1) 用户自己塞的 Cookie 头 —— 拆成 cookie 交给引擎，请求头里就不再出现它。
        #      留着它的话，引擎还会再拼一条，线上就是两个 Cookie 头（真实浏览器只有一个）；
        #   2) cookies= 参数 —— 语义是"叠加在 session.cookies 之上"，只对本次请求生效。
        cookie_pairs: list[tuple[str, str]] = []
        if any(name.lower() == "cookie" for name, _ in merged):
            kept = []
            for name, value in merged:
                if name.lower() == "cookie":
                    cookie_pairs.extend(_parse_cookie_pairs(str(value)))
                else:
                    kept.append((name, value))
            merged = kept
        for name, value in (options.get("cookies") or {}).items():
            if value is not None:
                cookie_pairs.append((str(name), str(value)))

        credentials = _pick(options, "auth", self.auth)
        if not credentials:
            userpwd = None
        elif isinstance(credentials, (tuple, list)):
            userpwd = "%s:%s" % (credentials[0],
                                 credentials[1] if len(credentials) > 1 else "")
        else:
            userpwd = str(credentials)

        ech = _pick(options, "ech", self.ech)
        doh = _pick(options, "doh", self.doh)
        dns_cache_ttl = _pick(options, "dns_cache_ttl", self.dns_cache_ttl)
        interface = _pick(options, "interface", self.interface)
        pinned_key = _pick(options, "pinned_key", self.pinned_key)
        max_download_speed = _pick(options, "max_download_speed", self.max_download_speed)
        max_upload_speed = _pick(options, "max_upload_speed", self.max_upload_speed)
        curl_options = _pick(options, "curl_options", self.curl_options)

        # 连接池键：指纹 + 连接身份 + 上面这些会影响句柄状态的 option
        key = (
            fp.impersonate or "",
            fp.overrides.cache_key(),
            int(verify),
            ca_path or "",
            http_version,
            proxy or "",
            # resolve 会写进 handle 自带的 DNS 缓存且不会自动清，故按条目分区
            tuple(resolve_entries),
            _ech_value(ech) or "",
            doh or "",
            int(dns_cache_ttl) if dns_cache_ttl is not None else -1,
            interface or "",
            pinned_key or "",
            int(max_download_speed) if max_download_speed is not None else -1,
            int(max_upload_speed) if max_upload_speed is not None else -1,
            _curl_opts_key(curl_options),
        )

        return _Prep(
            method=method.upper(),
            url=url,
            key=key,
            fingerprint=fp,
            verify=verify,
            ca_path=ca_path,
            proxy=proxy,
            resolve_entries=resolve_entries,
            redirects=bool(_pick(options, "allow_redirects", self.allow_redirects)),
            max_redirects=int(self.max_redirects if options.get("max_redirects") is None
                              else options["max_redirects"]),
            http_version=http_version,
            timeout=_pick(options, "timeout", self.timeout),
            connect_timeout=_pick(options, "connect_timeout", self.connect_timeout),
            userpwd=userpwd,
            ech=ech,
            doh=doh,
            dns_cache_ttl=dns_cache_ttl,
            interface=interface,
            pinned_key=pinned_key,
            max_download_speed=max_download_speed,
            max_upload_speed=max_upload_speed,
            curl_options=curl_options,
            headers=merged,
            cookie_pairs=cookie_pairs,
            host=_origin_of(url)[1],
            stream=bool(_pick(options, "stream", self.stream)),
            body=body,
        )

    def _apply_fingerprint(self, ptr: Any, fp: Fingerprint) -> None:
        if fp.impersonate:
            raw = fp.impersonate
            name, _, flag = raw.partition(":")
            target = resolve_target(name.strip())
            if flag.strip() == "":
                default_headers = fp.default_headers
            else:
                default_headers = flag.strip().lower() not in ("no", "false", "0", "off")
            code = lib.easy_set_impersonate(
                ptr, target.encode("utf-8"), 1 if default_headers else 0)
            if code != 0:
                raise ImpersonateError(
                    "下发 impersonate=%r 失败: %s" % (raw, lib.strerror(code)))

        if not fp.overrides.is_empty():
            # 兜底校验：parse_* 已校验过，这里防直接构造 FingerprintOverrides 绕过
            fp.overrides.validate()
            code = lib.apply_fingerprint(ptr, fp.overrides.to_values())
            if code != 0:
                raise FingerprintError("下发自定义指纹失败: %s" % lib.strerror(code))

    def _apply_extra_options(self, ptr: Any, prep: _Prep) -> None:
        """ECH / DoH / DNS TTL / interface / pinned / 限速 / curl_options 直通。"""
        if prep.ech is not None:
            value = _ech_value(prep.ech)
            if value:
                lib.set_option_string(ptr, CurlOpt.ECH, value.encode("utf-8"))
        if prep.doh:
            lib.set_option_string(ptr, CurlOpt.DOH_URL, _as_bytes(prep.doh))
        if prep.dns_cache_ttl is not None:
            lib.set_option_long(ptr, CurlOpt.DNS_CACHE_TIMEOUT, int(prep.dns_cache_ttl))
        if prep.interface:
            lib.set_option_string(ptr, CurlOpt.INTERFACE, _as_bytes(prep.interface))
        if prep.pinned_key:
            lib.set_option_string(ptr, CurlOpt.PINNEDPUBLICKEY, _as_bytes(prep.pinned_key))
        if prep.max_download_speed:
            lib.set_option_off(ptr, CurlOpt.MAX_RECV_SPEED_LARGE, int(prep.max_download_speed))
        if prep.max_upload_speed:
            lib.set_option_off(ptr, CurlOpt.MAX_SEND_SPEED_LARGE, int(prep.max_upload_speed))
        if prep.curl_options:
            apply_curl_options(lib, ptr, prep.curl_options,
                               allow_dangerous=self.allow_dangerous_options)

    def _apply_handle_options(self, ptr: Any, prep: _Prep, *, handshake: bool = False) -> None:
        """把装配结果下发到 native handle。

        ``handshake=True`` 用于 WebSocket 握手：这是一次协议升级握手而不是普通
        HTTP 请求，所以不设重定向、HTTP 版本、请求方法与请求体。
        """
        lib.easy_set_redirect(ptr, 0 if handshake else (1 if prep.redirects else 0),
                              0 if handshake else int(prep.max_redirects or 0))
        lib.easy_set_verbose(ptr, 1 if self.debug else 0)
        lib.easy_set_verify(ptr, 1 if prep.verify else 0,
                            (prep.ca_path or "").encode("utf-8") if prep.ca_path else None)
        lib.easy_set_proxy(ptr, prep.proxy.encode("utf-8")
                           if prep.proxy is not None else None)
        if prep.resolve_entries:
            lib.easy_set_resolve(ptr, [e.encode("utf-8") for e in prep.resolve_entries])
        self._apply_extra_options(ptr, prep)

        if prep.http_version is not None and not handshake:
            code = lib.easy_set_http_version(
                ptr, int(resolve_http_version(prep.http_version) or 0))
            if code != 0:
                raise RequestError(curl_error_detail(
                    code, "设置 http_version=%r 失败: %s"
                    % (prep.http_version, lib.strerror(code))))
        if prep.timeout:
            lib.easy_set_timeout(ptr, int(float(prep.timeout) * 1000))
        if prep.connect_timeout:
            lib.easy_set_connect_timeout(ptr, int(float(prep.connect_timeout) * 1000))
        if prep.userpwd:
            lib.easy_set_userpwd(ptr, prep.userpwd.encode("utf-8"))

        lib.easy_set_header_lines(ptr, _header_lines_arg(prep.headers))
        # 这一行是**故意**不写 CURLOPT_COOKIE 的：cookie 只有内建引擎一条通道
        # （见 _sync_cookies）。两条路并存就会把同一个 cookie 拼两遍。
        lib.easy_set_url(ptr, prep.url.encode("utf-8"))
        if not handshake:
            lib.easy_set_method(ptr, prep.method.encode("utf-8"))
            if prep.body is None:
                lib.easy_set_body(ptr, None, 0)
            else:
                lib.easy_set_body(ptr, prep.body, len(prep.body))

    def _build_tcp(self, options: Mapping[str, Any], prep: _Prep) -> TcpProfile | None:
        """构造 TCP 层画像；与代理互斥（否则目标站看到的是代理机的 SYN）。"""
        profile = build_tcp_profile(
            _pick(options, "tcp", self.tcp),
            _pick(options, "ttl", self.ttl),
            _pick(options, "timestamps", self.timestamps),
            warn=_pick(options, "tcp_warn", self.tcp_warn),
        )
        if profile is None:
            return None
        proxy_desc = prep.proxy if prep.proxy is not None else _env_proxy_hint(prep.url)
        if proxy_desc:
            raise TCPShapeError(
                "TCP 画像与代理不能同时使用（当前代理 %s）。\n"
                '  可做：传 proxy="" 显式禁用代理，或 unset http_proxy '
                "https_proxy all_proxy 后重试" % proxy_desc)
        return profile

    def _apply_tcp(self, handle: _Handle, profile: TcpProfile | None) -> tuple[int | None, bool]:
        """下发 TCP 画像，返回 (rcvbuf 计划, 是否换了画像)。

        换了画像必须新建连接才生效（调用方据此决定 FRESH_CONNECT）。
        """
        new_key = profile.key() if profile is not None else None
        switched = new_key != handle.tcp_profile
        rcvbuf_plan: int | None = None
        if profile is not None or handle.tcp_profile is not None:
            if profile is None:
                lib.easy_set_tcp_shape(handle.ptr)  # 关掉画像
            else:
                # plan_rcvbuf 返回 None = 本机做不到这组 window/wscale，
                # 这时完全不碰 SO_RCVBUF（本机默认窗口原样保留），它自己会发警告
                rcvbuf_plan = plan_rcvbuf(profile)
                lib.easy_set_tcp_shape(
                    handle.ptr,
                    ttl=_or_neg1(profile.ttl),
                    mss=_or_neg1(profile.mss),
                    window=_or_neg1(profile.window),
                    wscale=_or_neg1(profile.wscale),
                    rcvbuf=_or_neg1(rcvbuf_plan),
                    timestamp=_or_neg1(profile.timestamp),
                )
        handle.tcp_profile = new_key
        return rcvbuf_plan, switched

    # ------------------------------------------------------------------ #
    # cookie：只有内建引擎一条通道
    # ------------------------------------------------------------------ #
    def _sync_cookies(self, ptr: Any, prep: _Prep,
                      pushed: dict[tuple, str]) -> list[tuple[str, str, bool, str]]:
        """把会话罐里的 cookie 同步进这只 handle 的引擎，返回本次专用 cookie 的作用域键。

        内建引擎（libcurl 的 cookie engine）负责把 cookie 拼进 ``Cookie:`` 请求头，
        也是唯一通道：引擎自己从 ``Set-Cookie`` 学到的、和用户显式给的，都在同一个罐里，
        所以不会出现同名 cookie 被拼两遍。

        * 只推**引擎里还缺的**（``pushed`` 记录已下发状态），因此每次请求只花几次 setopt；
        * 会话罐里已经没有的（用户删了 / 过期了）推一条过期行，等价于从引擎里删掉；
        * 本次专用 cookie（显式 ``Cookie`` 头、请求级 ``cookies=``）按本次请求的主机
          补作用域，并在用完之后撤掉 —— 它们不进会话罐。见 :meth:`_drop_transient_cookies`。
        """
        wanted = self.cookies._wanted(prep.host, time.time())
        transient: list[tuple[str, str, bool, str]] = []
        for name, value in prep.cookie_pairs:
            key = (name, prep.host, False, "/")
            transient.append(key)
            wanted[key] = _netscape_cookie_line(prep.host, False, "/", name, value)
            pushed.pop(key, None)  # 可能与会话罐里的同名项冲突，强制按本次的值重推
        for key, line in wanted.items():
            if pushed.get(key) != line:
                lib.easy_set_cookie_list(ptr, line.encode("utf-8"))
                pushed[key] = line
        for key in [k for k in pushed if k not in wanted]:
            lib.easy_set_cookie_list(ptr, expired_cookie_line(key).encode("utf-8"))
            del pushed[key]
        return transient

    def _drop_transient_cookies(self, ptr: Any, keys: Sequence[tuple],
                               pushed: dict[tuple, str]) -> None:
        """本次专用 cookie 用完即弃：从引擎里删掉，并让会话罐里的同名项下次重推。"""
        for key in keys:
            lib.easy_set_cookie_list(ptr, expired_cookie_line(key).encode("utf-8"))
            pushed.pop(key, None)

    def _warn_stream_tcp(self, profile: TcpProfile) -> None:
        """``stream=True`` 与 ``tcp=`` 同用时的提醒（每次会话只说一次）。

        流式下载把响应头回调交给了 Python（这样 ``headers`` 在返回时就能用），
        而 TCP 画像的"事后回读校验"原本挂在那条回调上 —— 少的是自检，socket 上的
        设定本身照常生效，所以只提醒、不报警。
        """
        if self._stream_tcp_warned:
            return
        self._stream_tcp_warned = True
        emit_warning(
            profile,
            "流式下载（stream=True）接管了响应头回调，TCP 画像的事后回读校验本次跳过；"
            "socket 上的设定本身照常生效",
            fix="想同时看到回读校验，就用非流式请求跑一次同样的 tcp= 组合",
        )

    def _verify_tcp(self, handle: _Handle, code: int, profile: TcpProfile | None,
                    rcvbuf_plan: int | None) -> None:
        """请求结束后核对画像到底设上没有：不生效的发警告，不改返回值。"""
        if profile is None:
            return
        if code != 0:
            message = lib.easy_get_tcp_shape_error(handle.ptr)
            if message:
                emit_warning(
                    profile,
                    "TCP 画像有一项没设上，该项不生效：%s\n"
                    "  可做：用 nb_curl.tcp_support() 查看本机可用字段" % message)
            return
        # 只在新建连接时底层才有快照；复用连接时这里会是 None，跳过
        actual = lib.easy_check_tcp_shape(handle.ptr)
        if actual is not None:
            verify_actual(profile, actual, rcvbuf_set=rcvbuf_plan is not None)

    def _perform(self, handle: _Handle, prep: _Prep, rcvbuf_plan: int | None,
                 tcp_switched: bool) -> tuple[int, int, bytes, bytes, str | None, float]:
        """执行请求，并把「连接复用失败」自适应重试包在里面。

        返回 ``(code, status, content, raw_headers, error, 累计墙钟耗时)``。
        """
        origin = _origin_of(prep.url)
        with self._no_reuse_lock:
            force_fresh = origin in self._no_reuse_origins
        attempts_left = self.max_retries if prep.method in _IDEMPOTENT_METHODS else 0
        attempt = 0
        wall = 0.0

        while True:
            # attempt 0 且该 origin 未被标记 -> 允许复用；否则强制新建连接。
            lib.easy_set_fresh_connect(
                handle.ptr, 1 if (force_fresh or attempt or tcp_switched) else 0)
            started = time.perf_counter()
            code, status, content, raw_headers, error = lib.perform(handle.ptr)
            wall += time.perf_counter() - started

            if code == 0 or code not in _REUSE_FAILURE_CODES:
                break
            if not force_fresh:
                # 记住这个 origin：以后直接新建连接，避免每次都先失败一次
                with self._no_reuse_lock:
                    self._no_reuse_origins.add(origin)
                force_fresh = True
            if attempts_left <= 0:
                break
            attempts_left -= 1
            attempt += 1
            if self.debug:
                print("[nb_curl] 连接复用失败(%d)，强制新建连接重试 #%d: %s"
                      % (code, attempt, prep.url))

        return code, status, content, raw_headers, error, wall

    @staticmethod
    def _raise_for_code(code: int, message: str, *,
                        proxy_error: int | None = None,
                        proxy_in_use: str | None = None) -> None:
        """按 CURLcode 抛对应异常。

        文案统一带数值、符号名、中文说明与官方错误码手册链接，
        方便直接按错误码查。代理相关的失败再补上"代理子原因"（``proxy_error``）
        与"这次走的是哪个代理"（``proxy_in_use``）—— 97 只有一句笼统的
        proxy handshake error，不补这两行根本看不出代理配错在哪。
        """
        detail = curl_error_detail(code, message,
                                   proxy_error=proxy_error,
                                   proxy_in_use=proxy_in_use)
        if code == _CURLE_OPERATION_TIMEDOUT:
            raise Timeout(detail, code)
        if code in (_CURLE_COULDNT_CONNECT, _CURLE_COULDNT_RESOLVE_HOST,
                    _CURLE_COULDNT_RESOLVE_PROXY):
            raise ConnectTimeout(detail, code)
        if code == _CURLE_TOO_MANY_REDIRECTS:
            raise TooManyRedirects(detail, code)
        if code == _CURLE_PROXY:
            raise ProxyError(detail, code)
        raise RequestError(detail, code)

    # ------------------------------------------------------------------ #
    # 执行
    # ------------------------------------------------------------------ #
    def _request(self, method: str, url: str,
                 **options: Unpack[RequestOptions]) -> Response:
        """执行一次请求。

        参数见 :class:`nb_curl.params.RequestOptions`（``nb_curl.params.describe()``
        可打印完整表）。``params`` 会先并进 URL，再做其余装配。
        """
        check_options("请求", options, REQUEST_KEYS)
        if self._closed:
            raise NbCurlError("Session 已关闭")

        prep = self._prepare(method, _merge_url(url, options.get("params")), options)
        tcp_profile = self._build_tcp(options, prep)
        if prep.stream:
            return self._request_stream(prep, tcp_profile)

        pool = self._pool_for(prep.key)
        handle = pool.acquire()
        cookie_dump = ""
        transient: list[tuple] = []
        try:
            self._apply_fingerprint(handle.ptr, prep.fingerprint)
            rcvbuf_plan, tcp_switched = self._apply_tcp(handle, tcp_profile)
            self._apply_handle_options(handle.ptr, prep)
            transient = self._sync_cookies(handle.ptr, prep, handle.pushed_cookies)
            code, status, content, raw_headers, error, wall = self._perform(
                handle, prep, rcvbuf_plan, tcp_switched)
            self._verify_tcp(handle, code, tcp_profile, rcvbuf_plan)
            info = _read_info(handle)
            cookie_dump = lib.get_cookies(handle.ptr)
            if transient:
                self._drop_transient_cookies(handle.ptr, transient, handle.pushed_cookies)
        finally:
            pool.release(handle)

        self.cookies._absorb(cookie_dump, time.time(), frozenset(transient))
        if code != 0:
            self._raise_for_code(code, error or lib.strerror(code),
                                 proxy_error=info.proxy_error,
                                 proxy_in_use=_proxy_in_use(prep.proxy, prep.url))
        return _build_response(prep, info, status, content, raw_headers, wall, cookie_dump)

    def _request_stream(self, prep: _Prep, tcp_profile: TcpProfile | None) -> Response:
        """流式下载：独立 handle + 后台线程，响应体在写回调里当场交给 Python。

        ``stream=True`` 走这条路 —— 不等整个响应体下载完（那样内存占用就等于文件大小），
        而是调用方要一块给一块。独立 handle 的代价是这类请求不复用连接池里的连接，
        换来的是一块连接完全由这条流独占（``close()`` 能干净地中止它）。
        """
        response = Response(
            status_code=0,
            headers=Headers(),
            content=None,
            url=prep.url,
            request=Request(prep.method, prep.url, Headers(prep.headers)),
        )
        reader = _StreamReader(self, prep, response)
        response._stream = reader
        if tcp_profile is not None:
            self._warn_stream_tcp(tcp_profile)
        try:
            reader.start(tcp_profile)
        except BaseException:
            reader.close()
            raise
        return response

    # ------------------------------------------------------------------ #
    # WebSocket / cookie 持久化
    # ------------------------------------------------------------------ #
    def ws_connect(self, url: str, **options: Unpack[RequestOptions]) -> Any:
        """建立 WebSocket 连接，返回 :class:`nb_curl.WebSocket`。

        指纹 / verify / proxy / resolve / ECH 等参数与普通请求一致，
        见 :class:`nb_curl.params.RequestOptions`；额外支持 ``subprotocol``
        （写进 ``Sec-WebSocket-Protocol`` 头）。

        内部用独立 handle（不走连接池），``ws.close()`` 时释放。
        """
        from .ws import WebSocket

        check_options("ws_connect()", options, REQUEST_KEYS | {"subprotocol"})
        if self._closed:
            raise NbCurlError("Session 已关闭")

        prep = self._prepare("GET", url, options)
        subprotocol = options.get("subprotocol")
        if subprotocol:
            prep.headers = _merge_headers(prep.headers, {"Sec-WebSocket-Protocol": subprotocol})

        ptr = lib.easy_init()
        if not ptr:
            raise NbCurlError("easy_init() 失败")
        try:
            lib.easy_set_cookie_engine(ptr, 1)
            self._apply_fingerprint(ptr, prep.fingerprint)
            self._apply_handle_options(ptr, prep, handshake=True)
            lib.set_option_long(ptr, CurlOpt.CONNECT_ONLY, 2)  # 进入 ws 模式

            code, status, body, raw_head, err = lib.perform(ptr)
            if code != 0:
                raise RequestError(curl_error_detail(
                    code, "WebSocket 握手失败: %s" % (err or lib.strerror(code))), code)
            return WebSocket(self, ptr, lib)
        except Exception:
            lib.easy_cleanup(ptr)
            raise

    def save_cookies(self, path: str | os.PathLike) -> None:
        """把当前 ``session.cookies`` 写成 Netscape jar 文件。

        注意：``session.cookies`` 只存 name→value，丢失 domain/path；
        写出的是简化的全局 cookie（domain="."），适合跨进程快速恢复登录态。
        完整 cookie jar（带 domain/path）请用 curl_options 直传
        ``CurlOpt.COOKIEFILE``（需 allow_dangerous=True）。
        """
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write("# Netscape HTTP Cookie File\n")
            for name, value in self.cookies.items():
                f.write(".\tTRUE\t/\tFALSE\t0\t%s\t%s\n" % (name, value))

    def load_cookies(self, path: str | os.PathLike) -> None:
        """从 Netscape jar 文件读 cookies 进 ``session.cookies``（name→value）。"""
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\r\n")
                if not line or (line.startswith("#") and not line.startswith("#HttpOnly_")):
                    continue
                if line.startswith("#HttpOnly_"):
                    line = line[len("#HttpOnly_"):]
                fields = line.split("\t")
                if len(fields) >= 7:
                    self.cookies[fields[-2]] = fields[-1]
                elif "=" in line and "\t" not in line:
                    k, _, v = line.partition("=")
                    self.cookies[k.strip()] = v.strip()

    # ------------------------------------------------------------------ #
    # 自省
    # ------------------------------------------------------------------ #
    @property
    def pool_size(self) -> int:
        """当前连接池里的 handle 总数（跨所有指纹）。"""
        with self._pools_lock:
            pools = list(self._pools.values())
        return sum(len(pool) for pool in pools)

    def pool_keys(self) -> list[tuple]:
        """当前按指纹隔离出的连接分区。"""
        with self._pools_lock:
            return list(self._pools.keys())

    def __repr__(self) -> str:
        return "<Session impersonate=%r pools=%d>" % (self.impersonate, len(self._pools))


# request / get / post / put / patch / delete / head / options
# 由 `_facade` 提供（显式入口在那一层，实现都在本类），这里再导出一次。
