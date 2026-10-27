"""nb_curl.session —— requests 风格的 Session

关键设计：

* **连接池按指纹隔离**：每个 (指纹, verify, proxy, http_version) 组合对应一个
  native easy handle。TLS 指纹只在新建连接时生效，所以切换指纹必须换 handle，
  否则会复用到旧指纹的 TLS 连接（这是最容易踩的坑）。
* **每次请求全量重设 option**：不依赖任何跨请求残留，从根上避免"第二次请求
  丢 header"这类问题。
* **impersonate 先于用户头下发**：libcurl 内部把浏览器默认头放在
  CURLOPT_HTTPBASEHEADER，用户头放 CURLOPT_HTTPHEADER，两者按序合并。
* **cookie 每次请求只走一条通道**：没有显式 cookie 时由内建引擎拼 ``Cookie:``
  （Python 侧只把"该有哪些"同步进引擎，``CURLOPT_COOKIELIST``）；用户显式给了
  ``Cookie`` 头或 ``cookies=`` 时，那条 cookie 变成 ``headers`` 里的一条普通
  ``Cookie: …`` 行，引擎本次清空静默。两条路并存会让同一个 cookie 被拼两遍
  （``Cookie: sid=x; sid=x``）。
* **``Cookie`` 头只发一条、值原样、位置跟着 ``headers=`` 走**：显式串一个字节都不改写，
  也不拆行（``CURLOPT_SPLIT_COOKIES`` 默认 0，见 :meth:`Session._apply_handle_options`）。
* **stream=True 是真流式**：流由**会话级专职 reactor**（每 Session 至多一个线程，
  见 :mod:`nb_curl._stream_reactor`）驱动，写回调把每一块当场交给 Python，不经过
  C 层缓冲；缓冲超过高水位就回 ``CURL_WRITEFUNC_PAUSE``（这一块**不入队**），
  消费者取到低水位以下才恢复。所以内存占用与响应体大小无关，也不再每流一个线程。

参数（``Session(...)`` / ``get(...)`` 能传什么、怎么给）统一在
:mod:`nb_curl.params` 声明与说明，本模块只管实现。
"""

from __future__ import annotations

import asyncio
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
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

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
from .fingerprint import (Fingerprint, FingerprintOverrides, build_overrides,
                          _normalize_header_order)
from .impersonate import is_available, resolve_target
from .models import (
    CookieJar,
    Headers,
    Request,
    Response,
    expired_cookie_line,
    is_secure_origin,
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


def _env_ca_path() -> str | None:
    """``REQUESTS_CA_BUNDLE`` / ``CURL_CA_BUNDLE`` 环境变量（对齐 requests / curl_cffi）。

    企业内网与抓包环境（mitmproxy / Burp）基本都靠这两个变量换 CA；以前我们不读，
    用户以为自己配好了、结果我们静默用内置 cacert 校验。路径是否存在不在这里判断
    （指向不存在的文件应当**报错**，而不是悄悄回退 —— 与 curl 一致）。
    """
    for name in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        value = os.environ.get(name)
        if value:
            return value
    return None


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


#: URL 里不需要再转义的字符（保留已有的 ``%XX``）
_URL_SAFE = "/%:@!$&'()*+,;=-._~"
_URL_SAFE_QUERY = _URL_SAFE + "?="


def _requote(uri: str) -> str:
    """把 URL 里的非法字符（空格、中文…）转义掉，已有的 ``%XX`` 保持不动。

    ``quote=True`` 时使用；等价于 requests 的 ``requote_uri`` 的实用子集。
    """
    parts = urlsplit(uri)
    return urlunsplit(parts._replace(
        path=quote(parts.path or "/", safe=_URL_SAFE),
        query=quote(parts.query, safe=_URL_SAFE_QUERY),
    ))


#: 需要跟随的 3xx
_REDIRECT_CODES = (301, 302, 303, 307, 308)
#: libcurl 自己跟就完全正确的"原生方法"（语义由 httpreq 决定）
_NATIVE_METHODS = ("GET", "POST", "HEAD")


def next_redirect_hop(prep: "_Prep", options: Mapping[str, Any],
                      response: "Response") -> tuple[str | None, str | None, dict]:
    """下一个请求该用什么方法 / URL / 参数（照 Chrome 155 实测矩阵）。

    实测结果（``oracle/chrome_redirect_matrix.json``）：

    ========  =======  =======  =======  =======  =======
    方法      301      302      303      307      308
    ========  =======  =======  =======  =======  =======
    POST      GET      GET      GET      POST     POST
    PUT       PUT      PUT      **GET**  PUT      PUT
    PATCH     PATCH    PATCH    **GET**  PATCH    PATCH
    DELETE    DELETE   DELETE   **GET**  DELETE   DELETE
    HEAD      HEAD     HEAD     HEAD     HEAD     HEAD
    ========  =======  =======  =======  =======  =======

    返回 ``(None, None, {})`` 表示这一跳不是重定向、到此为止。
    """
    if response.status_code not in _REDIRECT_CODES:
        return None, None, {}
    location = response.headers.get("location")
    if not location:
        return None, None, {}
    url = urljoin(prep.url, location)
    method = prep.method
    code = response.status_code
    if code == 303 and method != "HEAD":
        method = "GET"                       # 303：除 HEAD 全部降级为 GET
    elif code in (301, 302) and method == "POST":
        method = "GET"                       # 301/302：只降级 POST
    # 307/308：方法与 body 都保留

    next_options = dict(options)
    if method == "GET" and prep.method != "GET":
        # 降级成 GET：body 与外带的 Content-Type 一起丢掉（浏览器就是这样）
        for key in ("data", "json", "files"):
            next_options.pop(key, None)
    return method, url, next_options


def _final_url(url: str, params: Any) -> str:
    """``params`` 合并 + **永远 requote**（Chrome 的 URL 解析就是这么干的）。

    实测 Chrome 155：``fetch('/x?q=a b')`` 线上是 ``/x?q=a%20b``；非法字符它自己转义，
    已有的 ``%XX`` 保持不动。我们以前对这种 URL 直接报 ``curl 3 CURLE_URL_MALFORMAT``，
    与浏览器不一致，所以这里不再提供开关。
    """
    return _requote(_merge_url(url, params))


def _expand_pairs(extra: Any) -> list[tuple[str, Any]]:
    """把 ``headers=`` 展开成 ``[(name, value), …]``，**同名合并成一条**。

    这是浏览器的真实行为（实测 Chrome 155）：

    * ``fetch(url, {headers: [["X-Dup","1"],["X-Dup","2"]]})`` → 线上 ``X-Dup: 1, 2``；
    * XHR 连续两次 ``setRequestHeader('X','1'/'2')`` → 也是 ``1, 2``（规范就是 ", " 追加）。

    浏览器**根本发不出两行同名请求头**，所以这里跟它一致：同名值按出现顺序用 ", " 拼成
    一条（数据不丢，但报文形态与浏览器相同）。list/tuple 值等价于多个同名的值。
    值 ``None`` = 删掉该默认头；值 ``""`` = 发一条空值头。
    """
    merged: list[tuple[str, Any]] = []
    index: dict[str, int] = {}
    items: list[tuple[str, Any]] = []
    if extra is None:
        return merged
    if hasattr(extra, "items"):
        for name, value in extra.items():
            if isinstance(value, (list, tuple)):
                for part in value:
                    items.append((str(name), part))
            else:
                items.append((str(name), value))
    else:
        for item in extra:
            name, value = str(item[0]), item[1]
            if isinstance(value, (list, tuple)):
                for part in value:
                    items.append((name, part))
            else:
                items.append((name, value))

    for name, value in items:
        key = name.lower()
        if value is None:
            merged.append((name, None))          # 删除语义原样保留（交给下游处理）
            continue
        text = value if isinstance(value, str) else str(value)
        slot = index.get(key)
        if slot is None:
            index[key] = len(merged)
            merged.append((name, text))
        else:
            prev_name, prev_value = merged[slot]
            if prev_value is None:                # 前面有"删除这条"，本身就不发
                merged[slot] = (name, text)
            else:
                merged[slot] = (prev_name, "%s, %s" % (prev_value, text))
    return merged


def _merge_headers(base: Sequence[tuple[str, Any]], extra: Any) -> list[tuple[str, Any]]:
    """把 ``extra`` 并进 ``base``：同名头**就地覆盖**，其余按给的顺序追加。

    同名多行（``headers=[("X-Dup", "1"), ("X-Dup", "2")]``）必须两条都发出去：
    浏览器侧虽然发不了重复头，但手写客户端会（``Accept``、``X-Forwarded-For``、
    ``Cookie`` 拆行等），历史上这里做过"同名覆盖"导致第二条被吞、报文静默失真。
    规则：第一条同名的在**原位替换**（保证默认头的相对顺序不乱），后续同名的
    追加在后面。
    """
    result = list(base)
    taken: set[int] = set()
    first_pos: dict[str, int] = {}
    for i, (name, _value) in enumerate(result):
        first_pos.setdefault(str(name).lower(), i)
    for name, value in _expand_pairs(extra):
        key = name.lower()
        slot = first_pos.get(key)
        if slot is not None and slot not in taken:
            taken.add(slot)
            result[slot] = (name, value)
        else:
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
    """按 files > json > data 的优先级拼请求体，返回 (body, 需要补的 Content-Type)。

    Content-Type 的推断**照抄 Chrome**（实测 Chrome 155）：

    ==============================  ==================================================
    ``fetch(url, {body: …})``       浏览器发的 Content-Type
    ==============================  ==================================================
    字符串（``'abc'``）              ``text/plain;charset=UTF-8``
    ``Uint8Array`` / ``ArrayBuffer`` **不发** Content-Type
    ``URLSearchParams``              ``application/x-www-form-urlencoded;charset=UTF-8``
    ``FormData``                     ``multipart/form-data; boundary=----WebKitFormBoundary…``
    ``Blob``（带 type）              用 Blob 自己的 type
    ==============================  ==================================================

    以前这里对 str/bytes 一律不设，于是 libcurl 自己补了
    ``application/x-www-form-urlencoded``（它设 ``POSTFIELDS`` 时的默认值）——
    声明成表单却没做表单编码，服务端按表单解析必然出错。
    """
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
        # 没有 body：把 libcurl 给 POST 补的默认 Content-Type（form-urlencoded）也去掉，
        # 浏览器在"没有 body"时就是不发 Content-Type。
        return None, [("Content-Type", None)]
    if isinstance(data, Mapping):
        # 表单提交的口径：Chrome 155 提交 form 时是
        # ``Content-Type: application/x-www-form-urlencoded``（**不带** charset；
        # fetch 里用 URLSearchParams 才会带 ``;charset=UTF-8``）。
        return (urlencode(data, doseq=True).encode("utf-8"),
                [("Content-Type", "application/x-www-form-urlencoded")])
    if isinstance(data, (list, tuple)) and data and isinstance(data[0], (list, tuple)):
        # [(k, v), …] 形式（同样按表单提交口径）
        return (urlencode(data, doseq=True).encode("utf-8"),
                [("Content-Type", "application/x-www-form-urlencoded")])
    if isinstance(data, str):
        return data.encode("utf-8"), [("Content-Type", "text/plain;charset=UTF-8")]
    if isinstance(data, (bytes, bytearray, memoryview)):
        # Chrome 对二进制 body 不发 Content-Type；libcurl 会自己补 form 编码，得显式删掉
        return bytes(data), [("Content-Type", None)]
    if hasattr(data, "read"):           # 文件对象：读出来，不猜类型
        return _to_bytes(data.read()), [("Content-Type", None)]
    if hasattr(data, "__iter__"):       # 生成器/可迭代：拼起来
        return b"".join(_to_bytes(chunk) for chunk in data), [("Content-Type", None)]
    return _to_bytes(data), [("Content-Type", None)]


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
    """把一条 ``Cookie:`` 头值拆成 ``[(name, value), …]``（**只用于认名字**）。

    值原样保留（只有名字与分隔用的空白会被去掉），因为有些站点的签名 cookie
    里带 ``=`` 之类的字符。发送路径已经改成"整串原样下发"，所以这个函数现在
    只服务于"哪些名字已经出现过"的判断。
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


def _header_lines_arg(pairs: Sequence[tuple[str, Any]]) -> list[bytes]:
    """把 (name, value) 序列编码成 C 侧的 header 行数组（保序、保重复）。

    * ``value is None`` → ``"Name:"``：让 libcurl 删掉同名默认头；
    * ``value == ""`` → ``"Name: "``：**发一条空值头**（Chrome 就是这么发的）；
    * 其余按 **latin-1** 编码 —— HTTP 头的字节语义就是 latin-1（WHATWG 的
      ByteString），编不进去的值（中文等）直接报错，而不是静默按 UTF-8 发出去
      （那会产出浏览器永远发不出来的头字节序）。
    """
    lines: list[bytes] = []
    for name, value in pairs:
        if value is None:
            # libcurl 的语义：`Name:`（无值）= 删掉同名默认头
            lines.append(("%s:" % name).encode("latin-1", "strict"))
            continue
        text = value if isinstance(value, str) else str(value)
        if "\r" in text or "\n" in text:
            raise NbCurlError("头部值不能包含换行: %r" % name)
        if text == "":
            # 空值头要用 `Name;` 这种写法才发得出去（`Name: ` 会被 libcurl 当成删除）
            lines.append(("%s;" % name).encode("latin-1"))
            continue
        try:
            raw = ("%s: %s" % (name, text)).encode("latin-1")
        except UnicodeEncodeError as exc:
            # 浏览器就是这个行为（实测 Chrome 155）：
            #   fetch → TypeError: String contains non ISO-8859-1 code point.
            #   XHR .setRequestHeader → 同一条 TypeError。
            raise TypeError(
                "请求头 %r 的值含非 ISO-8859-1 字符（浏览器同样拒绝）：%r"
                % (name, text)) from exc
        lines.append(raw)
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
    """同一分区（指纹 + 连接身份）下的 easy handle 池。

    与旧实现的差别（都是性能/生命周期问题）：

    * 空闲句柄放在 ``deque`` 里，**获取与归还都是 O(1)**（旧版每次 acquire 都线性
      扫描全部句柄，并发越高越慢）；
    * ``_total`` 记录"已创建且尚未销毁"的句柄数，上限仍是 ``max_size``
      —— 保持 ``max_clients`` 的公开含义不变；
    * :meth:`drain`（会话 close）之后：等待者立刻拿到**确定错误**，不再新建句柄，
      也不再新建池；
    * 正在请求的句柄由 :meth:`release` 在归还时关闭 —— 绝不在别处与
      ``curl_easy_perform`` 抢同一个 handle；
    * :meth:`discard` 用于"配置失败的半成品句柄"：它**不进池**，直接销毁，
      池容量当场让出来（否则半个配置的句柄会被下一个请求当成干净句柄复用）。
    """

    def __init__(self, max_size: int):
        self._cond = threading.Condition()
        self._idle: deque[_Handle] = deque()
        self._total = 0
        self._max = max(1, int(max_size))
        self._draining = False
        self._closed = False

    def acquire(self) -> _Handle:
        with self._cond:
            while True:
                if self._closed:
                    raise NbCurlError("Session 已关闭")
                if self._idle:
                    handle = self._idle.pop()          # O(1)
                    handle.busy = True
                    return handle
                if self._total < self._max:
                    self._total += 1
                    break
                self._cond.wait()
        # 在锁外创建：easy_init() 是跨界调用，不该让其它等待者陪着一起阻塞
        try:
            handle = _Handle()
        except BaseException:
            with self._cond:
                self._total -= 1
                self._cond.notify()
            raise
        handle.busy = True
        return handle

    def release(self, handle: _Handle) -> None:
        close_later = False
        with self._cond:
            handle.busy = False
            if self._closed or self._draining:
                # close() 已经把空闲句柄收走了；本句柄当时还在跑，现在补关。
                self._total -= 1
                close_later = True
                self._cond.notify_all()
            else:
                self._idle.append(handle)
                self._cond.notify()
        if close_later:
            handle.close()

    def discard(self, handle: _Handle) -> None:
        """半配置 / 损坏的句柄：不进池，直接销毁。

        典型场景：``_configure`` 中途抛异常（选项不合法、指纹下发失败），
        此时句柄上只落了一半配置 —— 放回池里会让下一个请求踩到脏状态。
        """
        with self._cond:
            handle.busy = False
            self._total -= 1
            self._cond.notify()
        handle.close()

    def drain(self) -> list[_Handle]:
        """关闭池：取出所有空闲句柄交给调用方释放，并让等待者立即拿到错误。

        busy（正在请求）的句柄跳过，由 :meth:`release` / :meth:`discard`
        在请求结束后补关 —— 避免与 curl_easy_perform 并发 free 同一个 handle。
        """
        with self._cond:
            self._draining = True
            self._closed = True
            idle = list(self._idle)
            self._idle.clear()
            self._total -= len(idle)
            self._cond.notify_all()
        return idle

    def __len__(self) -> int:
        with self._cond:
            return self._total


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
    http3_permute_extensions: bool | None
    """HTTP/3 的 QUIC ClientHello 是否逐连接随机打乱 TLS 扩展顺序。

    ``None`` = 不下发（跟随 C 内核/preset 的默认），``True`` / ``False`` = 显式开关。"""
    interface: str | None
    pinned_key: str | None
    max_download_speed: int | None
    max_upload_speed: int | None
    curl_options: Any
    headers: list[tuple[str, str]]
    cookie_header: str | None
    """本次请求最终发出去的 ``Cookie`` 头值（显式 cookie + 会话罐，已按浏览器口径排序）。

    发送走 ``headers`` 里的那条 ``Cookie`` 行；内建引擎在发送前被清空
    （见 :meth:`Session._sync_cookies`），只负责学习响应里的 ``Set-Cookie``。
    """
    host: str
    stream: bool
    body: bytes | None
    discard_cookies: bool = False
    follow_python: bool = False
    """这个请求的重定向是否由 Python 侧跟（见 :meth:`Session._follow_redirects`）。"""


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


# --------------------------------------------------------------------------- #
# 「连接复用失败」自适应重试：同步与异步共用同一套判定
# --------------------------------------------------------------------------- #
class _Retry:
    """一次请求的重试状态机（同步 ``_perform`` 与异步 multi 驱动都用它）。

    语义（与旧实现逐条一致，只是抽出来共用，避免异步侧重写时走样）：

    * 只有幂等方法（``_IDEMPOTENT_METHODS``）才自动重试，非幂等请求绝不重放；
    * 首次失败后把这个 origin 记进 ``_no_reuse_origins``，之后同一 origin 直接
      强制新建连接，不再每次都先白失败一次；
    * 重试次数上限是 ``max_retries``。
    """

    __slots__ = ("origin", "force_fresh", "attempts_left", "attempt", "wall")

    def __init__(self, session: "Session", prep: _Prep):
        self.origin = _origin_of(prep.url)
        with session._no_reuse_lock:
            self.force_fresh = self.origin in session._no_reuse_origins
        self.attempts_left = (session.max_retries
                              if prep.method in _IDEMPOTENT_METHODS else 0)
        self.attempt = 0
        self.wall = 0.0

    def fresh_connect(self, tcp_switched: bool = False) -> bool:
        """本次尝试是否必须新建连接（首次且未标记、且没换 TCP 画像时可以复用）。"""
        return bool(self.force_fresh or self.attempt or tcp_switched)

    def on_failure(self, session: "Session", code: int, url: str) -> bool:
        """记一次失败；返回 True = 应当强制新建连接重试。"""
        if code == 0 or code not in _REUSE_FAILURE_CODES:
            return False
        if not self.force_fresh:
            with session._no_reuse_lock:
                session._no_reuse_origins.add(self.origin)
            self.force_fresh = True
        if self.attempts_left <= 0:
            return False
        self.attempts_left -= 1
        self.attempt += 1
        if session.debug:
            print("[nb_curl] 连接复用失败(%d)，强制新建连接重试 #%d: %s"
                  % (code, self.attempt, url))
        return True


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
#: 整体读（``Response.content``）时的分块大小
_STREAM_READ_CHUNK = 65536
#: close() 等传输侧收尾的秒数（每条流；bulk close 共享同一份预算）
_STREAM_CLOSE_GRACE = 1.0
#: 会话 close 等流式 reactor 线程退出的上限
_STREAM_REACTOR_GRACE = 5.0
#: 会被自动跟随的重定向状态码（判断"这个响应块是不是最终响应"用）
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
#: 非阻塞取数的哨兵："现在还没有数据，需要等"
_NO_DATA = object()


def _set_future_result(fut: Any) -> None:
    """在事件循环线程上完成一个 Future（已经完成/被取消就跳过）。"""
    if not fut.done():
        fut.set_result(None)


class _StreamBody:
    """``stream=True`` 响应体的公共部分：有界缓冲 + 取数游标 + 状态/异常交付。
    同步 :class:`Session` 与 :class:`AsyncSession` 的流式都跑在**同一个**会话级
    专职 reactor 上（见 :mod:`nb_curl._stream_reactor`）：reactor 线程是唯一碰得到
    native 的人，本类只负责"数据怎么排队、游标怎么走、错误什么时候抛"，因此与
    "谁在驱动传输"无关。旧实现里"每条流一个后台线程"的传输侧已删除。

    线程契约：

    * 传输侧（reactor 线程）在 ``_lock`` 里只做 O(1) 记账后立刻返回，
      **绝不在持锁时进 native**、绝不等消费者；
    * 消费侧（调用线程）可以任意阻塞在 :meth:`_take` 上 —— reactor 独立推进，
      所以"在事件循环线程里同步调 content / iter_content"不会死锁；
    * 跨线程交付只走两处：``_cond.notify_all()``（同步等待者）与
      ``loop.call_soon_threadsafe``（异步等待者，绝不直接 ``set_result``）。

    复用语义（都是既有资产，不只是实现细节）：

    * 游标 ``_pending`` 在**实例**上、且先删后 yield：``iter_content()`` 可以分几次
      接着读，中途 ``break`` 也不丢已经取出但尚未交出去的字节；
    * 传输错误先把已经拿到的内容交完，读完再抛（与 requests 的流式语义一致）。
    """

    def __init__(self, session: "Session", prep: _Prep, response: Response):
        self._session = session
        self._prep = prep
        # 弱引用：响应对象必须能在"没人用了"的时候被回收 —— 回收时它会回调
        # close(join=False) 通知我们中止传输。这里要是持强引用，响应就永远收不掉。
        self._response_ref = weakref.ref(response)
        self._handle: _Handle | None = None
        self._keepalive: Any = None          # 回调对象，必须活到传输结束
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._chunks: deque[bytes] = deque()
        self._buffered = 0
        self._done = False
        self._abort = False
        self._code = 0
        self._error: str | None = None
        self._pxcode: int | None = None          # CURLINFO_PROXY_ERROR（97 才有）
        self._exc: BaseException | None = None   # 传输之外冒出来的异常，原样抛回
        self._status = 0
        self._blocks: list[tuple[int, str, Headers]] = []
        self._raw_headers = bytearray()
        self._code_dump = ""
        # 已经取出来、还没交出去的字节。放在实例上而不是生成器局部变量：
        # 调用方中途 break 之后，这些字节必须留给下一次 iter_content / content。
        self._pending = bytearray()
        self._consumed = False
        self._closing = False
        # 传输侧收尾（句柄已释放）后置位：close(join=True) / bulk close 靠它做有界等待
        self._release_event = threading.Event()
        # 异步等待者（最多一个）与它所属的事件循环
        self._async_waiter: Any = None
        self._loop: Any = None
        # 建好就登记：这样"响应头还没到 / 还没提交给 reactor"的阶段也能被
        # Session.close() 及时中止（否则 close 会漏掉它，一直等下去）。
        session._streams.add(self)

    # -- 异步等待者（reactor 线程激活；只在事件循环线程里挂/摘） -------------- #
    def _new_waiter_locked(self) -> Any:
        """建一个（当前 loop 上的）等待者并登记；调用方需持锁。"""
        loop = asyncio.get_running_loop()
        self._loop = loop
        fut = loop.create_future()
        self._async_waiter = fut
        return fut

    def _drop_waiter(self, fut: Any) -> None:
        with self._cond:
            if self._async_waiter is fut:
                self._async_waiter = None

    def _notify_locked(self) -> None:
        """唤醒同步与（最多一个）异步等待者；调用方需持锁。

        异步交付一律经 ``call_soon_threadsafe``：reactor 线程直接 ``set_result``
        会让 Future 的完成回调跑在 reactor 线程上，那是隐蔽的线程错误。
        """
        self._cond.notify_all()
        fut, self._async_waiter = self._async_waiter, None
        if fut is None or fut.done():
            return
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        try:
            loop.call_soon_threadsafe(_set_future_result, fut)
        except RuntimeError:      # 循环正在关闭
            pass

    # -- 生命周期（传输侧钩子由 reactor 实现） ------------------------------ #
    def wait_ready(self) -> None:
        """等最终响应头到达（或传输结束 / 被中止）。

        此时 ``status_code`` / ``headers`` 可用，调用方可以据此决定要不要继续读；
        重定向中间跳不算数，等的是跳完之后那一次响应。
        """
        with self._cond:
            while not self._done and not self._abort and not self._status:
                self._cond.wait()
        self._raise_pending()

    async def wait_ready_async(self) -> None:
        """``wait_ready`` 的异步版：while 重验谓词（数据/abort/结束都可能提前唤醒）。"""
        while True:
            fut = None
            with self._cond:
                if not self._done and not self._abort and not self._status:
                    fut = self._new_waiter_locked()
            if fut is None:
                break
            try:
                await fut
            finally:
                self._drop_waiter(fut)
        self._raise_pending()

    async def wait_data(self) -> None:
        """等"再来一块数据"（已经可读 / 已结束则立刻返回，不建 Future）。

        while 重验谓词：任何一次提前唤醒（abort/done/notify 竞争）都必须重新
        检查条件，绝不能"await 一次就当数据到了"。
        """
        while True:
            fut = None
            with self._cond:
                if self._chunks or self._done:
                    return
                fut = self._new_waiter_locked()
            try:
                await fut
            finally:
                self._drop_waiter(fut)

    def abort(self) -> None:
        """只发中止信号（不 join、不碰句柄）。

        写回调会据此返回 False 让 libcurl 立刻收手；**同时**必须通知传输侧
        （:meth:`_cancel_transport`）——"响应头还没到、一个字节都没收到"的情况下
        写回调根本没被调用过，光靠它取消不掉，这正是"取消流头前"要覆盖的场景。
        """
        with self._cond:
            self._abort = True
            self._notify_locked()
        self._cancel_transport()

    def close(self, *, join: bool = True) -> None:
        """中止传输并释放连接；已经结束的流调用它没有副作用。

        ``join=False``（``Response.__del__`` 用）只发中止意图、不等传输侧收尾：
        句柄归 reactor 线程所有，由它自己释放，避免与正在跑的 native 调用抢。
        幂等且**允许第二次等待**：第一次 join=False 之后再来一次 join=True，
        仍要在预算内等同一个 release_event（``_closing`` 只是防止重复发中止
        意图，不是"跳过等待"的借口）。
        """
        first = not self._closing
        if first:
            self._closing = True
        self.abort()
        if join:
            self.wait_released(_STREAM_CLOSE_GRACE)

    def wait_released(self, timeout: float) -> bool:
        """等传输侧真的收尾（句柄已释放）；返回是否在预算内完成。"""
        return self._release_event.wait(max(0.0, timeout))

    def _cancel_transport(self) -> None:
        """通知传输侧中止（基类默认无传输：什么都没发生）。"""
        return None

    def _release_handle(self) -> None:
        """清理 native handle（幂等）。

        必须走 :meth:`_Handle.close`（它会把 ``ptr`` 置空）而不是直接
        ``easy_cleanup(handle.ptr)``：否则 ``_Handle`` 对象被回收时 ``__del__``
        会拿着同一个指针再 free 一次 —— 双重释放，之后新建的 handle 会踩到坏内存。
        """
        with self._lock:
            handle, self._handle = self._handle, None
        self._session._streams.discard(self)
        if handle is not None:
            try:
                handle.close()
            except Exception:  # noqa: BLE001
                pass
        self._release_event.set()

    # -- 状态 -------------------------------------------------------------- #
    @property
    def response(self) -> Response | None:
        """对应的响应对象（已被回收时为 ``None`` —— 那时数据也没人接手了）。"""
        return self._response_ref()

    @property
    def finished(self) -> bool:
        """传输是否已经结束（不代表数据都被取走了）。"""
        with self._cond:
            return self._done

    @property
    def consumed(self) -> bool:
        """是否已经开始被读取过（流是游标，可以接着往下读）。"""
        return self._consumed

    # -- 头回调（传输侧线程调用） ------------------------------------------ #
    def _on_header(self, line: bytes) -> bool:
        """头回调：逐行累积响应头，攒完一块就刷新状态（含状态行）。

        头块很小，不做背压；1xx 与代理 CONNECT 块由 :func:`parse_header_blocks`
        过滤，重定向中间跳由 :meth:`_refresh_locked` 过滤 —— 只有最终块置
        ``status_code``。
        """
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
        self._notify_locked()

    # -- 取数 -------------------------------------------------------------- #
    def iter_chunks(self, chunk_size: int = 8192) -> Iterator[bytes]:
        """逐块产出响应体（同步）。

        流是一个**游标**：可以分多次调用接着往下读（与 requests 一致），
        也可以中途 ``break`` —— 剩下的数据还在，交给 ``content`` 或下一次
        ``iter_content()`` 读走；真不要了用 ``Response.close()`` 释放连接。
        """
        self._consumed = True
        return self._iter_chunks(max(1, int(chunk_size)))

    def _iter_chunks(self, size: int) -> Iterator[bytes]:
        pending = self._pending     # 游标：跨调用、跨 break 都保留
        while True:
            data = self._take()
            if data is None:
                break
            pending += data
            while len(pending) >= size:
                # 必须**先**从缓冲里删掉再 yield：生成器会停在 yield 上，
                # 若先 yield，字节还留在 pending 里，下次读取会再投递一遍（正文重复）。
                chunk = bytes(pending[:size])
                del pending[:size]
                yield chunk
        if pending:
            chunk = bytes(pending)
            del pending[:]
            yield chunk
        self._raise_pending()

    async def aiter_chunks(self, size: int) -> Any:
        """``_iter_chunks`` 的异步版：同一套游标语义，挂起时只等数据。

        每挂起一次只建一个 Future（由 reactor 线程唤醒），**不再**每块都
        ``asyncio.to_thread(next, iterator)`` —— 那样每块都要动一次线程。
        """
        self._consumed = True
        pending = self._pending
        while True:
            data = self._take_nowait()
            while data is _NO_DATA:
                await self.wait_data()
                data = self._take_nowait()
            if data is None:
                break
            pending += data
            while len(pending) >= size:
                chunk = bytes(pending[:size])
                del pending[:size]
                yield chunk
        if pending:
            chunk = bytes(pending)
            del pending[:]
            yield chunk
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
                    self._after_take_locked()     # 通知传输侧可以继续收
                    return data
                if self._done:
                    return None
                self._cond.wait()

    def _take_nowait(self) -> Any:
        """非阻塞取数：``bytes`` / ``None``（结束且没剩余）/ :data:`_NO_DATA`（还没到）。"""
        with self._cond:
            if self._chunks:
                data = self._chunks.popleft()
                self._buffered -= len(data)
                self._after_take_locked()
                return data
            if self._done:
                return None
            return _NO_DATA

    def _after_take_locked(self) -> None:
        """消费者取走一块之后的通知钩子（调用方持锁）；传输侧按需覆写。"""
        self._cond.notify_all()

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
        if not done or has_data or abort or code == 0:
            return
        if code == _CURLE_WRITE_ERROR:
            # 只有"我们主动中止"才允许吞掉这条错误（abort 已在上面返回）。
            # 走到这里说明写回调真的失败了，不能伪装成正常结束。
            raise RequestError(curl_error_detail(
                code, "响应体写入被中止（写回调返回失败）: %s"
                % (error or lib.strerror(code))), code)
        self._session._raise_for_code(
            code, error or lib.strerror(code),
            proxy_error=pxcode,
            proxy_in_use=_proxy_in_use(self._prep.proxy, self._prep.url))


# 把公共基类交给 reactor 侧组合（ReactorStream 的消费接口由 _StreamBody 提供）
from ._stream_reactor import _bind_stream_body as _bind_stream_body  # noqa: E402
_bind_stream_body(_StreamBody)


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
    >>> with nb_curl.Session(impersonate="chrome155") as s:
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
        # 请求头顺序：与 impersonate 同级的显式参数（None = 跟随预设）。
        header_order = options.get("header_order")
        self.header_order = header_order
        # HTTP/3 的 QUIC ClientHello 扩展顺序随机化（None = 跟随预设：
        # Chrome / Edge 系预设默认开，其余关）。
        self.http3_permute_extensions = options.get("http3_permute_extensions")

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
            (_env_ca_path() or _default_ca_path()) if self.verify else None)
        self.timeout = options.get("timeout")
        self.connect_timeout = options.get("connect_timeout")
        self.allow_redirects = _session_default(options, "allow_redirects")
        self.max_redirects = _session_default(options, "max_redirects")
        # credentials：对齐 fetch 的 credentials 语义（浏览器口径）。
        #   None / "include" / "same-origin" → 正常发 cookie 并记住响应 Set-Cookie
        #   "omit"                          → 本次请求既不发也不记（浏览器就是这么做的）
        credentials = options.get("credentials")
        if credentials is not None and credentials not in ("omit", "same-origin", "include"):
            raise ValueError(
                "credentials 只能是 'omit' / 'same-origin' / 'include'，收到 %r" % (credentials,))
        self.credentials = credentials
        http_version = options.get("http_version")
        if http_version is not None:
            resolve_http_version(http_version)  # 提前校验，别等到发请求才报错
        self.http_version = http_version
        self.max_clients = max(1, int(_session_default(options, "max_clients")))
        self.max_retries = max(0, int(_session_default(options, "max_retries")))
        self.graceful_close = _session_default(options, "graceful_close")
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
        # 还活着的流式响应（弱引用）：close() 时要把它们的传输一起中止
        self._streams: weakref.WeakSet = weakref.WeakSet()
        # 流式专职 reactor（每 Session 至多一个，惰性创建；见 _stream_reactor）
        self._stream_reactor: Any = None
        # 惰性创建互斥：20 个线程 barrier 同时首次 stream 也只允许创建一个
        # reactor 实例（review-poll-core：session 层懒创建无锁会出现 3 个 reactor）
        self._reactor_lock = threading.Lock()
        # 异步 multi 驱动（只有 AsyncSession 会装上；同步 Session 恒为 None）。
        # 放在基类里，close() 才能在库里统一处理，不必依赖子类的析构顺序。
        self._async_driver: Any = None
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
        # 先置关闭位：新请求立即被拒，正在等池的 acquire 也会拿到确定错误
        self._closed = True

        # 异步驱动先停（取消在飞传输、关闭 multi）；它自己保证只收尾一次。
        # graceful_close 时**有界等 owner 线程收完连接再关池**：连接释放与
        # easy_cleanup 并发会让 libcurl 跳过优雅关闭路径直接 close —— 接收队列里
        # 还有对端字节时那就是 RST（旧版阻塞式收尾不会被这条路径踩到）。
        driver, self._async_driver = self._async_driver, None
        if driver is not None:
            try:
                driver.close(wait=bool(self.graceful_close))
            except Exception:  # noqa: BLE001
                pass

        # 流式：先停 reactor（一次唤醒就能拆掉全部在飞流），再有界等待收尾
        self._shutdown_streams(wait=True)

        self._close_pools()

    def _close_abandoned(self) -> None:
        """``__del__`` 专用收尾：只发"停止/取消"意图，绝不等 owner 线程。

        析构发生在哪个线程、什么时候都不确定，等它等于把 GC 卡住（而且驱动此刻
        可能正在 free 同一个 multi / easy）。有序收尾是 :meth:`close` 的职责。
        """
        self._closed = True
        driver, self._async_driver = self._async_driver, None
        if driver is not None:
            try:
                driver.close(wait=False)
            except Exception:  # noqa: BLE001
                pass
        self._shutdown_streams(wait=False)
        self._close_pools()

    def _close_pools(self) -> None:
        """关闭全部连接池并把空闲句柄交回 native。"""
        with self._pools_lock:
            pools = list(self._pools.values())
            self._pools.clear()
        for pool in pools:
            for handle in pool.drain():
                handle.close()

    def _shutdown_streams(self, *, wait: bool) -> None:
        """停掉流式 reactor 并收掉所有还开着的流。

        ``wait=True``（close()）：有界等待——每条流 1s 共享预算 + reactor 线程退出；
        ``wait=False``（``__del__``）：只发中止意图，绝不与 reactor 抢 native 资源。

        ``AsyncSession`` 的异步 close 会自己先 ``await to_thread(reactor.wait_closed)``，
        那时这里的 reactor 已经是 ``None``，于是不会在事件循环线程上阻塞。
        """
        # 与 _reactor_for_streams 同锁：close 与"首次 stream 惰性创建"交错时，
        # 要么创建先拿到锁（reactor 进清理列表被正常关闭），要么 close 先拿到
        # 锁（之后创建路径看到 _closed 直接报错），不会漏掉任何 reactor。
        with self._reactor_lock:
            reactor, self._stream_reactor = self._stream_reactor, None
        if reactor is not None:
            try:
                reactor.stop(wait=False)      # 只发"停止 + 取消全部"意图
            except Exception:  # noqa: BLE001
                pass
        self._close_streams(wait=wait)
        if wait and reactor is not None:
            reactor.wait_closed(_STREAM_REACTOR_GRACE)

    def _close_streams(self, *, wait: bool = True) -> None:
        """中止所有还活着的流式响应。

        先把中止意图**全部**发出去（一次唤醒就能让 reactor 拆掉全部在飞传输），
        再按**共享的** 1s 预算等它们真的收尾 —— 不会因为并发流多就把 close
        拖成 N 秒。``wait=False`` 只发意图。
        """
        readers = list(self._streams)
        for reader in readers:
            try:
                reader.abort()
            except Exception:  # noqa: BLE001
                pass
        deadline = time.monotonic() + _STREAM_CLOSE_GRACE
        for reader in readers:
            try:
                reader.close(join=False)      # 幂等：只置状态，不等待
                if wait:
                    reader.wait_released(max(0.0, deadline - time.monotonic()))
            except Exception:  # noqa: BLE001
                pass

    def __del__(self):  # pragma: no cover - 兜底
        """析构只发"取消意图"：绝不等 reactor / 驱动线程收尾（那是 close() 的事）。"""
        try:
            self._close_abandoned()
        except Exception:  # noqa: BLE001
            pass

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def stream_mode(self) -> str:
        """流式走的传输路径：``reactor``（会话级专职线程）/ ``unstarted``。

        只是可观测性字段（用来证明没有偷偷回退到"每条流一个线程"），不是公开 API。
        """
        return "reactor" if self._stream_reactor is not None else "unstarted"

    def _reactor_for_streams(self) -> Any:
        """取（首次则创建）本会话的流式 reactor —— 每个 Session 至多一个。

        check-then-create 必须与 close 走同一把锁（``_reactor_lock``）：否则
        barrier 并发首次 stream 会各建一个 reactor（各带一个线程），close 与
        create 交错时又会把刚创建的 reactor 从清理列表里漏掉。
        """
        with self._reactor_lock:
            reactor = self._stream_reactor
            if reactor is not None:
                return reactor
            if self._closed:
                raise NbCurlError("Session 已关闭")
            from ._stream_reactor import StreamReactor

            reactor = StreamReactor(self)
            self._stream_reactor = reactor
            return reactor

    # ------------------------------------------------------------------ #
    # 内部：指纹与连接池
    # ------------------------------------------------------------------ #
    def _build_fingerprint(self, options: Mapping[str, Any], h2_priority: Any,
                           header_order: Any = None) -> Fingerprint:
        """合并所有指纹来源，优先级（低 -> 高）：

        impersonate 底座 < 会话级 ja3/akamai/diy_fp < 请求级快照
        < 请求级 ja3/akamai/diy_fp < 显式 ``h2_priority`` / ``header_order``。

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
        # 请求头顺序是显式参数（与 impersonate 同级），压过预设与 diy_fp。
        # 这里统一归一化成 C 层要的逗号串（字符串 / 列表两种写法都收），
        # 顺带保证 cache_key / 池键可哈希。
        if header_order is not None:
            overrides = overrides.merge(FingerprintOverrides(
                header_order=_normalize_header_order(header_order)))
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
            if self._closed:
                # close() 与本调用之间的竞态：关闭后**不再新建池**（否则新池
                # 不在 close 的清理列表里，里面的连接会泄漏到会话之外）
                raise NbCurlError("Session 已关闭")
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
        fp = self._build_fingerprint(
            options, _pick(options, "h2_priority", self.h2_priority),
            _pick(options, "header_order", self.header_order))

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

        # 浏览器行为（实测 Chrome 155）：GET/HEAD 带 body 直接抛 TypeError
        #   "Request with GET/HEAD method cannot have body."
        method_upper = method.upper()
        if method_upper in ("GET", "HEAD") and (
                options.get("data") is not None or options.get("json") is not None
                or options.get("files") is not None):
            raise TypeError("Request with GET/HEAD method cannot have body.")

        body, extra_headers = _build_body(options)
        if extra_headers:
            # 用户显式写了 Content-Type 就不覆盖（Chrome 也是"你给的优先"）
            has_ct = any(str(n).lower() == "content-type" for n, _v in merged)
            for name, value in extra_headers:
                if has_ct and str(name).lower() == "content-type":
                    continue
                merged = _merge_headers(merged, [(name, value)])

        # 本次请求的 cookie：整条 ``Cookie:`` 头**一律由 Python 拼**（浏览器口径）。
        #   1) 用户自己塞的 Cookie 头 —— 值逐字节原样，位置就是 headers= 里那个位置；
        #   2) cookies= 参数 —— 语义是"叠加在 session.cookies 之上"，只对本次请求生效；
        #   3) 会话罐里命中的 cookie —— 按 RFC 6265 5.4 排序（path 长者先、同长按创建
        #      时间），Secure 只走安全上下文，host-only 的不会串到别的主机。
        # 为什么不让内建引擎拼：它按 path/domain/name **长度**排序（lib/cookie.c 的
        # cookie_sort），顺序与浏览器不同；而且它不管"显式 Cookie 头"这一路，两条
        # 并存会把同一个 cookie 拼两遍。
        cookie_raw_parts: list[str] = []
        cookie_slot: int | None = None
        kept: list[tuple[str, Any]] = []
        for name, value in merged:
            if str(name).lower() == "cookie":
                if cookie_slot is None:
                    cookie_slot = len(kept)          # 记住用户放的位置
                text = "" if value is None else str(value).strip()
                if text:                             # 空值、纯空白 = 没有 cookie
                    cookie_raw_parts.append(text)
            else:
                kept.append((name, value))
        merged = kept
        cookie_pairs: list[tuple[str, str]] = []
        for name, value in (options.get("cookies") or {}).items():
            if value is not None:
                cookie_pairs.append((str(name), str(value)))

        scheme, host, _port = _origin_of(url)
        credentials = _pick(options, "credentials", self.credentials)
        discard_cookies = credentials == "omit"
        cookie_header: str | None = None
        if cookie_raw_parts or cookie_pairs or not discard_cookies:
            cookie_header = self.cookies.header_value(
                host,
                urlsplit(url).path or "/",
                secure=is_secure_origin(scheme, host),
                pairs=cookie_pairs,
                raw="; ".join(cookie_raw_parts),
                now=time.time(),
            ) or None
        if cookie_header:
            # 用户给了 Cookie 头 -> 回到原位；只从罐里拼的 -> 追加到末尾
            # （Chrome 的 Cookie 头就在最后一条，实测 http://127.0.0.1 抓包确认）。
            #
            # 注意：**永远只发一条**。实测 Chrome 155 在 HTTP/2 上也是把全部 cookie
            # 拼成一条 `cookie` 头（本地 h2 服务端抓到的就是
            # `['a=1; bb=2; zebra=3']`，不是多条）；旧版本 Chrome 曾经拆行，
            # 现在不拆了，所以 ``diy_fp={"split_cookies": ...}`` 对这条头不再有任何作用。
            spot = len(merged) if cookie_slot is None else min(cookie_slot, len(merged))
            merged.insert(spot, ("Cookie", cookie_header))

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
        # H3 的 QUIC ClientHello 扩展顺序随机化：Chrome 每次连接都不一样，
        # 固定顺序本身是指纹。None = 跟随预设口径（Chrome/Edge 系默认开）。
        h3_permute = _pick(options, "http3_permute_extensions",
                           self.http3_permute_extensions)
        if h3_permute is None:
            _target = (fp.impersonate or "").partition(":")[0].strip().lower()
            if _target.startswith(("chrome", "edge")):
                h3_permute = True

        # 连接池键：指纹 + 连接身份 + 上面这些会影响句柄状态的 option
        key = (
            fp.impersonate or "",
            fp.overrides.cache_key(),
            int(verify),
            ca_path or "",
            http_version,
            # proxy=None（跟随环境变量）与 proxy=""（显式禁用代理）**不能折叠**：
            # 两者连接身份不同，折叠会让"显式禁用"的请求复用上一条走了代理的连接。
            ("env",) if proxy is None else ("set", proxy),
            # resolve 会写进 handle 自带的 DNS 缓存且不会自动清，故按条目分区
            tuple(resolve_entries),
            _ech_value(ech) or "",
            doh or "",
            int(dns_cache_ttl) if dns_cache_ttl is not None else -1,
            interface or "",
            pinned_key or "",
            int(max_download_speed) if max_download_speed is not None else -1,
            int(max_upload_speed) if max_upload_speed is not None else -1,
            -1 if h3_permute is None else (1 if h3_permute else 0),
            _curl_opts_key(curl_options),
        )

        prep = _Prep(
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
            http3_permute_extensions=h3_permute,
            interface=interface,
            pinned_key=pinned_key,
            max_download_speed=max_download_speed,
            max_upload_speed=max_upload_speed,
            curl_options=curl_options,
            headers=merged,
            cookie_header=cookie_header,
            host=host,
            stream=bool(_pick(options, "stream", self.stream)),
            body=body,
            discard_cookies=discard_cookies,
            follow_python=(bool(_pick(options, "allow_redirects", self.allow_redirects))
                           and method.upper() not in _NATIVE_METHODS),
        )
        return self._with_redirect_plan(prep)

    @staticmethod
    def _with_redirect_plan(prep: "_Prep") -> "_Prep":
        """把「谁来跟重定向」这件事定下来。

        * GET/POST/HEAD —— 交给 libcurl（它的 httpreq 语义与浏览器完全一致）；
        * 其余方法（PUT/PATCH/DELETE/OPTIONS/TRACE）—— libcurl 只会把语义切 GET、
          方法串留着（303 该降级的情况它降不下来），所以在 Python 侧按
          :func:`next_redirect_hop` 的矩阵自己跟。
        """
        if prep.follow_python:
            prep.redirects = False
            prep.stream = False        # 中间跳要整读，索性整条请求都缓冲
        return prep

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
            else:
                # ech=False -> 显式关掉（NULL 复位），不能靠"不设置"来偷懒
                lib.set_option_string(ptr, CurlOpt.ECH, None)
        if prep.doh:
            lib.set_option_string(ptr, CurlOpt.DOH_URL, _as_bytes(prep.doh))
        if prep.dns_cache_ttl is not None:
            lib.set_option_long(ptr, CurlOpt.DNS_CACHE_TIMEOUT, int(prep.dns_cache_ttl))
        if prep.http3_permute_extensions is not None:
            # CURL_HTTP3_SSL_PERMUTE_ENABLE=1 / DISABLE=0（-1 = 回退默认）
            lib.set_option_long(ptr, CurlOpt.HTTP3_SSL_PERMUTE_EXTENSIONS,
                                1 if prep.http3_permute_extensions else 0)
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
        # 这三项不会因为"这次没传"而自动消失：句柄是池里复用的，
        # 上一请求留下的 timeout / auth 会继续生效（配置残留 = 行为漂移）。
        # 所以这里**每次显式下发**，没有就写 0 / NULL 复位。
        lib.easy_set_timeout(
            ptr, int(float(prep.timeout) * 1000) if prep.timeout else 0)
        lib.easy_set_connect_timeout(
            ptr, int(float(prep.connect_timeout) * 1000)
            if prep.connect_timeout else 0)
        lib.easy_set_userpwd(
            ptr, prep.userpwd.encode("utf-8") if prep.userpwd else None)

        lib.easy_set_header_lines(ptr, _header_lines_arg(prep.headers))
        # Cookie 头已经在上面那份 header 行里（显式 cookie 由 Python 拼成一条
        # ``Cookie: …`` 行、位置就是用户给的那个位置），所以 CURLOPT_COOKIE 这一路
        # 必须保持 NULL —— 句柄是池里复用的，上一次请求留下的值不清掉就会多一条。
        lib.easy_set_cookies(ptr, None)
        # 引擎自己拼的 Cookie 也只发**一条**头。curl-impersonate 的每个预设都把
        # split_cookies 打开，HTTP/2 下 libcurl 会把 "a=1; b=2" 拆成两条 `cookie`
        # 头（lib/http.c 的 http_cookies split 分支）。服务端只要按"同名头覆盖"
        # 或只读最后一条处理，整串登录态就只剩一截。这里显式按不拆行下发；
        # 想复刻浏览器式拆行，用 diy_fp={"split_cookies": True} 打开。
        lib.set_option_long(
            ptr, CurlOpt.SPLIT_COOKIES,
            1 if prep.fingerprint.overrides.split_cookies else 0)
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
    # cookie：引擎拼头 与 显式 Cookie 头行，同一时刻只用一条
    # ------------------------------------------------------------------ #
    def _sync_cookies(self, ptr: Any, prep: _Prep,
                      pushed: dict[tuple, str]) -> None:
        """发送前把这只 handle 的 cookie 引擎**清空**（`ALL`）。

        为什么清空：``Cookie:`` 头一律由 Python 侧按浏览器口径拼好放进 header 行
        （见 :meth:`_prepare`），引擎再拼一条就会变成两个 ``Cookie`` 头、或者顺序
        被它自己的 ``cookie_sort`` 改写。引擎仍然开着，所以**本次响应**里的
        ``Set-Cookie`` 照常被学到，收尾时经 ``CURLINFO_COOKIELIST`` 导出并吸收进
        会话罐（罐里原有的 cookie 一条都没丢，它们本来就在 Python 侧）。

        ``pushed`` 因此不再需要增量下发（留参数是为了兼容既有调用点）。
        """
        lib.easy_set_cookie_list(ptr, b"ALL")
        pushed.clear()

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
        retry = _Retry(self, prep)

        while True:
            # attempt 0 且该 origin 未被标记 -> 允许复用；否则强制新建连接。
            lib.easy_set_fresh_connect(
                handle.ptr, 1 if retry.fresh_connect(tcp_switched) else 0)
            started = time.perf_counter()
            code, status, content, raw_headers, error = lib.perform(handle.ptr)
            retry.wall += time.perf_counter() - started

            if not retry.on_failure(self, code, prep.url):
                break

        return code, status, content, raw_headers, error, retry.wall

    @staticmethod
    def _raise_for_code(code: int, message: str, *,
                        proxy_error: int | None = None,
                        proxy_in_use: str | None = None) -> None:
        """按 CURLcode 抛对应异常。

        文案统一带数值、符号名、中文说明与官方错误码手册链接，
        方便直接按错误码查。代理相关的失败再补上"代理子原因"（``proxy_error``）
        与"这次走的是哪个代理"（``proxy_in_use``）—— 97 只有一句笼统的
        proxy handshake error，不补这些信息根本看不出代理配错在哪。
        整条文案始终单行（换行会被压成空格），日志里不会撑成一大坨。
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
    # ------------------------------------------------------------------ #
    # 共享生命周期：prepare -> acquire/configure -> execute -> finish
    # 同步、异步、流式、WebSocket 都复用下面这几个阶段，
    # 区别只在"谁执行"（curl_easy_perform / multi 驱动 / 后台流式线程）。
    # ------------------------------------------------------------------ #
    def _acquire_configured(self, prep: _Prep, tcp_profile: TcpProfile | None):
        """取一个池内句柄并完成全部配置。

        返回 ``(pool, handle, (rcvbuf_plan, tcp_switched))``。

        配置失败时句柄**不进池**（:meth:`_Pool.discard` 直接销毁）：
        半个配置的句柄被下一个请求复用会踩到脏状态，比多建一次连接昂贵得多。
        """
        pool = self._pool_for(prep.key)
        handle = pool.acquire()
        try:
            staged = self._configure(handle, prep, tcp_profile)
        except BaseException:
            pool.discard(handle)
            raise
        return pool, handle, staged

    def _configure(self, handle: "_Handle", prep: _Prep,
                   tcp_profile: TcpProfile | None):
        """把指纹 / TCP 画像 / 句柄选项 / cookie 全部落到句柄上（四个路径共用）。"""
        self._apply_fingerprint(handle.ptr, prep.fingerprint)
        rcvbuf_plan, tcp_switched = self._apply_tcp(handle, tcp_profile)
        self._apply_handle_options(handle.ptr, prep)
        self._sync_cookies(handle.ptr, prep, handle.pushed_cookies)
        return rcvbuf_plan, tcp_switched

    def _collect_result(self, handle: "_Handle", prep: _Prep):
        """传输结束后的收尾读数：getinfo + cookie 导出。

        导出必须在句柄回到池里之前做完：句柄是复用的，下一次请求的 cookie 同步
        会改写引擎，晚一步读就串味了。
        """
        info = _read_info(handle)
        cookie_dump = lib.get_cookies(handle.ptr)
        return info, cookie_dump

    def _finish(self, prep: _Prep, info: "_Info", cookie_dump: str,
                code: int, error: str | None,
                response: Response | None = None) -> Response | None:
        """共享收尾：吸收 cookie（含删除），然后按 CURLcode 抛对应异常（0 = 正常）。

        ``raise_for_status=True`` 时 4xx/5xx 在这里直接抛（与 curl_cffi 的会话级
        参数一致）；``discard_cookies=True`` 时这只请求既不读也不写 cookie 罐。
        """
        if info is None:
            # 结构保证：只有"真的传输完并读过结果"的 transfer 才允许走到这里。
            # 中止/失败一律交付明确异常，不许变成成功空正文或 AttributeError。
            raise NbCurlError(
                "内部状态错误：本次请求没有收尾信息（不应被当作成功交付）")
        if not prep.discard_cookies:
            self.cookies._absorb(cookie_dump, time.time())
            if response is not None:
                self._absorb_cookie_deletions(prep, response)
        if code != 0:
            self._raise_for_code(
                code, error or lib.strerror(code),
                proxy_error=info.proxy_error,
                proxy_in_use=_proxy_in_use(prep.proxy, prep.url))
        return response

    def _absorb_cookie_deletions(self, prep: _Prep, response: Response) -> None:
        """把响应里 ``Max-Age=0`` / 过期 ``Expires`` 的删除落到会话罐。

        引擎在发送前被清空（:meth:`_sync_cookies`），所以"删掉罐里已有的那条"这类
        通知它自己不会有；这里直接用响应头的原文补上，重定向中间跳也算。
        """
        hops = list(getattr(response, "history", ()) or ()) + [response]
        for hop in hops:
            for raw in hop.headers.get_list("set-cookie"):
                self.cookies.remember_set_cookie(
                    raw, prep.host, urlsplit(getattr(hop, "url", "") or prep.url).path or "/")

    def _request(self, method: str, url: str,
                 **options: Unpack[RequestOptions]) -> Response:
        """执行一次请求。

        参数见 :class:`nb_curl.params.RequestOptions`（``nb_curl.params.describe()``
        可打印完整表）。``params`` 会先并进 URL，再做其余装配。
        """
        check_options("请求", options, REQUEST_KEYS)
        if self._closed:
            raise NbCurlError("Session 已关闭")

        prep = self._prepare(method, _final_url(url, options.get("params")), options)
        tcp_profile = self._build_tcp(options, prep)
        if prep.follow_python:
            return self._follow_redirects(prep, options, tcp_profile)
        if prep.stream:
            return self._request_stream(prep, tcp_profile)
        return self._perform_one(prep, tcp_profile)

    def _perform_one(self, prep: "_Prep", tcp_profile: Any) -> Response:
        """发**一跳**（非流式）并收尾：cookie 吸收 / 错误码映射都在这里。"""
        pool, handle, staged = self._acquire_configured(prep, tcp_profile)
        rcvbuf_plan, tcp_switched = staged
        reusable = False
        try:
            code, status, content, raw_headers, error, wall = self._perform(
                handle, prep, rcvbuf_plan, tcp_switched)
            self._verify_tcp(handle, code, tcp_profile, rcvbuf_plan)
            info, cookie_dump = self._collect_result(handle, prep)
            reusable = True
        finally:
            # 收尾/读数中途抛异常 = 这只句柄的状态已不确定（只读了一半的传输
            # 也在上面）：销毁而不是放回池里污染下一个请求。
            if reusable:
                pool.release(handle)
            else:
                pool.discard(handle)

        response = _build_response(prep, info, status, content, raw_headers, wall, cookie_dump)
        self._finish(prep, info, cookie_dump, code, error, response)
        return response

    def _follow_redirects(self, prep: "_Prep", options: Mapping[str, Any],
                          tcp_profile: Any) -> Response:
        """在 Python 侧按浏览器矩阵跟重定向（只用于非原生方法）。

        libcurl 对 ``CUSTOMREQUEST`` 的自定义方法只会"语义切 GET、方法串留着"，
        所以 303 该降级成 GET 的情况它降不下来（PUT/PATCH/DELETE 都会带着方法名
        发个空 body 出去）。这里改成逐跳自己发，规则见 :func:`next_redirect_hop`。
        """
        hops: list[Response] = []
        while True:
            response = self._perform_one(prep, tcp_profile)
            method, next_url, next_options = next_redirect_hop(prep, options, response)
            if method is None:
                if hops:
                    response.history = hops + list(response.history or [])
                    response.redirect_count = len(response.history)
                return response
            if len(hops) >= max(0, int(prep.max_redirects or 0)):
                raise TooManyRedirects(
                    "重定向次数超限（max_redirects=%d）：%s" % (prep.max_redirects, next_url))
            hops.append(response)
            prep = self._prepare(method, next_url, next_options)
            prep.redirects = False
            prep.follow_python = True
            prep.stream = False
            tcp_profile = self._build_tcp(next_options, prep)

    def _stream_reader(self, prep: _Prep) -> tuple[Response, "_StreamBody"]:
        """建好流式响应与读取器（**不启动**），并确保它已被登记进 ``_streams``。

        调用方必须在启动前拿到这两个对象：``AsyncSession`` 要在事件循环线程里
        建它（这样"响应头还没到就被取消/关闭"也能及时中止），而真正的装配与传输
        由会话级 reactor 做。
        """
        if self._closed:
            raise NbCurlError("Session 已关闭")
        from ._stream_reactor import ReactorStream

        class _ReactorStream(ReactorStream, _StreamBody):
            """基类（消费接口）+ reactor 传输侧的组合（见 _stream_reactor）。"""
            __doc__ = ReactorStream.__doc__

        response = Response(
            status_code=0,
            headers=Headers(),
            content=None,
            url=prep.url,
            request=Request(prep.method, prep.url, Headers(prep.headers)),
        )
        reader = _ReactorStream(self, prep, response)   # 构造时即登记进 _streams
        response._stream = reader
        if self._closed:
            # 与 close() 的枚举赛跑：登记之后再看一次关闭位，窗口就闭合了
            reader.close(join=False)
            raise NbCurlError("Session 已关闭")
        return response, reader

    def _request_stream(self, prep: _Prep, tcp_profile: TcpProfile | None) -> Response:
        """流式下载（同步）：独立句柄 + **会话级 reactor**，响应体在写回调里当场交给 Python。

        ``stream=True`` 走这条路 —— 不等整个响应体下载完（那样内存占用就等于文件
        大小），而是调用方要一块给一块。独立句柄的代价是这类请求不复用连接池里的
        连接，换来的是一块连接完全由这条流独占（``close()`` 能干净地中止它）。

        读完之前调用方一直阻塞在 ``_take()`` 上，但传输跑在 reactor 线程：
        所以在事件循环里同步调 ``content`` / ``iter_content`` 也不会死锁。
        """
        response, reader = self._stream_reader(prep)
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
        from .ws import WebSocket, configure_ws_handshake

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
            # 握手前关掉 libcurl 的自动 PONG（CURLWS_NOAUTOPONG）：自动 PONG 只排进
            # 内部 pending，纯 recv 轮询永远不会被 flush；PONG 由 WebSocket.recv 回。
            configure_ws_handshake(ptr, lib)

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
