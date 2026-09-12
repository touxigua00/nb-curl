"""nb_curl.session —— requests 风格的 Session

关键设计：

* **连接池按指纹隔离**：每个 (指纹, verify, proxy, http_version) 组合对应一个
  native easy handle。TLS 指纹只在新建连接时生效，所以切换指纹必须换 handle，
  否则会复用到旧指纹的 TLS 连接（这是最容易踩的坑）。
* **每次请求全量重设 option**：不依赖任何跨请求残留，从根上避免"第二次请求
  丢 header"这类问题。
* **impersonate 先于用户头下发**：libcurl 内部把浏览器默认头放在
  CURLOPT_HTTPBASEHEADER，用户头放 CURLOPT_HTTPHEADER，两者按序合并。
"""

from __future__ import annotations

import json as _json
import os
import threading
import time
import uuid
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ._native import lib
from .const import (
    CURLINFO_EFFECTIVE_URL,
    CURLINFO_HTTP_VERSION,
    CURLINFO_PRIMARY_IP,
    CURLINFO_REDIRECT_COUNT,
    CURLINFO_TOTAL_TIME,
    resolve_http_version,
)
from .exceptions import (
    ConnectTimeout,
    NbCurlError,
    ImpersonateError,
    RequestError,
    Timeout,
    TooManyRedirects,
)
from .fingerprint import Fingerprint, build_overrides
from .impersonate import ImpersonateTarget, resolve_target
from .models import Headers, Request, Response, parse_header_blocks
from .xcctls import load_fp_snapshot

__all__ = ["Session", "request", "get", "post", "put", "patch", "delete", "head", "options"]

_DEFAULT_CA_ENV = "NB_CURL_CA_BUNDLE"

# libcurl 错误码
_CURLE_OPERATION_TIMEDOUT = 28
_CURLE_COULDNT_CONNECT = 7
_CURLE_COULDNT_RESOLVE_HOST = 6
_CURLE_COULDNT_RESOLVE_PROXY = 5
_CURLE_TOO_MANY_REDIRECTS = 47

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
    here = os.path.dirname(os.path.abspath(__file__))
    bundled = os.path.join(here, "_lib", "cacert.pem")
    if os.path.isfile(bundled):
        return bundled
    return None


def _to_bytes(data: Any) -> bytes:
    if data is None:
        return b""
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, str):
        return data.encode("utf-8")
    return str(data).encode("utf-8")


def _merge_url(url: str, params: Any) -> str:
    if not params:
        return url
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    if isinstance(params, Mapping):
        query.extend(params.items())
    else:
        query.extend(params)
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


def _encode_multipart(fields: Mapping[str, Any], files: Mapping[str, Any],
                      boundary_style: str = "webkit") -> tuple[bytes, str]:
    """自己拼 multipart/form-data，避免依赖 CURLOPT_MIMEPOST。"""
    if boundary_style == "webkit":
        boundary = "----WebKitFormBoundary" + uuid.uuid4().hex[:16]
    else:
        boundary = "--------------------------" + uuid.uuid4().hex[:24]

    out = bytearray()

    def part_header(name: str, filename: str | None = None, content_type: str | None = None) -> None:
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


class _Handle:
    """一个 native easy handle + 它自己的连接缓存。"""

    __slots__ = ("ptr", "busy")

    def __init__(self, key: tuple):
        ptr = lib.easy_init()
        if not ptr:
            raise NbCurlError("easy_init() 失败：native 句柄创建不成功")
        self.ptr = ptr
        self.busy = False
        # 开启内存 cookie 引擎，这样 Set-Cookie 会被记录下来
        lib.easy_set_cookie_engine(ptr, 1)

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

    def acquire(self, key: tuple) -> _Handle:
        with self._cond:
            while True:
                for handle in self._handles:
                    if not handle.busy:
                        handle.busy = True
                        return handle
                if len(self._handles) < self._max:
                    handle = _Handle(key)
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


def _parse_cookie_list(raw: str) -> dict[str, str]:
    """解析 libcurl 的 Netscape 格式 cookie 列表。"""
    jar: dict[str, str] = {}
    for line in raw.splitlines():
        if not line:
            continue
        # 注释行（#HttpOnly_ 开头的仍是有效 cookie）
        if line.startswith("#") and not line.startswith("#HttpOnly_"):
            continue
        fields = line.split("\t")
        if len(fields) >= 7:
            jar[fields[-2]] = fields[-1]
    return jar


class Session:
    """类 requests 的会话对象，支持浏览器指纹。

    所有会话级参数都可以在请求级（``get`` / ``post`` / ``request`` 等）
    逐项覆盖；请求级传了就覆盖会话级，没传就沿用会话级。

    :param impersonate: 内置浏览器指纹预设名，如 ``"chrome152"``、
        ``"firefox147"``。完整取值见 :data:`nb_curl.impersonate.ImpersonateTarget`
        （IDE 对该参数会直接补全），或运行 ``nb_curl.available_targets()``。
        家族别名（``"chrome"``/``"firefox"``/``"safari"``/``"edge"``）自动
        解析为该家族最新版。也可传 :class:`nb_curl.Fingerprint` 对象
        （如 ``parse_xcctls()`` 的结果）。加 ``":no"`` 后缀（如
        ``"chrome152:no"``）表示不附带该预设的浏览器默认请求头。
    :param ja3: JA3 指纹字符串
        ``TLSVersion,Ciphers,Extensions,Groups,ECPointFormats``，
        覆盖预设的 TLS 层指纹。
    :param akamai: Akamai HTTP/2 指纹
        ``SETTINGS|WINDOW_UPDATE|STREAMS|PSEUDO_HEADER_ORDER``，
        覆盖预设的 H2 层指纹（隐含 HTTP/2）。
    :param diy_fp: 键值对形式的细粒度指纹覆盖项，如
        ``{"tls_grease": True, "tls_trust_anchors": ""}``。
        可用键及取值范围用 ``nb_curl.diy_fp_fields()`` 查询。
    :param fp_file: 指纹快照（浏览器访问 https://www.xcctls.top/all 的
        响应 JSON）：文件路径、JSON 文本或 dict。一键复刻抓取到的
        完整指纹（含浏览器默认头）。与 impersonate/ja3/akamai/diy_fp
        可以叠加（快照打底，显式参数覆盖）。
    :param headers: 会话级默认请求头（dict）。会被请求级同名头覆盖。
    :param cookies: 会话级 cookie（dict）。响应的 Set-Cookie 会自动
        记录回 ``session.cookies``。
    :param auth: HTTP 基本认证，``("user", "password")`` 二元组或
        ``"user:password"`` 字符串。
    :param proxy: 单个代理 URL，对所有协议生效，如
        ``"socks5h://user:pass@host:port"``、``"http://host:8080"``。
    :param proxies: 按协议选代理的字典，如
        ``{"http": "socks5h://...", "https": "socks5h://..."}``；
        也接受 ``"all"`` 键。与 ``proxy`` 同时给出时 ``proxy`` 优先。
    :param verify: 是否校验服务端证书（默认 True）。
    :param ca_path: CA bundle 路径；不传则自动找（环境变量
        ``NB_CURL_CA_BUNDLE`` > certifi > 包内自带）。
    :param timeout: 整个请求的超时秒数（含传输）。
    :param connect_timeout: 仅 TCP/TLS 建连阶段的超时秒数。
    :param allow_redirects: 是否自动跟随重定向（默认 True）。
    :param max_redirects: 最大重定向次数（默认 30）。
    :param http_version: 强制 HTTP 版本：``"1.0"``/``"1.1"``/``"2"``/
        ``"2tls"``/``"2prior"``/``"3"``（默认按指纹走 2TLS）。
    :param default_headers: impersonate 预设是否附带浏览器默认请求头
        （默认 True）。
    :param max_clients: 同一指纹下并发的 native handle 上限（默认 1；
        线程并发场景调大，如 AsyncSession 默认 20）。
    :param max_retries: 幂等请求遇"连接复用失败"时的重试次数（默认 2）。
    :param debug: True 时打开 libcurl verbose 输出到 stderr。
    """

    def __init__(
        self,
        *,
        impersonate: ImpersonateTarget | str | Fingerprint | None = None,
        ja3: str | None = None,
        akamai: str | None = None,
        diy_fp: Mapping[str, Any] | None = None,
        fp_file: str | os.PathLike | Mapping[str, Any] | None = None,
        headers: Mapping[str, Any] | None = None,
        cookies: Mapping[str, Any] | None = None,
        auth: Any = None,
        proxy: str | None = None,
        proxies: Mapping[str, str] | str | None = None,
        verify: bool = True,
        ca_path: str | None = None,
        timeout: float | None = None,
        connect_timeout: float | None = None,
        allow_redirects: bool = True,
        max_redirects: int = 30,
        http_version: Any = None,
        default_headers: bool = True,
        max_clients: int = 1,
        max_retries: int = 2,
        debug: bool = False,
    ):
        # impersonate 也可直接传 Fingerprint 对象（等价于会话级快照）
        fp_snapshot_arg: Fingerprint | None = None
        if isinstance(impersonate, Fingerprint):
            fp_snapshot_arg = impersonate
            impersonate = None

        if impersonate is not None:
            # 提前校验，避免每次请求才报错
            from .impersonate import is_available

            name = impersonate.partition(":")[0].strip()
            if not is_available(name):
                raise ImpersonateError("未知或不可用的 impersonate target: %r" % impersonate)

        self.impersonate = impersonate
        self.ja3 = ja3
        self.akamai = akamai
        self.diy_fp = dict(diy_fp) if diy_fp else None
        self.default_headers = default_headers

        # fp_file：浏览器指纹快照（xcctls.top/all 的响应）。
        # 会话级只解析一次（load_fp_snapshot 自带按 mtime+size 的缓存）；
        # 显式传 Fingerprint 对象优先于 fp_file。
        self.fp_file = fp_file
        self._fp_snapshot = fp_snapshot_arg if fp_snapshot_arg is not None else (
            load_fp_snapshot(fp_file) if fp_file is not None else None)

        self.headers = Headers(list((headers or {}).items())) if headers else Headers()
        self.cookies = dict(cookies) if cookies else {}
        self.auth = auth
        self.proxy = proxy
        self.proxies = proxies
        self.verify = verify
        self.ca_path = ca_path if ca_path is not None else (_default_ca_path() if verify else None)
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.allow_redirects = allow_redirects
        self.max_redirects = max_redirects
        if http_version is not None:
            # 提前校验，别等到发请求才报错
            resolve_http_version(http_version)
        self.http_version = http_version
        self.max_clients = max(1, int(max_clients))
        self.max_retries = max(0, int(max_retries))
        self.debug = debug

        # 会话级 overrides = 快照 overrides（若有）+ 显式 ja3/akamai/diy_fp
        self._session_overrides = build_overrides(ja3=ja3, akamai=akamai, diy_fp=self.diy_fp)
        if self._fp_snapshot is not None:
            self._session_overrides = self._fp_snapshot.overrides.merge(self._session_overrides)
        self._session_fp_key = (
            self.impersonate or "",
            self._session_overrides.cache_key(),
        )

        self._pools: dict[tuple, _Pool] = {}
        self._pools_lock = threading.Lock()
        # 已知"复用会失败"的 origin：后续请求直接强制新建连接，不再每次白白失败一次
        self._no_reuse_origins: set[tuple] = set()
        self._no_reuse_lock = threading.Lock()
        self._closed = False

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #
    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
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
    def _build_fingerprint(
        self,
        impersonate: str | Fingerprint | None,
        ja3: str | None,
        akamai: str | None,
        diy_fp: Mapping[str, Any] | None,
        fp_file: Any = None,
    ) -> Fingerprint:
        """合并所有指纹来源，优先级（低 -> 高）：

        impersonate 底座 < 会话级 ja3/akamai/diy_fp
        < 请求级快照 < 请求级 ja3/akamai/diy_fp。

        - ``impersonate`` 传 :class:`Fingerprint` 对象（如
          ``parse_xcctls()`` 的结果）-> 当作请求级快照参与合并；
        - ``fp_file``（xcctls.top/all 快照）-> 解析成完整指纹参与合并，
          其自带浏览器头作为最低层默认头（会被 Session/请求级 headers 覆盖）。
        """
        # 请求级 impersonate=Fingerprint 对象 -> 请求级快照
        req_snap: Fingerprint | None = None
        if isinstance(impersonate, Fingerprint):
            req_snap = impersonate
            impersonate = None

        raw = impersonate if impersonate is not None else self.impersonate

        # --- 快照：请求级 fp_file / 请求级 Fingerprint 优先于会话级 ---
        snap = None
        if fp_file is not None:
            snap = load_fp_snapshot(fp_file)
        elif req_snap is not None:
            snap = req_snap
        elif self._fp_snapshot is not None:
            snap = self._fp_snapshot

        # --- 底座：显式 impersonate 优先，否则用快照自带的底座 ---
        c_impersonate = raw
        if not raw and snap is not None and snap.impersonate:
            c_impersonate = snap.impersonate

        # --- Python 层浏览器默认头（快照自带） ---
        base_headers: list[tuple[str, str]] = list(snap.headers) if (snap and snap.headers) else []

        fp = Fingerprint(
            impersonate=c_impersonate,
            # 有 Python 层默认头时关掉 C 侧浏览器默认头，避免两套头打架
            default_headers=self.default_headers and not base_headers,
            ja3=ja3 if ja3 is not None else self.ja3,
            akamai=akamai if akamai is not None else self.akamai,
            diy_fp=diy_fp if diy_fp is not None else self.diy_fp,
            headers=base_headers or None,
        )

        overrides = self._session_overrides
        # 请求级快照（fp_file 或 impersonate=Fingerprint）覆盖会话级
        if snap is not None and (fp_file is not None or req_snap is not None):
            overrides = overrides.merge(snap.overrides)
        if ja3 or akamai or diy_fp:
            overrides = overrides.merge(build_overrides(ja3=ja3, akamai=akamai, diy_fp=diy_fp))
        fp.overrides = overrides
        return fp

    def _resolve_http_version(self, fp: Fingerprint, http_version: Any) -> Any:
        if http_version is not None:
            return http_version
        if self.http_version is not None:
            return self.http_version
        if fp.force_http2():
            return 20
        return None

    def _proxy_for(self, url: str, proxy: Any, proxies: Any = None) -> str | None:
        """解析本次请求生效的代理：请求级 > 会话级，proxy > proxies。

        ``proxy`` 是单个 URL 字符串，对所有协议生效；
        ``proxies`` 是 {scheme: url} 字典（接受 "all" 键）或字符串。
        """
        # 请求级
        if isinstance(proxy, Mapping):
            # 容错：proxy= 误传了 dict，按 proxies 语义处理
            proxies = proxies if proxies is not None else proxy
            proxy = None
        if isinstance(proxies, Mapping):
            scheme = urlsplit(url).scheme.lower()
            picked = proxies.get(scheme) or proxies.get("all") or proxies.get("https")
        else:
            picked = proxies
        if proxy:
            return str(proxy)
        if picked:
            return str(picked)
        # 会话级
        if self.proxy:
            return str(self.proxy)
        if isinstance(self.proxies, Mapping):
            scheme = urlsplit(url).scheme.lower()
            picked = self.proxies.get(scheme) or self.proxies.get("all") or self.proxies.get("https")
            return str(picked) if picked else (str(self.proxies) if isinstance(self.proxies, str) else None)
        if self.proxies:
            return str(self.proxies)
        return None

    def _pool_for(self, key: tuple) -> _Pool:
        with self._pools_lock:
            pool = self._pools.get(key)
            if pool is None:
                pool = _Pool(self.max_clients)
                self._pools[key] = pool
            return pool

    # ------------------------------------------------------------------ #
    # 内部：请求装配
    # ------------------------------------------------------------------ #
    def _apply_fingerprint(self, handle: _Handle, fp: Fingerprint) -> None:
        if fp.impersonate:
            raw = fp.impersonate
            name, _, flag = raw.partition(":")
            target = resolve_target(name.strip())
            if flag.strip() == "":
                default_headers = fp.default_headers
            else:
                default_headers = flag.strip().lower() not in ("no", "false", "0", "off")
            code = lib.easy_set_impersonate(
                handle.ptr, target.encode("utf-8"), 1 if default_headers else 0
            )
            if code != 0:
                raise ImpersonateError(
                    "下发 impersonate=%r 失败: %s (CURLcode %d，错误码表: "
                    "https://curl.se/libcurl/c/libcurl-errors.html)"
                    % (raw, lib.strerror(code), code)
                )

        if not fp.overrides.is_empty():
            # 兜底校验：parse_* 已校验过，这里防直接构造 FingerprintOverrides 绕过
            fp.overrides.validate()
            code = lib.apply_fingerprint(handle.ptr, fp.overrides.to_values())
            if code != 0:
                from .exceptions import FingerprintError

                raise FingerprintError(
                    "下发自定义指纹失败: %s (CURLcode %d，错误码表: "
                    "https://curl.se/libcurl/c/libcurl-errors.html)"
                    % (lib.strerror(code), code)
                )

    def _request(  # noqa: PLR0913
        self,
        method: str,
        url: str,
        *,
        params: Any = None,
        headers: Mapping[str, Any] | None = None,
        cookies: Mapping[str, Any] | None = None,
        data: Any = None,
        json: Any = None,
        files: Mapping[str, Any] | None = None,
        timeout: float | None = None,
        connect_timeout: float | None = None,
        allow_redirects: bool | None = None,
        max_redirects: int | None = None,
        proxy: str | Mapping[str, str] | None = None,
        proxies: Mapping[str, str] | str | None = None,
        verify: bool | None = None,
        ca_path: str | None = None,
        auth: Any = None,
        impersonate: ImpersonateTarget | str | Fingerprint | None = None,
        ja3: str | None = None,
        akamai: str | None = None,
        diy_fp: Mapping[str, Any] | None = None,
        fp_file: Any = None,
        http_version: Any = None,
    ) -> Response:
        """执行一次请求。参数含义与 :class:`Session` 相同名（见其 docstring），

        会话级未设置或请求级显式传入时生效。额外支持：

        :param params: 追加到 URL 的查询参数（dict 或 (k, v) 序列）。
        :param headers: 本次请求的请求头（覆盖会话级同名头）。
        :param cookies: 本次请求的 cookie（叠加到会话级之上）。
        :param data: 请求体：dict -> 表单（urlencoded），str/bytes 原样。
        :param json: JSON 请求体（自动带 Content-Type: application/json）。
        :param files: multipart/form-data 上传，``{字段名: (文件名, 内容[, 类型])}``。
        """
        if self._closed:
            raise NbCurlError("Session 已关闭")

        method = method.upper()
        url = _merge_url(url, params)

        fp = self._build_fingerprint(impersonate, ja3, akamai, diy_fp, fp_file)
        effective_http_version = self._resolve_http_version(fp, http_version)
        effective_verify = self.verify if verify is None else bool(verify)
        effective_ca = ca_path if ca_path is not None else self.ca_path
        effective_proxy = self._proxy_for(url, proxy, proxies)
        effective_redirects = self.allow_redirects if allow_redirects is None else allow_redirects
        effective_max_redirects = self.max_redirects if max_redirects is None else max_redirects

        # --- 组装请求头（优先级：快照/预设浏览器头 < 会话头 < 请求头） ---
        merged = _merge_headers(fp.headers or [], self.headers.items())
        merged = _merge_headers(merged, headers or {})

        # --- 组装请求体 ---
        body: bytes | None = None
        extra_headers: list[tuple[str, str]] = []
        if files:
            body, boundary = _encode_multipart(data if isinstance(data, Mapping) else {}, files)
            extra_headers.append(("Content-Type", "multipart/form-data; boundary=%s" % boundary))
        elif json is not None:
            body = _json.dumps(json, ensure_ascii=False).encode("utf-8")
            extra_headers.append(("Content-Type", "application/json"))
        elif data is not None:
            if isinstance(data, Mapping):
                body = urlencode(data, doseq=True).encode("utf-8")
                extra_headers.append(("Content-Type", "application/x-www-form-urlencoded"))
            else:
                body = _to_bytes(data)
        if body is not None:
            merged = _merge_headers(merged, dict(extra_headers))

        # --- cookie ---
        jar = dict(self.cookies)
        if cookies:
            jar.update(cookies)
        cookie_header = "; ".join("%s=%s" % (k, v) for k, v in jar.items() if v is not None)

        # --- 连接池键：指纹 + 连接身份 ---
        key = (
            fp.impersonate or "",
            fp.overrides.cache_key(),
            int(effective_verify),
            effective_ca or "",
            effective_http_version,
            effective_proxy or "",
        )

        pool = self._pool_for(key)
        handle = pool.acquire(key)

        try:
            self._apply_fingerprint(handle, fp)

            lib.easy_set_redirect(
                handle.ptr, 1 if effective_redirects else 0, int(effective_max_redirects or 0)
            )
            lib.easy_set_verbose(handle.ptr, 1 if self.debug else 0)
            lib.easy_set_verify(handle.ptr, 1 if effective_verify else 0,
                                (effective_ca or "").encode("utf-8") if effective_ca else None)
            lib.easy_set_proxy(handle.ptr, effective_proxy.encode("utf-8") if effective_proxy else None)

            if effective_http_version is not None:
                version_code = resolve_http_version(effective_http_version)
                if version_code is None:
                    version_code = 0
                code = lib.easy_set_http_version(handle.ptr, int(version_code))
                if code != 0:
                    raise RequestError(
                        "设置 http_version=%r 失败: %s (CURLcode %d，错误码表: "
                        "https://curl.se/libcurl/c/libcurl-errors.html)"
                        % (effective_http_version, lib.strerror(code), code)
                    )

            timeout_s = timeout if timeout is not None else self.timeout
            if timeout_s:
                lib.easy_set_timeout(handle.ptr, int(float(timeout_s) * 1000))
            connect_s = connect_timeout if connect_timeout is not None else self.connect_timeout
            if connect_s:
                lib.easy_set_connect_timeout(handle.ptr, int(float(connect_s) * 1000))

            credentials = auth if auth is not None else self.auth
            if credentials:
                if isinstance(credentials, (tuple, list)):
                    userpwd = "%s:%s" % (credentials[0], credentials[1] if len(credentials) > 1 else "")
                else:
                    userpwd = str(credentials)
                lib.easy_set_userpwd(handle.ptr, userpwd.encode("utf-8"))

            # 请求头（保序、保重复）
            lib.easy_set_header_lines(handle.ptr, _header_lines_arg(merged))

            # cookie
            lib.easy_set_cookies(handle.ptr, cookie_header.encode("utf-8") if cookie_header else None)

            # URL / 方法 / body
            lib.easy_set_url(handle.ptr, url.encode("utf-8"))
            lib.easy_set_method(handle.ptr, method.encode("utf-8"))
            if body is not None:
                lib.easy_set_body(handle.ptr, body, len(body))
            else:
                lib.easy_set_body(handle.ptr, None, 0)

            # --- 执行（含"连接复用失败"自适应重试） ---
            origin = _origin_of(url)
            with self._no_reuse_lock:
                force_fresh = origin in self._no_reuse_origins
            can_retry = method in _IDEMPOTENT_METHODS
            attempts_left = self.max_retries if can_retry else 0
            attempt = 0
            wall = 0.0

            while True:
                # attempt 0 且该 origin 未被标记 -> 允许复用；否则强制新建连接
                lib.easy_set_fresh_connect(handle.ptr, 1 if (force_fresh or attempt) else 0)
                started = time.perf_counter()
                code, status, content, raw_headers, error = lib.perform(handle.ptr)
                wall += time.perf_counter() - started

                if code == 0:
                    break
                reuse_failure = code in _REUSE_FAILURE_CODES
                if reuse_failure and not force_fresh:
                    # 记住这个 origin：以后直接新建连接，避免每次都先失败一次
                    with self._no_reuse_lock:
                        self._no_reuse_origins.add(origin)
                    force_fresh = True
                if reuse_failure and attempts_left > 0:
                    attempts_left -= 1
                    attempt += 1
                    if self.debug:
                        print("[nb_curl] 连接复用失败(%d)，强制新建连接重试 #%d: %s"
                              % (code, attempt, url))
                    continue
                break

            effective_url = _getinfo_string(handle.ptr, CURLINFO_EFFECTIVE_URL) or url
            primary_ip = _getinfo_string(handle.ptr, CURLINFO_PRIMARY_IP) or ""
            http_ver_raw = _getinfo_long(handle.ptr, CURLINFO_HTTP_VERSION) or 0
            redirect_count = _getinfo_long(handle.ptr, CURLINFO_REDIRECT_COUNT) or 0
            curl_total = _getinfo_double(handle.ptr, CURLINFO_TOTAL_TIME)
            cookie_dump = lib.get_cookies(handle.ptr)
        finally:
            pool.release(handle)

        elapsed = curl_total if curl_total else wall

        if cookie_dump:
            self.cookies.update(_parse_cookie_list(cookie_dump))

        if code != 0:
            self._raise_for_code(code, error or lib.strerror(code))

        blocks = parse_header_blocks(raw_headers)
        if blocks:
            final_status, reason, final_headers = blocks[-1]
            history = [
                Response(status_code=c, headers=h, content=b"", url=effective_url,
                         reason=r, elapsed=0.0)
                for c, r, h in blocks[:-1]
            ]
        else:
            final_status, reason, final_headers = status, "", Headers()
            history = []

        response = Response(
            status_code=final_status or status,
            headers=final_headers,
            content=content,
            url=effective_url,
            reason=reason,
            http_version=_http_version_name(http_ver_raw),
            primary_ip=primary_ip,
            elapsed=elapsed,
            history=history,
            redirect_count=redirect_count,
            request=Request(method, url, Headers(merged)),
            cookie_list=cookie_dump,
        )
        return response

    @staticmethod
    def _raise_for_code(code: int, message: str) -> None:
        if code == _CURLE_OPERATION_TIMEDOUT:
            raise Timeout(message, code)
        if code in (_CURLE_COULDNT_CONNECT, _CURLE_COULDNT_RESOLVE_HOST,
                    _CURLE_COULDNT_RESOLVE_PROXY):
            raise ConnectTimeout(message, code)
        if code == _CURLE_TOO_MANY_REDIRECTS:
            raise TooManyRedirects(message, code)
        raise RequestError(message, code)

    # ------------------------------------------------------------------ #
    # 公开方法
    # ------------------------------------------------------------------ #
    def request(self, method: str, url: str, **kwargs: Any) -> Response:
        """通用请求。参数见 :meth:`_request` 与 :class:`Session` 的 docstring。"""
        return self._request(method, url, **kwargs)

    def get(self, url: str, **kwargs: Any) -> Response:
        """GET 请求。全部参数（impersonate/proxy/headers/...）见
        :meth:`_request` 与 :class:`Session` 的 docstring。"""
        return self._request("GET", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> Response:
        """OPTIONS 请求。参数见 :meth:`_request`。"""
        return self._request("OPTIONS", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Response:
        """HEAD 请求。参数见 :meth:`_request`。"""
        return self._request("HEAD", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Response:
        """POST 请求。参数见 :meth:`_request`。"""
        return self._request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> Response:
        """PUT 请求。参数见 :meth:`_request`。"""
        return self._request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> Response:
        """PATCH 请求。参数见 :meth:`_request`。"""
        return self._request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> Response:
        """DELETE 请求。参数见 :meth:`_request`。"""
        return self._request("DELETE", url, **kwargs)

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


# --------------------------------------------------------------------------- #
# 内部小工具
# --------------------------------------------------------------------------- #
def _header_lines_arg(pairs: Sequence[tuple[str, str]]) -> list[bytes]:
    """把 (name, value) 序列编码成 C 侧的 header 行数组（保序、保重复）。"""
    lines: list[bytes] = []
    for name, value in pairs:
        if value is None:
            # value 为 None 表示移除该默认头
            lines.append(("%s:" % name).encode("utf-8"))
            continue
        text = str(value)
        if "\r" in text or "\n" in text:
            raise NbCurlError("头部值不能包含换行: %r" % name)
        lines.append(("%s: %s" % (name, text)).encode("utf-8"))
    return lines


def _getinfo_string(ptr: Any, info: int) -> str | None:
    return lib.getinfo_string(ptr, info)


def _getinfo_long(ptr: Any, info: int) -> int | None:
    return lib.getinfo_long(ptr, info)


def _getinfo_double(ptr: Any, info: int) -> float | None:
    return lib.getinfo_double(ptr, info)


def _http_version_name(value: int) -> str:
    from .const import http_version_name

    return http_version_name(int(value))


# --------------------------------------------------------------------------- #
# 模块级便捷函数
# --------------------------------------------------------------------------- #
def request(method: str, url: str, **kwargs: Any) -> Response:
    """一次性请求（内部创建临时 Session，用完即关）。

    除 ``proxy`` / ``proxies`` / ``default_headers`` / ``max_retries`` /
    ``debug`` 外，其余参数都按请求级参数处理（见 :class:`Session`）。
    """
    session_opts = {k: kwargs.pop(k) for k in
                    ("proxy", "proxies", "default_headers", "max_retries", "debug")
                    if k in kwargs}
    with Session(**session_opts) as session:
        return session._request(method, url, **kwargs)


def get(url: str, **kwargs: Any) -> Response:
    return request("GET", url, **kwargs)


def post(url: str, **kwargs: Any) -> Response:
    return request("POST", url, **kwargs)


def put(url: str, **kwargs: Any) -> Response:
    return request("PUT", url, **kwargs)


def patch(url: str, **kwargs: Any) -> Response:
    return request("PATCH", url, **kwargs)


def delete(url: str, **kwargs: Any) -> Response:
    return request("DELETE", url, **kwargs)


def head(url: str, **kwargs: Any) -> Response:
    return request("HEAD", url, **kwargs)


def options(url: str, **kwargs: Any) -> Response:
    return request("OPTIONS", url, **kwargs)
