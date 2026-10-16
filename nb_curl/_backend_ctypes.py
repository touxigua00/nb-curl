"""nb_curl._backend_ctypes —— ctypes 后端（兜底实现）

在没编译 CFFI API 模式扩展的环境下使用。只依赖标准库，
加载 ``nb_curl_native.dll`` 并声明稳定 C ABI。

对外暴露的接口与 :mod:`nb_curl._backend_cffi` 完全一致，
由 :mod:`nb_curl._native` 在运行期二选一。
"""

from __future__ import annotations

import ctypes
import os

from ._curlopt_generated import CurlOpt

__all__ = ["CtypesBackend", "NativeError", "MULTI_ABI_VERSION"]

#: 与 nb_curl_bridge.h 的 nb_multi_abi_version() 对应；不一致直接报错
MULTI_ABI_VERSION = 3

_IS_WIN = os.name == "nt"
_LIB_FILENAME = "nb_curl_native.dll" if _IS_WIN else "libnb_curl_native.so"


class NativeError(RuntimeError):
    """native 调用返回了错误码。"""

    def __init__(self, code: int, message: str):
        super().__init__("nb_curl native error %d: %s" % (code, message))
        self.code = code
        self.message = message


def _candidate_paths():
    here = os.path.dirname(os.path.abspath(__file__))
    yield os.path.join(here, "_lib", _LIB_FILENAME)
    yield os.path.join(here, _LIB_FILENAME)
    parent = os.path.dirname(here)
    yield os.path.join(parent, "build", _LIB_FILENAME)
    env = os.environ.get("NB_CURL_NATIVE_LIB")
    if env:
        yield env


def load_dll_path() -> str:
    tried = []
    for path in _candidate_paths():
        if path and os.path.isfile(path):
            return path
        if path:
            tried.append(path)
    raise ImportError(
        "找不到 nb_curl 动态库 %s。已尝试:\n  %s\n"
        "可设置环境变量 NB_CURL_NATIVE_LIB 指向该文件。"
        % (_LIB_FILENAME, "\n  ".join(tried))
    )


class _NbFingerprint(ctypes.Structure):
    """必须与 C 端 nb_fingerprint 结构体逐字段一致。"""

    _fields_ = [
        ("struct_size", ctypes.c_int32),
        ("ciphers", ctypes.c_char_p),
        ("tls13_ciphers", ctypes.c_char_p),
        ("curves", ctypes.c_char_p),
        ("sig_hash_algs", ctypes.c_char_p),
        ("extension_order", ctypes.c_char_p),
        ("cert_compression", ctypes.c_char_p),
        ("ssl_version", ctypes.c_int32),
        ("tls_grease", ctypes.c_int32),
        ("tls_grease_sigalgs", ctypes.c_int32),
        ("permute_extensions", ctypes.c_int32),
        ("signed_cert_timestamps", ctypes.c_int32),
        ("status_request", ctypes.c_int32),
        ("enable_alps", ctypes.c_int32),
        ("use_new_alps_codepoint", ctypes.c_int32),
        ("record_size_limit", ctypes.c_int32),
        ("key_shares_limit", ctypes.c_int32),
        ("delegated_credentials", ctypes.c_char_p),
        ("trust_anchors", ctypes.c_char_p),
        ("http2_settings", ctypes.c_char_p),
        ("http2_window_update", ctypes.c_int32),
        ("http2_pseudo_headers_order", ctypes.c_char_p),
        ("http2_streams", ctypes.c_char_p),
        ("http2_no_priority", ctypes.c_int32),
        ("stream_weight", ctypes.c_int32),
        ("stream_exclusive", ctypes.c_int32),
        ("header_order", ctypes.c_char_p),
        ("split_cookies", ctypes.c_int32),
        # 必须与 C 端一致地放在末尾
        ("http2_headers_priority", ctypes.c_int32),
    ]


# struct 字段 -> 类型（'s' 字符串 / 'i' int）
_FP_FIELDS: tuple[tuple[str, str], ...] = tuple(
    (name, "s" if field is ctypes.c_char_p else "i")
    for name, field in _NbFingerprint._fields_
    if name != "struct_size"
)

_c_char_p_p = ctypes.POINTER(ctypes.c_char_p)


class _NbTcpShape(ctypes.Structure):
    """必须与 C 端 nb_tcp_shape 结构体逐字段一致。

    ``window`` / ``wscale`` 不下发（只用于回读比对），真正生效的是 ``rcvbuf``。
    """

    _fields_ = [
        ("ttl", ctypes.c_int32),
        ("mss", ctypes.c_int32),
        ("window", ctypes.c_int32),
        ("wscale", ctypes.c_int32),
        ("rcvbuf", ctypes.c_int32),
        ("timestamp", ctypes.c_int32),
    ]


class _NbTcpShapeActual(ctypes.Structure):
    """必须与 C 端 nb_tcp_shape_actual 结构体逐字段一致（-1 = 读不到）。"""

    _fields_ = [
        ("ttl", ctypes.c_int32),
        ("mss", ctypes.c_int32),
        ("wscale", ctypes.c_int32),
        ("window", ctypes.c_int32),
        ("rcvbuf", ctypes.c_int32),
        ("timestamp", ctypes.c_int32),
    ]


# 下发时按名字对齐（顺序必须与 C 端 nb_tcp_shape 一致）
_TCP_SHAPE_FIELDS = ("ttl", "mss", "window", "wscale", "rcvbuf", "timestamp")
_TCP_ACTUAL_FIELDS = ("ttl", "mss", "wscale", "window", "rcvbuf", "timestamp")


class _NbSockInfo(ctypes.Structure):
    """与 C 端 nb_sock_info 逐字段一致（fd 为 64 位）。"""

    _fields_ = [
        ("fd", ctypes.c_longlong),
        ("action", ctypes.c_int),
        ("_reserved", ctypes.c_int),
    ]


class _NbPollItem(ctypes.Structure):
    """与 C 端 nb_poll_item 逐字段一致。"""

    _fields_ = [
        ("fd", ctypes.c_longlong),
        ("events", ctypes.c_int),
        ("revents", ctypes.c_int),
    ]


class CtypesBackend:
    """用 ctypes 直接驱动 nb_curl_native.dll。"""

    name = "ctypes"

    def __init__(self):
        self.path = load_dll_path()
        self._dll = ctypes.CDLL(self.path)

        def sig(name, restype, argtypes):
            fn = getattr(self._dll, name)
            fn.restype = restype
            fn.argtypes = argtypes
            return fn

        c_void_p, c_char_p, c_int, c_long = (
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_long)

        self.nb_global_init = sig("nb_global_init", c_int, [])
        self.nb_global_cleanup = sig("nb_global_cleanup", None, [])
        self.nb_fingerprint_size = sig("nb_fingerprint_size", c_int, [])

        self._easy_init = sig("easy_init", c_void_p, [])
        self.easy_cleanup = sig("easy_cleanup", None, [c_void_p])
        self.easy_reset = sig("easy_reset", None, [c_void_p])

        self.easy_set_impersonate = sig(
            "easy_set_impersonate", c_int, [c_void_p, c_char_p, c_int])
        self.easy_impersonate_exists = sig("easy_impersonate_exists", c_int, [c_char_p])
        self._easy_apply_fingerprint = sig(
            "easy_apply_fingerprint", c_int, [c_void_p, ctypes.POINTER(_NbFingerprint)])

        self.easy_set_url = sig("easy_set_url", c_int, [c_void_p, c_char_p])
        self.easy_set_method = sig("easy_set_method", c_int, [c_void_p, c_char_p])
        self.easy_set_headers = sig("easy_set_headers", c_int, [c_void_p, c_char_p])
        self.easy_set_cookies = sig("easy_set_cookies", c_int, [c_void_p, c_char_p])
        self.easy_set_cookie_engine = sig("easy_set_cookie_engine", c_int, [c_void_p, c_int])
        self.easy_set_cookie_list = sig("easy_set_cookie_list", c_int, [c_void_p, c_char_p])
        self._easy_get_cookies = sig(
            "easy_get_cookies", c_int, [c_void_p, ctypes.POINTER(c_char_p)])
        self.easy_set_body = sig("easy_set_body", c_int, [c_void_p, c_char_p, c_int])
        self.easy_set_timeout = sig("easy_set_timeout", c_int, [c_void_p, c_long])
        self.easy_set_connect_timeout = sig(
            "easy_set_connect_timeout", c_int, [c_void_p, c_long])
        self.easy_set_verify = sig("easy_set_verify", c_int, [c_void_p, c_int, c_char_p])
        self.easy_set_http_version = sig("easy_set_http_version", c_int, [c_void_p, c_int])
        self.easy_set_proxy = sig("easy_set_proxy", c_int, [c_void_p, c_char_p])
        self.easy_set_userpwd = sig("easy_set_userpwd", c_int, [c_void_p, c_char_p])
        self.easy_set_redirect = sig("easy_set_redirect", c_int, [c_void_p, c_int, c_int])
        self.easy_set_verbose = sig("easy_set_verbose", c_int, [c_void_p, c_int])
        self.easy_set_fresh_connect = sig("easy_set_fresh_connect", c_int, [c_void_p, c_int])
        self._curl_easy_setopt = sig("_curl_easy_setopt", c_int, [c_void_p, c_int, c_void_p])

        # TCP 层画像（JA4T）
        self._easy_set_tcp_shape = sig(
            "easy_set_tcp_shape", c_int, [c_void_p, ctypes.POINTER(_NbTcpShape)])
        self._easy_get_tcp_shape_error = sig("easy_get_tcp_shape_error", c_char_p, [c_void_p])
        self._easy_check_tcp_shape = sig(
            "easy_check_tcp_shape", c_int,
            [c_void_p, ctypes.POINTER(_NbTcpShapeActual)])

        # 通用 setopt 直传
        self.easy_set_option_long = sig(
            "easy_set_option_long", c_int, [c_void_p, c_int, c_long])
        self.easy_set_option_string = sig(
            "easy_set_option_string", c_int, [c_void_p, c_int, c_char_p])
        self._easy_set_option_slist = sig(
            "easy_set_option_slist", c_int, [c_void_p, c_int, _c_char_p_p, c_int])
        self.easy_set_option_off = sig(
            "easy_set_option_off", c_int, [c_void_p, c_int, ctypes.c_longlong])

        # WebSocket
        self._easy_ws_send = sig(
            "easy_ws_send", c_int, [c_void_p, c_char_p, c_int, c_int])
        self._easy_ws_recv = sig(
            "easy_ws_recv", c_int,
            [c_void_p, ctypes.POINTER(ctypes.c_char), c_int,
             ctypes.POINTER(c_int), ctypes.POINTER(c_int),
             ctypes.POINTER(ctypes.c_longlong), ctypes.POINTER(ctypes.c_longlong)])

        self._easy_perform = sig(
            "easy_perform_take", c_int,
            [c_void_p, ctypes.POINTER(c_int),
             ctypes.POINTER(c_char_p), ctypes.POINTER(ctypes.c_size_t),
             ctypes.POINTER(c_char_p), ctypes.POINTER(ctypes.c_size_t),
             ctypes.POINTER(c_char_p)])
        self._easy_free_string = sig("easy_free_string", None, [c_void_p])

        self._easy_getinfo_long = sig(
            "easy_getinfo_long", c_int, [c_void_p, c_int, ctypes.POINTER(c_long)])
        self._easy_getinfo_double = sig(
            "easy_getinfo_double", c_int, [c_void_p, c_int, ctypes.POINTER(ctypes.c_double)])
        self._easy_getinfo_string = sig(
            "easy_getinfo_string", c_int, [c_void_p, c_int, ctypes.POINTER(c_char_p)])

        self._easy_version = sig("easy_version", c_char_p, [])
        self._easy_strerror = sig("easy_strerror", c_char_p, [c_int])

        # 阶段 2：multi / 结果移交 / poll（内部名一律 _m_*，包装方法在下面）
        self._m_abi = sig("nb_multi_abi_version", c_int, [])
        self._m_init = sig("nb_multi_init", c_void_p, [])
        self._m_cleanup = sig("nb_multi_cleanup", None, [c_void_p])
        self._m_add = sig("nb_multi_add", c_int, [c_void_p, c_void_p])
        self._m_remove = sig("nb_multi_remove", c_int, [c_void_p, c_void_p])
        self._m_active = sig("nb_multi_active", c_int, [c_void_p])
        self._m_perform = sig("nb_multi_perform", c_int, [c_void_p])
        self._m_socket_action = sig(
            "nb_multi_socket_action", c_int, [c_void_p, ctypes.c_longlong, c_int])
        self._m_snapshot = sig(
            "nb_multi_socket_snapshot", c_int,
            [c_void_p, ctypes.POINTER(_NbSockInfo), c_int, ctypes.POINTER(c_int)])
        self._m_socket_changes = sig(
            "nb_multi_socket_changes", c_int,
            [c_void_p, ctypes.POINTER(_NbSockInfo), c_int, ctypes.POINTER(c_int)])
        self._m_timer = sig(
            "nb_multi_timer", c_int, [c_void_p, ctypes.POINTER(c_long)])
        self._m_fire_timer = sig("nb_multi_fire_timer", c_int, [c_void_p])
        self._m_poll = sig(
            "nb_multi_poll", c_int, [c_void_p, c_long, ctypes.POINTER(c_int)])
        self._m_wakeup = sig("nb_multi_wakeup", c_int, [c_void_p])
        self._m_drain = sig(
            "nb_multi_drain", c_int,
            [c_void_p, ctypes.POINTER(c_int), ctypes.POINTER(c_int),
             ctypes.POINTER(c_void_p)])
        self._easy_prepare_request = sig("easy_prepare_request", c_int, [c_void_p])
        self._easy_take_body = sig(
            "easy_take_body", c_int,
            [c_void_p, ctypes.POINTER(c_void_p), ctypes.POINTER(ctypes.c_size_t)])
        self._easy_take_headers = sig(
            "easy_take_headers", c_int,
            [c_void_p, ctypes.POINTER(c_void_p), ctypes.POINTER(ctypes.c_size_t)])
        self._easy_pause = sig("easy_pause", c_int, [c_void_p, c_int])
        self._poll_sockets_raw = sig(
            "nb_poll_sockets", c_int,
            [ctypes.POINTER(_NbPollItem), c_int, c_long])

        # 初始化前先校验 ABI 布局，避免结构体错位导致的静默错误
        expect = self.nb_fingerprint_size()
        actual = ctypes.sizeof(_NbFingerprint)
        if expect != actual:
            raise ImportError(
                "nb_curl native ABI 不匹配：C 端 nb_fingerprint=%d 字节，"
                "Python 端=%d 字节。请重新安装与本机平台匹配的 nb-curl。" % (expect, actual))

        # 阶段 2：multi ABI 必须存在且版本一致（不静默降级到旧 DLL）
        ver = self._m_abi()
        if ver != MULTI_ABI_VERSION:
            raise ImportError(
                "nb_curl native 库的 multi ABI 版本为 %r，期望 %d。"
                "请用 build/ 下的新脚本重新构建 native/nb_curl_bridge.c。"
                % (ver, MULTI_ABI_VERSION))
        for cls, want in ((_NbSockInfo, 16), (_NbPollItem, 16)):
            got = ctypes.sizeof(cls)
            if got != want:
                raise ImportError(
                    "nb_curl native ABI 不匹配：%s=%d 字节，期望 %d 字节。"
                    % (cls.__name__, got, want))

        self.nb_global_init()

    # -- 句柄 -------------------------------------------------------------- #
    def easy_init(self):
        return self._easy_init()

    # -- 指纹 -------------------------------------------------------------- #
    def apply_fingerprint(self, handle, values: dict) -> int:
        """按 values（FingerprintOverrides.as_dict()）构造 struct 并下发。"""
        st = _NbFingerprint()
        st.struct_size = 0
        keep: list[bytes] = []
        for field_name, kind in _FP_FIELDS:
            value = values.get(field_name)
            if kind == "s":
                if value is None:
                    continue
                data = str(value).encode("utf-8")
                keep.append(data)
                setattr(st, field_name, data)
            else:
                # None -> -1（不设置）；bool -> 0/1
                if value is None:
                    setattr(st, field_name, -1)
                elif isinstance(value, bool):
                    setattr(st, field_name, 1 if value else 0)
                else:
                    setattr(st, field_name, int(value))
        st._keepalive = keep  # type: ignore[attr-defined]
        return self._easy_apply_fingerprint(handle, ctypes.byref(st))

    # -- 保序请求头 -------------------------------------------------------- #
    def easy_set_header_lines(self, handle, lines: list[bytes]) -> int:
        array = (ctypes.c_char_p * (len(lines) or 1))()
        for i, line in enumerate(lines):
            array[i] = line
        fn = getattr(self._dll, "easy_set_header_lines")
        fn.restype = ctypes.c_int
        fn.argtypes = [ctypes.c_void_p, _c_char_p_p, ctypes.c_int]
        return fn(handle, array, len(lines))

    # -- DNS 覆盖 ---------------------------------------------------------- #
    def easy_set_resolve(self, handle, entries: list[bytes]) -> int:
        array = (ctypes.c_char_p * (len(entries) or 1))()
        for i, entry in enumerate(entries):
            array[i] = entry
        fn = getattr(self._dll, "easy_set_resolve")
        fn.restype = ctypes.c_int
        fn.argtypes = [ctypes.c_void_p, _c_char_p_p, ctypes.c_int]
        return fn(handle, array, len(entries))

    # -- TCP 层画像（JA4T） ----------------------------------------------- #
    def easy_set_tcp_shape(self, handle, *, ttl=None, mss=None, window=None,
                           wscale=None, rcvbuf=None, timestamp=None) -> int:
        """下发 socket 级 TCP 画像；六个字段全不给 = 取消画像。

        缺省项写 -1（C 端约定：-1 = 不设置、跟随本机）。``window`` / ``wscale``
        只用于回读比对，真正下发的是折算好的 ``rcvbuf``。
        """
        values = (ttl, mss, window, wscale, rcvbuf, timestamp)
        if all(v is None for v in values):
            return self._easy_set_tcp_shape(handle, None)
        st = _NbTcpShape(*(-1 if v is None else int(v) for v in values))
        return self._easy_set_tcp_shape(handle, ctypes.byref(st))

    def easy_get_tcp_shape_error(self, handle):
        """perform 期间 socket 层设置失败的原因；没失败返回 ``None``。"""
        raw = self._easy_get_tcp_shape_error(handle)
        return raw.decode("utf-8", "replace") if raw else None

    def easy_check_tcp_shape(self, handle):
        """连接期间回读到的 socket 快照（dict）；没建新连接 / 读不到返回 ``None``。"""
        out = _NbTcpShapeActual()
        if self._easy_check_tcp_shape(handle, ctypes.byref(out)) != 0:
            return None
        return {name: int(getattr(out, name)) for name in _TCP_ACTUAL_FIELDS}

    # -- 执行 -------------------------------------------------------------- #
    def perform(self, handle):
        """执行一次请求，返回 (code, status, body: bytes, raw_headers: bytes, error)。

        body/headers 按 C 层给出的真实长度读取，二进制安全。
        """
        status = ctypes.c_int(0)
        body = ctypes.c_char_p()
        body_len = ctypes.c_size_t(0)
        headers = ctypes.c_char_p()
        headers_len = ctypes.c_size_t(0)
        err = ctypes.c_char_p()

        code = self._easy_perform(
            handle, ctypes.byref(status),
            ctypes.byref(body), ctypes.byref(body_len),
            ctypes.byref(headers), ctypes.byref(headers_len),
            ctypes.byref(err))

        body_bytes = ctypes.string_at(body, body_len.value) if body.value is not None else b""
        head_bytes = ctypes.string_at(headers, headers_len.value) if headers.value is not None else b""
        error = err.value.decode("utf-8", "replace") if err.value else None

        if body.value is not None:
            self._easy_free_string(body)
        if headers.value is not None:
            self._easy_free_string(headers)
        if err.value is not None:
            self._easy_free_string(err)

        return code, status.value, body_bytes, head_bytes, error

    def get_cookies(self, handle) -> str:
        out = ctypes.c_char_p()
        if self._easy_get_cookies(handle, ctypes.byref(out)) != 0:
            return ""
        text = out.value.decode("utf-8", "replace") if out.value else ""
        if out.value is not None:
            self._easy_free_string(out)
        return text

    # -- getinfo ----------------------------------------------------------- #
    def getinfo_long(self, handle, info: int):
        out = ctypes.c_long(0)
        if self._easy_getinfo_long(handle, info, ctypes.byref(out)) != 0:
            return None
        return int(out.value)

    def getinfo_double(self, handle, info: int):
        out = ctypes.c_double(0.0)
        if self._easy_getinfo_double(handle, info, ctypes.byref(out)) != 0:
            return None
        return float(out.value)

    def getinfo_string(self, handle, info: int):
        out = ctypes.c_char_p()
        if self._easy_getinfo_string(handle, info, ctypes.byref(out)) != 0:
            return None
        return out.value.decode("utf-8", "replace") if out.value else None

    # -- multi / 结果移交 / poll（阶段 2 新增 ABI） ------------------------ #
    def multi_abi_version(self) -> int:
        return int(self._m_abi())

    def multi_init(self):
        return self._m_init()

    def multi_cleanup(self, multi) -> None:
        self._m_cleanup(multi)

    def multi_add(self, multi, handle) -> int:
        return int(self._m_add(multi, handle))

    def multi_remove(self, multi, handle) -> int:
        return int(self._m_remove(multi, handle))

    def multi_active(self, multi) -> int:
        return int(self._m_active(multi))

    def multi_perform(self, multi) -> int:
        return int(self._m_perform(multi))

    def multi_socket_action(self, multi, fd: int, ev_bitmask: int) -> int:
        return int(self._m_socket_action(multi, int(fd), int(ev_bitmask)))

    def multi_socket_snapshot(self, multi) -> list:
        """当前登记的 socket 表：``[(fd, action), ...]``（action 为 CURL_POLL_*）。"""
        total = ctypes.c_int(0)
        self._m_snapshot(multi, None, 0, ctypes.byref(total))
        n = int(total.value)
        if n <= 0:
            return []
        arr = (_NbSockInfo * n)()
        got = int(self._m_snapshot(multi, arr, n, ctypes.byref(total)))
        if got <= 0:
            return []
        return [(int(arr[i].fd), int(arr[i].action)) for i in range(min(got, n))]

    def multi_socket_changes(self, multi) -> list:
        """消费 socket 变更：``[(fd, action), ...]``，REMOVE 为 4。"""
        total = ctypes.c_int(0)
        rc = int(self._m_socket_changes(multi, None, 0, ctypes.byref(total)))
        if rc < 0:
            raise NativeError(rc, "multi_socket_changes failed")
        n = int(total.value)
        if n == 0:
            return []
        arr = (_NbSockInfo * n)()
        got = int(self._m_socket_changes(multi, arr, n, ctypes.byref(total)))
        if got < 0:
            raise NativeError(got, "multi_socket_changes failed")
        return [(int(arr[i].fd), int(arr[i].action)) for i in range(got)]

    def multi_timer(self, multi) -> int:
        out = ctypes.c_long(-1)
        if self._m_timer(multi, ctypes.byref(out)) != 0:
            return -1
        return int(out.value)

    def multi_fire_timer(self, multi) -> int:
        return int(self._m_fire_timer(multi))

    def multi_poll(self, multi, timeout_ms: int) -> int:
        out = ctypes.c_int(0)
        return int(self._m_poll(multi, int(timeout_ms), ctypes.byref(out)))

    def multi_wakeup(self, multi) -> int:
        return int(self._m_wakeup(multi))

    def multi_drain(self, multi):
        """取一条完成消息：``(msg, code, easy)``；队列空返回 ``None``。"""
        msg = ctypes.c_int(0)
        code = ctypes.c_int(0)
        easy = ctypes.c_void_p(None)
        if self._m_drain(multi, ctypes.byref(msg), ctypes.byref(code),
                         ctypes.byref(easy)) != 1:
            return None
        return int(msg.value), int(code.value), easy.value

    def prepare_request(self, handle) -> int:
        return int(self._easy_prepare_request(handle))

    def take_body(self, handle) -> bytes:
        return self._take_via(handle, self._easy_take_body)

    def take_headers(self, handle) -> bytes:
        return self._take_via(handle, self._easy_take_headers)

    def _take_via(self, handle, func) -> bytes:
        """所有权移交式取结果：读一次就 free，不做二次 C 复制。"""
        out = ctypes.c_void_p(None)
        length = ctypes.c_size_t(0)
        if func(handle, ctypes.byref(out), ctypes.byref(length)) != 0:
            return b""
        if not out.value:
            return b""
        n = int(length.value)
        data = ctypes.string_at(out.value, n) if n else b""
        self._easy_free_string(out)       # 转成 bytes 后立刻 free
        return data

    def pause(self, handle, bitmask: int) -> int:
        return int(self._easy_pause(handle, int(bitmask)))

    def poll_sockets(self, items, timeout_ms: int) -> list:
        """跨平台 poll：``items`` 是 ``[(fd, events)]``，返回 ``[(fd, revents)]``。

        - 无就绪条目（含等待超时、被信号打断）返回 ``[]``；
        - 真正的失败（参数错 / 系统调用错）**抛 :class:`NativeError`**，绝不
          伪装成"没有事件" —— 上层驱动必须能区分"没事件"和"poll 坏了"。
        """
        if not items:
            return []
        arr = (_NbPollItem * len(items))()
        for i, (fd, events) in enumerate(items):
            arr[i].fd = int(fd)
            arr[i].events = int(events)
            arr[i].revents = 0
        ready = int(self._poll_sockets_raw(arr, len(items), int(timeout_ms)))
        if ready == -3:                   # EINTR：不是错误，按"没有事件"重试
            return []
        if ready < 0:
            raise NativeError(ready, "nb_poll_sockets 调用失败")
        if ready == 0:
            return []
        return [(int(arr[i].fd), int(arr[i].revents))
                for i in range(len(items)) if arr[i].revents]

    # -- 杂项 -------------------------------------------------------------- #
    def strerror(self, code: int) -> str:
        msg = self._easy_strerror(code)
        return msg.decode("utf-8", "replace") if msg else "unknown error"

    def version(self) -> str:
        v = self._easy_version()
        return v.decode("utf-8", "replace") if v else ""

    # -- 流式下载（stream=True） ------------------------------------------- #
    #: size_t(char *, size_t, size_t, void *)
    _STREAM_CB = ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.c_size_t, ctypes.c_void_p)

    def install_stream_callbacks(self, handle, on_chunk, on_header):
        """把响应体/响应头的回调换成 Python 函数（与 CFFI 后端同一套语义）。

        :param on_chunk: ``f(data: bytes) -> bool | int``：

            * ``True``  —— 这一块已被消费，回 ``size*nmemb``；
            * ``False`` —— 写回调真失败（CURLE_WRITE_ERROR），回 0；
            * 其它 ``int`` —— **原样**回给 libcurl，用于背压
              （``CURL_WRITEFUNC_PAUSE`` = 0x10000001）以及前向兼容
              ``CURL_WRITEFUNC_ERROR``。回 PAUSE 的前提是这一块**没有被入队**，
              否则 libcurl 恢复后会重投递同一块，正文会重复。
        :param on_header: ``f(line: bytes) -> bool``
        :returns: 需要**保活到 perform 结束**的对象
        """

        def _write(ptr, size, nmemb, _ud):
            n = size * nmemb
            if not n:
                return 0
            # 用 string_at 而不是 c_char_p：响应体可能是二进制，含 \0 不能被截断
            result = on_chunk(ctypes.string_at(ptr, n))
            if result is True:
                return n
            if isinstance(result, int):
                return result          # False -> 0；PAUSE/ERROR 等原样透传
            return 0

        def _header(ptr, size, nmemb, _ud):
            n = size * nmemb
            if not n:
                return 0
            return n if on_header(ctypes.string_at(ptr, n)) else 0

        write_cb = self._STREAM_CB(_write)
        head_cb = self._STREAM_CB(_header)
        self._curl_easy_setopt(handle, CurlOpt.WRITEFUNCTION,
                               ctypes.cast(write_cb, ctypes.c_void_p))
        self._curl_easy_setopt(handle, CurlOpt.HEADERFUNCTION,
                               ctypes.cast(head_cb, ctypes.c_void_p))
        return (write_cb, head_cb)

    # -- 通用 setopt 直传 ----------------------------------------------- #
    def set_option_long(self, handle, option: int, value: int) -> int:
        return self.easy_set_option_long(handle, option, int(value))

    def set_option_string(self, handle, option: int, value) -> int:
        if value is None:
            return self.easy_set_option_string(handle, option, None)
        if isinstance(value, str):
            value = value.encode("utf-8")
        return self.easy_set_option_string(handle, option, value)

    def set_option_slist(self, handle, option: int, entries: list[bytes]) -> int:
        array = (ctypes.c_char_p * (len(entries) or 1))()
        for i, entry in enumerate(entries):
            array[i] = entry
        return self._easy_set_option_slist(handle, option, array, len(entries))

    def set_option_off(self, handle, option: int, value: int) -> int:
        return self.easy_set_option_off(handle, option, int(value))

    # -- WebSocket ----------------------------------------------------- #
    def ws_send(self, handle, buf: bytes, flags: int) -> int:
        return self._easy_ws_send(handle, buf, len(buf), flags)

    def ws_recv(self, handle, cap: int) -> tuple[int, bytes, int, int, int]:
        buf = (ctypes.c_char * cap)()
        nread = ctypes.c_int(0)
        oflags = ctypes.c_int(0)
        off = ctypes.c_longlong(0)
        left = ctypes.c_longlong(0)
        code = self._easy_ws_recv(
            handle, buf, cap,
            ctypes.byref(nread), ctypes.byref(oflags),
            ctypes.byref(off), ctypes.byref(left))
        data = ctypes.string_at(buf, nread.value) if nread.value > 0 else b""
        return int(code), data, int(oflags.value), int(off.value), int(left.value)

