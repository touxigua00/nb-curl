"""nb_curl._backend_ctypes —— ctypes 后端（兜底实现）

在没编译 CFFI API 模式扩展的环境下使用。只依赖标准库，
加载 ``nb_curl_native.dll`` 并声明稳定 C ABI。

对外暴露的接口与 :mod:`nb_curl._backend_cffi` 完全一致，
由 :mod:`nb_curl._native` 在运行期二选一。
"""

from __future__ import annotations

import ctypes
import os

__all__ = ["CtypesBackend", "NativeError"]

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
    ]


# struct 字段 -> 类型（'s' 字符串 / 'i' int）
_FP_FIELDS: tuple[tuple[str, str], ...] = tuple(
    (name, "s" if field is ctypes.c_char_p else "i")
    for name, field in _NbFingerprint._fields_
    if name != "struct_size"
)

_c_char_p_p = ctypes.POINTER(ctypes.c_char_p)


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

        self._easy_perform = sig(
            "easy_perform", c_int,
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

        # 初始化前先校验 ABI 布局，避免结构体错位导致的静默错误
        expect = self.nb_fingerprint_size()
        actual = ctypes.sizeof(_NbFingerprint)
        if expect != actual:
            raise ImportError(
                "nb_curl native ABI 不匹配：C 端 nb_fingerprint=%d 字节，"
                "Python 端=%d 字节。请重新安装与本机平台匹配的 nb-curl。" % (expect, actual))

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

    # -- 杂项 -------------------------------------------------------------- #
    def strerror(self, code: int) -> str:
        msg = self._easy_strerror(code)
        return msg.decode("utf-8", "replace") if msg else "unknown error"

    def version(self) -> str:
        v = self._easy_version()
        return v.decode("utf-8", "replace") if v else ""
