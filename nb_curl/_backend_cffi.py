"""nb_curl._backend_cffi —— CFFI API 模式后端（首选实现）

CFFI API 模式在**编译期**把 Python 调用直接绑定到 C 函数（生成的是真实 C 调用，
不是 libffi 的通用 trampoline），因此：

* 单次跨界调用无 libffi 解释开销（实测比 ctypes 快约 1.2x）；
* 结构体布局由编译器用真实头文件校验，ABI 不匹配在**编译期**就报错；
* 不需要手写 argtypes/restype。

注意：HTTP 请求的耗时几乎全在网络/TLS，"FFI 快 1.2x" 对端到端时延的影响 <0.1%。
选它的主要理由是类型安全与代码整洁，不是吞吐。

扩展产物：``nb_curl/_nb_curl_cffi*.pyd``
"""

from __future__ import annotations

import os

__all__ = ["CffiBackend", "NativeError", "cffi_available"]


class NativeError(RuntimeError):
    """native 调用返回了错误码。"""

    def __init__(self, code: int, message: str):
        super().__init__("nb_curl native error %d: %s" % (code, message))
        self.code = code
        self.message = message


def _import_module():
    """导入已编译的 CFFI 扩展，并把 native DLL 目录加入 DLL 搜索路径。"""
    from . import _backend_ctypes as _ct

    here = os.path.dirname(os.path.abspath(__file__))
    dll_dir = os.path.join(here, "_lib")
    # Python 3.8+ 加载扩展时会搜 .pyd 所在目录，这里再显式加一遍，稳一点
    added = None
    if os.name == "nt" and hasattr(os, "add_dll_directory") and os.path.isdir(dll_dir):
        try:
            added = os.add_dll_directory(dll_dir)
        except OSError:
            added = None

    try:
        from . import _nb_curl_cffi  # type: ignore
    except ImportError:
        # 兜底：若扩展在 build/ 下，也尝试从那里加载
        import glob
        import importlib.util

        build_root = os.path.join(os.path.dirname(here), "build")
        cands: list[str] = []
        for ext in ("pyd", "so", "dylib"):
            cands += glob.glob(
                os.path.join(build_root, "**", "_nb_curl_cffi*.%s" % ext), recursive=True)
        if not cands:
            if added is not None:
                added.close()
            raise
        spec = importlib.util.spec_from_file_location("nb_curl._nb_curl_cffi", cands[0])
        module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        assert spec and spec.loader
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        return module, added, _ct

    return _nb_curl_cffi, added, _ct


def cffi_available() -> bool:
    try:
        _import_module()
        return True
    except Exception:  # noqa: BLE001
        return False


# struct 字段 -> 类型（'s' 字符串 / 'i' int），与 ctypes 后端保持同一份顺序约定
_FP_FIELDS: tuple[tuple[str, str], ...] = (
    ("ciphers", "s"), ("tls13_ciphers", "s"), ("curves", "s"), ("sig_hash_algs", "s"),
    ("extension_order", "s"), ("cert_compression", "s"),
    ("ssl_version", "i"), ("tls_grease", "i"), ("tls_grease_sigalgs", "i"),
    ("permute_extensions", "i"),
    ("signed_cert_timestamps", "i"), ("status_request", "i"), ("enable_alps", "i"),
    ("use_new_alps_codepoint", "i"), ("record_size_limit", "i"), ("key_shares_limit", "i"),
    ("delegated_credentials", "s"), ("trust_anchors", "s"),
    ("http2_settings", "s"), ("http2_window_update", "i"),
    ("http2_pseudo_headers_order", "s"), ("http2_streams", "s"),
    ("http2_no_priority", "i"), ("stream_weight", "i"), ("stream_exclusive", "i"),
    ("header_order", "s"), ("split_cookies", "i"),
)


class CffiBackend:
    """用 CFFI API 模式扩展直接驱动 nb_curl_native.dll。"""

    name = "cffi"

    def __init__(self):
        module, added, _ct = _import_module()
        self._module = module
        self._ffi = module.ffi
        self._c = module.lib
        self._dll_handle = added
        self._ctypes_fallback = _ct
        self.path = _ct.load_dll_path()

        # 编译期已保证布局一致，这里再跑一次运行期自检，防止手改过 .py 的情况
        expect = self._c.nb_fingerprint_size()
        actual = self._ffi.sizeof("nb_fingerprint")
        if expect != actual:
            raise ImportError(
                "nb_curl CFFI ABI 不匹配：C 端 nb_fingerprint=%d 字节，"
                "CFFI 端=%d 字节。请重新安装与本机 Python 匹配的 nb-curl。" % (expect, actual))

        self._c.nb_global_init()

    # -- 句柄 -------------------------------------------------------------- #
    def easy_init(self):
        return self._c.easy_init()

    def easy_cleanup(self, handle):
        self._c.easy_cleanup(handle)

    def easy_reset(self, handle):
        self._c.easy_reset(handle)

    # -- 指纹 -------------------------------------------------------------- #
    def easy_set_impersonate(self, handle, target: bytes, default_headers: int) -> int:
        return self._c.easy_set_impersonate(handle, target, default_headers)

    def easy_impersonate_exists(self, target: bytes) -> int:
        return self._c.easy_impersonate_exists(target)

    def apply_fingerprint(self, handle, values: dict) -> int:
        ffi = self._ffi
        st = ffi.new("nb_fingerprint *")
        keep: list = [st]
        for field_name, kind in _FP_FIELDS:
            value = values.get(field_name)
            if kind == "s":
                if value is None:
                    setattr(st, field_name, ffi.NULL)
                else:
                    cstr = ffi.new("char[]", str(value).encode("utf-8"))
                    keep.append(cstr)
                    setattr(st, field_name, cstr)
            else:
                if value is None:
                    setattr(st, field_name, -1)
                elif isinstance(value, bool):
                    setattr(st, field_name, 1 if value else 0)
                else:
                    setattr(st, field_name, int(value))
        code = self._c.easy_apply_fingerprint(handle, st)
        _ = keep  # 保活：直到调用返回才允许释放
        return code

    def nb_fingerprint_size(self) -> int:
        return self._c.nb_fingerprint_size()

    # -- 逐项设置 ---------------------------------------------------------- #
    def easy_set_url(self, handle, url: bytes) -> int:
        return self._c.easy_set_url(handle, url)

    def easy_set_method(self, handle, method: bytes) -> int:
        return self._c.easy_set_method(handle, method)

    def easy_set_headers(self, handle, headers: bytes) -> int:
        return self._c.easy_set_headers(handle, headers)

    def easy_set_header_lines(self, handle, lines: list[bytes]) -> int:
        ffi = self._ffi
        if not lines:
            return self._c.easy_set_header_lines(handle, ffi.NULL, 0)
        # CFFI 的 char*[] 元素必须是 cdata，不能直接塞 bytes；
        # cstrings 会被 array 持有引用，两者一起保活到调用返回。
        cstrings = [ffi.new("char[]", line) for line in lines]
        array = ffi.new("char *[]", cstrings)
        code = self._c.easy_set_header_lines(handle, array, len(lines))
        _ = (array, cstrings)  # 保活
        return code

    def easy_set_cookies(self, handle, cookies) -> int:
        return self._c.easy_set_cookies(handle, cookies if cookies is not None else self._ffi.NULL)

    def easy_set_cookie_engine(self, handle, enable: int) -> int:
        return self._c.easy_set_cookie_engine(handle, enable)

    def easy_set_cookie_list(self, handle, cookie) -> int:
        return self._c.easy_set_cookie_list(handle, cookie if cookie is not None else self._ffi.NULL)

    def easy_set_body(self, handle, body, length: int) -> int:
        return self._c.easy_set_body(handle, body if body is not None else self._ffi.NULL, length)

    def easy_set_timeout(self, handle, ms: int) -> int:
        return self._c.easy_set_timeout(handle, ms)

    def easy_set_connect_timeout(self, handle, ms: int) -> int:
        return self._c.easy_set_connect_timeout(handle, ms)

    def easy_set_verify(self, handle, verify: int, ca_path) -> int:
        return self._c.easy_set_verify(
            handle, verify, ca_path if ca_path is not None else self._ffi.NULL)

    def easy_set_http_version(self, handle, version: int) -> int:
        return self._c.easy_set_http_version(handle, version)

    def easy_set_proxy(self, handle, proxy) -> int:
        return self._c.easy_set_proxy(handle, proxy if proxy is not None else self._ffi.NULL)

    def easy_set_userpwd(self, handle, userpwd: bytes) -> int:
        return self._c.easy_set_userpwd(handle, userpwd)

    def easy_set_redirect(self, handle, follow: int, max_redirs: int) -> int:
        return self._c.easy_set_redirect(handle, follow, max_redirs)

    def easy_set_verbose(self, handle, on: int) -> int:
        return self._c.easy_set_verbose(handle, on)

    def easy_set_fresh_connect(self, handle, on: int) -> int:
        return self._c.easy_set_fresh_connect(handle, on)

    def _curl_easy_setopt(self, handle, option: int, param) -> int:
        return self._c._curl_easy_setopt(handle, option, param)

    # -- 执行 -------------------------------------------------------------- #
    def perform(self, handle):
        """执行一次请求，返回 (code, status, body: bytes, raw_headers: bytes, error)。"""
        ffi = self._ffi
        c = self._c
        status = ffi.new("int *")
        body = ffi.new("char **")
        body_len = ffi.new("size_t *")
        headers = ffi.new("char **")
        headers_len = ffi.new("size_t *")
        err = ffi.new("char **")

        code = c.easy_perform(handle, status, body, body_len, headers, headers_len, err)

        body_ptr = body[0]
        head_ptr = headers[0]
        err_ptr = err[0]
        body_bytes = ffi.buffer(body_ptr, body_len[0])[:] if body_ptr != ffi.NULL else b""
        head_bytes = ffi.buffer(head_ptr, headers_len[0])[:] if head_ptr != ffi.NULL else b""
        error = ffi.string(err_ptr).decode("utf-8", "replace") if err_ptr != ffi.NULL else None

        if body_ptr != ffi.NULL:
            c.easy_free_string(body_ptr)
        if head_ptr != ffi.NULL:
            c.easy_free_string(head_ptr)
        if err_ptr != ffi.NULL:
            c.easy_free_string(err_ptr)

        return code, int(status[0]), body_bytes, head_bytes, error

    def get_cookies(self, handle) -> str:
        ffi = self._ffi
        out = ffi.new("char **")
        if self._c.easy_get_cookies(handle, out) != 0:
            return ""
        ptr = out[0]
        if ptr == ffi.NULL:
            return ""
        text = ffi.string(ptr).decode("utf-8", "replace")
        self._c.easy_free_string(ptr)
        return text

    # -- getinfo ----------------------------------------------------------- #
    def getinfo_long(self, handle, info: int):
        ffi = self._ffi
        out = ffi.new("long *")
        if self._c.easy_getinfo_long(handle, info, out) != 0:
            return None
        return int(out[0])

    def getinfo_double(self, handle, info: int):
        ffi = self._ffi
        out = ffi.new("double *")
        if self._c.easy_getinfo_double(handle, info, out) != 0:
            return None
        return float(out[0])

    def getinfo_string(self, handle, info: int):
        ffi = self._ffi
        out = ffi.new("const char **")
        if self._c.easy_getinfo_string(handle, info, out) != 0:
            return None
        ptr = out[0]
        if ptr == ffi.NULL:
            return None
        return ffi.string(ptr).decode("utf-8", "replace")

    # -- 杂项 -------------------------------------------------------------- #
    def strerror(self, code: int) -> str:
        msg = self._c.easy_strerror(code)
        return self._ffi.string(msg).decode("utf-8", "replace") if msg else "unknown error"

    def version(self) -> str:
        v = self._c.easy_version()
        return self._ffi.string(v).decode("utf-8", "replace") if v else ""
