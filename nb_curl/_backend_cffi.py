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

from ._curlopt_generated import CurlOpt

__all__ = ["CffiBackend", "NativeError", "cffi_available", "MULTI_ABI_VERSION"]

#: 桥接层 multi ABI 版本（对应 native/nb_curl_bridge.h 的 nb_multi_abi_version()）。
#: 版本不一致 = Python 与 DLL 不配套，**直接报错**，不静默降级。
MULTI_ABI_VERSION = 3


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
    ("http2_headers_priority", "i"),
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

        # 阶段 2：multi ABI 必须存在且版本一致（不静默降级到旧 DLL）
        ver = self._c.nb_multi_abi_version()
        if ver != MULTI_ABI_VERSION:
            raise ImportError(
                "nb_curl native 库的 multi ABI 版本为 %r，期望 %d。"
                "请用 build/ 下的新脚本重新构建 native/nb_curl_bridge.c。"
                % (ver, MULTI_ABI_VERSION))
        for struct_name, want in (("nb_sock_info", 16), ("nb_poll_item", 16)):
            got = self._ffi.sizeof(struct_name)
            if got != want:
                raise ImportError(
                    "nb_curl CFFI ABI 不匹配：%s=%d 字节，期望 %d 字节。"
                    % (struct_name, got, want))

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

    def easy_set_resolve(self, handle, entries: list[bytes]) -> int:
        ffi = self._ffi
        if not entries:
            return self._c.easy_set_resolve(handle, ffi.NULL, 0)
        cstrings = [ffi.new("char[]", entry) for entry in entries]
        array = ffi.new("char *[]", cstrings)
        code = self._c.easy_set_resolve(handle, array, len(entries))
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

    def easy_set_userpwd(self, handle, userpwd) -> int:
        # userpwd=None 是"显式取消认证"（句柄复用时否则会残留上一次的 auth）
        return self._c.easy_set_userpwd(
            handle, userpwd if userpwd is not None else self._ffi.NULL)

    def easy_set_redirect(self, handle, follow: int, max_redirs: int) -> int:
        return self._c.easy_set_redirect(handle, follow, max_redirs)

    def easy_set_verbose(self, handle, on: int) -> int:
        return self._c.easy_set_verbose(handle, on)

    def easy_set_fresh_connect(self, handle, on: int) -> int:
        return self._c.easy_set_fresh_connect(handle, on)

    # -- TCP 层画像（JA4T） ---------------------------------------------- #
    _TCP_FIELDS = ("ttl", "mss", "window", "wscale", "rcvbuf", "timestamp")

    def easy_set_tcp_shape(self, handle, *, ttl=None, mss=None, window=None,
                           wscale=None, rcvbuf=None, timestamp=None) -> int:
        """下发 socket 级 TCP 画像；六个字段全不给 = 取消画像。

        缺省项写 -1（C 端约定：-1 = 不设置、跟随本机）。``window`` / ``wscale``
        只用于回读比对，真正下发的是折算好的 ``rcvbuf``。
        """
        values = (ttl, mss, window, wscale, rcvbuf, timestamp)
        if all(v is None for v in values):
            return self._c.easy_set_tcp_shape(handle, self._ffi.NULL)
        st = self._ffi.new("nb_tcp_shape *")
        for name, value in zip(self._TCP_FIELDS, values):
            setattr(st, name, -1 if value is None else int(value))
        return self._c.easy_set_tcp_shape(handle, st)

    def easy_get_tcp_shape_error(self, handle):
        """perform 期间 socket 层设置失败的原因；没失败返回 ``None``。"""
        ptr = self._c.easy_get_tcp_shape_error(handle)
        if ptr == self._ffi.NULL:
            return None
        return self._ffi.string(ptr).decode("utf-8", "replace")

    def easy_check_tcp_shape(self, handle):
        """连接期间回读到的 socket 快照（dict）；没建新连接 / 读不到返回 ``None``。"""
        out = self._ffi.new("nb_tcp_shape_actual *")
        if self._c.easy_check_tcp_shape(handle, out) != 0:
            return None
        return {name: int(getattr(out, name)) for name in self._TCP_FIELDS}

    def _curl_easy_setopt(self, handle, option: int, param) -> int:
        return self._c._curl_easy_setopt(handle, option, param)

    # -- 流式下载（stream=True） ------------------------------------------- #
    def install_stream_callbacks(self, handle, on_chunk, on_header):
        """把响应体/响应头的回调换成 Python 函数。

        :param on_chunk: ``f(data: bytes) -> bool | int``：

            * ``True``  —— 这一块已被消费，回 ``size*nmemb``；
            * ``False`` —— 写回调真失败（CURLE_WRITE_ERROR），回 0；
            * 其它 ``int`` —— **原样**回给 libcurl，用于背压
              （``CURL_WRITEFUNC_PAUSE`` = 0x10000001）以及前向兼容
              ``CURL_WRITEFUNC_ERROR``。回 PAUSE 的前提是这一块**没有被入队**，
              否则 libcurl 恢复后会重投递同一块，正文会重复。
        :param on_header: ``f(line: bytes) -> bool`` —— 收到一行响应头（状态行也算）
        :returns: 需要**保活到 perform 结束**的对象（CFFI 的闭包被 free 掉就会崩）

        用 ``_curl_easy_setopt`` 直接设 ``CURLOPT_WRITEFUNCTION`` / ``HEADERFUNCTION``：
        C 层已装好的默认回调会被顶掉，所以这两个回调在传输期间完全由 Python 接管
        —— 数据不再经过 C 层缓冲，每来一块就当场交给调用方。
        """
        ffi = self._ffi

        def _write(ptr, size, nmemb, _ud):
            n = size * nmemb
            if not n:
                return 0
            result = on_chunk(ffi.buffer(ptr, n)[:])
            if result is True:
                return n
            if isinstance(result, int):
                return result          # False -> 0；PAUSE/ERROR 等原样透传
            return 0

        def _header(ptr, size, nmemb, _ud):
            n = size * nmemb
            if not n:
                return 0
            return n if on_header(ffi.buffer(ptr, n)[:]) else 0

        write_cb = ffi.callback("size_t(char *, size_t, size_t, void *)")(_write)
        head_cb = ffi.callback("size_t(char *, size_t, size_t, void *)")(_header)
        self._curl_easy_setopt(handle, CurlOpt.WRITEFUNCTION, ffi.cast("void *", write_cb))
        self._curl_easy_setopt(handle, CurlOpt.HEADERFUNCTION, ffi.cast("void *", head_cb))
        return (write_cb, head_cb)

    # -- 通用 setopt 直传 ----------------------------------------------- #
    def set_option_long(self, handle, option: int, value: int) -> int:
        return self._c.easy_set_option_long(handle, option, int(value))

    def set_option_string(self, handle, option: int, value) -> int:
        return self._c.easy_set_option_string(
            handle, option, value if value is not None else self._ffi.NULL)

    def set_option_slist(self, handle, option: int, entries: list[bytes]) -> int:
        ffi = self._ffi
        if not entries:
            return self._c.easy_set_option_slist(handle, option, ffi.NULL, 0)
        cstrings = [ffi.new("char[]", entry) for entry in entries]
        array = ffi.new("char *[]", cstrings)
        code = self._c.easy_set_option_slist(handle, option, array, len(entries))
        _ = (array, cstrings)
        return code

    def set_option_off(self, handle, option: int, value: int) -> int:
        return self._c.easy_set_option_off(handle, option, int(value))

    # -- WebSocket ----------------------------------------------------- #
    def ws_send(self, handle, buf: bytes, flags: int) -> int:
        return self._c.easy_ws_send(handle, buf, len(buf), flags)

    def ws_recv(self, handle, cap: int) -> tuple[int, bytes, int, int, int]:
        """返回 (code, data, flags, offset, bytesleft)。code=81(CURLE_AGAIN) 表示无数据。"""
        ffi = self._ffi
        buf = ffi.new("char[]", cap)
        nread = ffi.new("int *")
        oflags = ffi.new("int *")
        off = ffi.new("long long *")
        left = ffi.new("long long *")
        code = self._c.easy_ws_recv(handle, buf, cap, nread, oflags, off, left)
        data = ffi.buffer(buf, nread[0])[:] if nread[0] > 0 else b""
        return int(code), data, int(oflags[0]), int(off[0]), int(left[0])

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

        # easy_perform_take：正文缓冲**所有权移交**，C 层不再整块复制一份，
        # Python 侧只做一次 ffi.buffer(...)[:]（旧路径是 C 复制 + Python 复制共两次）
        code = c.easy_perform_take(handle, status, body, body_len,
                                   headers, headers_len, err)

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

    # -- multi / 结果移交 / poll（阶段 2 新增 ABI） ------------------------ #
    def multi_abi_version(self) -> int:
        return int(self._c.nb_multi_abi_version())

    def multi_init(self):
        return self._c.nb_multi_init()

    def multi_cleanup(self, multi) -> None:
        self._c.nb_multi_cleanup(multi)

    def multi_add(self, multi, handle) -> int:
        return int(self._c.nb_multi_add(multi, handle))

    def multi_remove(self, multi, handle) -> int:
        return int(self._c.nb_multi_remove(multi, handle))

    def multi_active(self, multi) -> int:
        return int(self._c.nb_multi_active(multi))

    def multi_perform(self, multi) -> int:
        return int(self._c.nb_multi_perform(multi))

    def multi_socket_action(self, multi, fd: int, ev_bitmask: int) -> int:
        return int(self._c.nb_multi_socket_action(multi, int(fd), int(ev_bitmask)))

    def multi_socket_snapshot(self, multi) -> list:
        """当前登记的 socket 表：``[(fd, action), ...]``（action 为 CURL_POLL_*）。"""
        ffi = self._ffi
        total = ffi.new("int *")
        self._c.nb_multi_socket_snapshot(multi, ffi.NULL, 0, total)
        n = int(total[0])
        if n <= 0:
            return []
        arr = ffi.new("nb_sock_info[]", n)
        got = int(self._c.nb_multi_socket_snapshot(multi, arr, n, total))
        if got <= 0:
            return []
        return [(int(arr[i].fd), int(arr[i].action)) for i in range(got)]

    def multi_socket_changes(self, multi) -> list:
        """消费 socket 变更：``[(fd, action), ...]``，REMOVE 为 4。"""
        ffi = self._ffi
        total = ffi.new("int *")
        rc = int(self._c.nb_multi_socket_changes(multi, ffi.NULL, 0, total))
        if rc < 0:
            raise NativeError(rc, "multi_socket_changes failed")
        n = int(total[0])
        if n == 0:
            return []
        arr = ffi.new("nb_sock_info[]", n)
        got = int(self._c.nb_multi_socket_changes(multi, arr, n, total))
        if got < 0:
            raise NativeError(got, "multi_socket_changes failed")
        return [(int(arr[i].fd), int(arr[i].action)) for i in range(got)]

    def multi_timer(self, multi) -> int:
        out = self._ffi.new("long *")
        if self._c.nb_multi_timer(multi, out) != 0:
            return -1
        return int(out[0])

    def multi_fire_timer(self, multi) -> int:
        return int(self._c.nb_multi_fire_timer(multi))

    def multi_poll(self, multi, timeout_ms: int) -> int:
        out = self._ffi.new("int *")
        return int(self._c.nb_multi_poll(multi, int(timeout_ms), out))

    def multi_wakeup(self, multi) -> int:
        return int(self._c.nb_multi_wakeup(multi))

    def multi_drain(self, multi):
        """取一条完成消息：``(msg, code, easy)``；队列空返回 ``None``。"""
        ffi = self._ffi
        msg = ffi.new("int *")
        code = ffi.new("int *")
        easy = ffi.new("void **")
        if self._c.nb_multi_drain(multi, msg, code, easy) != 1:
            return None
        return int(msg[0]), int(code[0]), easy[0]

    def prepare_request(self, handle) -> int:
        return int(self._c.easy_prepare_request(handle))

    def take_body(self, handle) -> bytes:
        return self._take(handle, self._c.easy_take_body)

    def take_headers(self, handle) -> bytes:
        return self._take(handle, self._c.easy_take_headers)

    def _take(self, handle, func) -> bytes:
        """所有权移交式取结果：读一次就 free，不做二次 C 复制。"""
        ffi = self._ffi
        out = ffi.new("char **")
        length = ffi.new("size_t *")
        if func(handle, out, length) != 0:
            return b""
        ptr = out[0]
        if ptr == ffi.NULL:
            return b""
        n = int(length[0])
        data = ffi.buffer(ptr, n)[:] if n else b""
        self._c.easy_free_string(ptr)     # 转成 bytes 后立刻 free
        return data

    def pause(self, handle, bitmask: int) -> int:
        return int(self._c.easy_pause(handle, int(bitmask)))

    def poll_sockets(self, items, timeout_ms: int) -> list:
        """跨平台 poll：``items`` 是 ``[(fd, events)]``，返回 ``[(fd, revents)]``。

        - 无就绪条目（含等待超时、被信号打断）返回 ``[]``；
        - 真正的失败（参数错 / 系统调用错）**抛 :class:`NativeError`**，绝不
          伪装成"没有事件" —— 上层驱动必须能区分"没事件"和"poll 坏了"。
        """
        ffi = self._ffi
        if not items:
            return []
        arr = ffi.new("nb_poll_item[]", len(items))
        for i, (fd, events) in enumerate(items):
            arr[i].fd = int(fd)
            arr[i].events = int(events)
            arr[i].revents = 0
        ready = int(self._c.nb_poll_sockets(arr, len(items), int(timeout_ms)))
        if ready == -3:                   # EINTR：不是错误，按"没有事件"重试
            return []
        if ready < 0:
            raise NativeError(ready, "nb_poll_sockets 调用失败")
        if ready == 0:
            return []
        out = []
        for i in range(len(items)):
            revents = int(arr[i].revents)
            if revents:
                out.append((int(arr[i].fd), revents))
        return out

    # -- 杂项 -------------------------------------------------------------- #
    def strerror(self, code: int) -> str:
        msg = self._c.easy_strerror(code)
        return self._ffi.string(msg).decode("utf-8", "replace") if msg else "unknown error"

    def version(self) -> str:
        v = self._c.easy_version()
        return self._ffi.string(v).decode("utf-8", "replace") if v else ""
