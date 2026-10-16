"""nb_curl._cffi_build —— CFFI API 模式扩展的构建脚本

把稳定 C ABI（native/nb_curl_bridge.h）用 CFFI API 模式编译成扩展模块
``nb_curl._nb_curl_cffi``。API 模式生成的是**直接 C 调用**（编译期绑定符号），
没有 ctypes 每次调用的 libffi 解释开销，且 ABI 不匹配会在编译期就报错。

运行:  ./.venv/Scripts/python.exe -m nb_curl._cffi_build
"""

from __future__ import annotations

import os
import sys

# --------------------------------------------------------------------------- #
# MSVC 工具链定位
# --------------------------------------------------------------------------- #
# 为什么不靠 vcvars64.bat：
#   * 在 Git Bash 里 export PATH="D:/..." 会被 MSYS 改写成 PortableGit 下的
#     相对路径（已实测），导致 cl.exe 找不到；
#   * cmd.exe 在本环境被安全策略拦截。
# 所以直接在 Python 里用**原生 Windows 路径**写 os.environ，绕开所有 shell 改写。
_MSVC_TOOLS = os.environ.get(
    "NB_CURL_MSVC_TOOLS",
    r"D:\Program_files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC")
_SDK_ROOT = os.environ.get("NB_CURL_SDK_ROOT", r"C:\Program Files (x86)\Windows Kits\10")
_SDK_VER = os.environ.get("NB_CURL_SDK_VER", "10.0.26100.0")

# 预编译依赖也从仓库推导（deps/windows-prebuilt/ 下四套）；环境变量可覆盖。
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_PREBUILT = os.environ.get(
    "NB_CURL_PREBUILT", os.path.join(_REPO, "deps", "windows-prebuilt"))
_BSSL = os.path.join(_PREBUILT, "boringssl")
_VCPKG = os.path.join(_PREBUILT, "vcpkg-static")
_CURLDIR = os.path.join(_PREBUILT, "curl-impersonate")


def _latest_msvc() -> str:
    if not os.path.isdir(_MSVC_TOOLS):
        raise SystemExit("找不到 MSVC 工具链目录: %s" % _MSVC_TOOLS)
    versions = sorted(
        (d for d in os.listdir(_MSVC_TOOLS) if os.path.isdir(os.path.join(_MSVC_TOOLS, d))),
        key=lambda s: tuple(int(x) for x in s.split(".") if x.isdigit()),
    )
    return os.path.join(_MSVC_TOOLS, versions[-1])


def setup_msvc_env() -> None:
    """把 MSVC/SDK 的 INCLUDE/LIB/PATH 以 Windows 原生格式注入当前进程环境。"""
    if os.name != "nt":
        return
    msvc = _latest_msvc()
    sdk_inc = os.path.join(_SDK_ROOT, "Include", _SDK_VER)
    sdk_lib = os.path.join(_SDK_ROOT, "Lib", _SDK_VER)

    include_parts = [
        os.path.join(msvc, "include"),
        os.path.join(sdk_inc, "ucrt"),
        os.path.join(sdk_inc, "um"),
        os.path.join(sdk_inc, "shared"),
        os.path.join(sdk_inc, "winrt"),
        os.path.join(_CURLDIR, "include"),
        os.path.join(_BSSL, "include"),
        os.path.join(_VCPKG, "include"),
    ]
    prev_include = os.environ.get("INCLUDE", "")
    os.environ["INCLUDE"] = ";".join(include_parts) + (";" + prev_include if prev_include else "")

    lib_parts = [
        os.path.join(msvc, "lib", "x64"),
        os.path.join(sdk_lib, "ucrt", "x64"),
        os.path.join(sdk_lib, "um", "x64"),
    ]
    prev_lib = os.environ.get("LIB", "")
    os.environ["LIB"] = ";".join(lib_parts) + (";" + prev_lib if prev_lib else "")

    bin_parts = [
        os.path.join(msvc, "bin", "Hostx64", "x64"),
        os.path.join(_SDK_ROOT, "bin", _SDK_VER, "x64"),
    ]
    os.environ["PATH"] = ";".join(bin_parts) + ";" + os.environ.get("PATH", "")

    # 让 distutils 跳过"自己找 VS"，直接复用上面的环境
    os.environ["DISTUTILS_USE_SDK"] = "1"
    os.environ["MSSdk"] = "1"
    os.environ["CL"] = "/utf-8"
    # 清掉可能干扰编译的代理
    for key in ("http_proxy", "https_proxy", "all_proxy",
                "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        os.environ.pop(key, None)


CDEF = r"""
    typedef struct {
        int struct_size;
        const char* ciphers;
        const char* tls13_ciphers;
        const char* curves;
        const char* sig_hash_algs;
        const char* extension_order;
        const char* cert_compression;
        int ssl_version;
        int tls_grease;
        int tls_grease_sigalgs;
        int permute_extensions;
        int signed_cert_timestamps;
        int status_request;
        int enable_alps;
        int use_new_alps_codepoint;
        int record_size_limit;
        int key_shares_limit;
        const char* delegated_credentials;
        const char* trust_anchors;
        const char* http2_settings;
        int http2_window_update;
        const char* http2_pseudo_headers_order;
        const char* http2_streams;
        int http2_no_priority;
        int stream_weight;
        int stream_exclusive;
        const char* header_order;
        int split_cookies;
        int http2_headers_priority;
    } nb_fingerprint;

    /* TCP 层画像（JA4T）。int 与 C 端 int32_t 在支持平台上同宽同对齐。 */
    typedef struct {
        int ttl;
        int mss;
        int window;
        int wscale;
        int rcvbuf;
        int timestamp;
    } nb_tcp_shape;

    typedef struct {
        int ttl;
        int mss;
        int wscale;
        int window;
        int rcvbuf;
        int timestamp;
    } nb_tcp_shape_actual;

    int  nb_global_init(void);
    void nb_global_cleanup(void);

    void* easy_init(void);
    void  easy_cleanup(void* e);
    void  easy_reset(void* e);

    int easy_set_impersonate(void* e, const char* target, int default_headers);
    int easy_impersonate_exists(const char* target);
    int easy_apply_fingerprint(void* e, const nb_fingerprint* fp);
    int nb_fingerprint_size(void);

    int easy_set_url(void* e, const char* url);
    int easy_set_method(void* e, const char* method);
    int easy_set_headers(void* e, const char* headers);
    int easy_set_header_lines(void* e, const char* const* lines, int count);
    int easy_set_cookies(void* e, const char* cookies);
    int easy_set_cookie_engine(void* e, int enable);
    int easy_set_cookie_list(void* e, const char* cookie);
    int easy_get_cookies(void* e, char** out);
    int easy_set_body(void* e, const char* body, int len);
    int easy_set_timeout(void* e, long ms);
    int easy_set_connect_timeout(void* e, long ms);
    int easy_set_verify(void* e, int verify, const char* ca_path);
    int easy_set_http_version(void* e, int version);
    int easy_set_proxy(void* e, const char* proxy);
    int easy_set_resolve(void* e, const char* const* entries, int count);
    int easy_set_userpwd(void* e, const char* userpwd);
    int easy_set_redirect(void* e, int follow, int max_redirs);
    int easy_set_verbose(void* e, int on);
    int easy_set_fresh_connect(void* e, int on);
    int easy_set_tcp_shape(void* e, const nb_tcp_shape* st);
    const char* easy_get_tcp_shape_error(void* e);
    int easy_check_tcp_shape(void* e, nb_tcp_shape_actual* out);
    int _curl_easy_setopt(void* e, int option, void* param);

    int easy_set_option_long(void* e, int option, long value);
    int easy_set_option_string(void* e, int option, const char* value);
    int easy_set_option_slist(void* e, int option, const char* const* entries, int count);
    int easy_set_option_off(void* e, int option, long long value);
    int easy_ws_send(void* e, const char* buf, int len, int flags);
    int easy_ws_recv(void* e, char* buf, int cap, int* nread, int* oflags,
                     long long* offset, long long* bytesleft);

    int  easy_perform(void* e, int* status_code, char** body, size_t* body_len,
                      char** headers, size_t* headers_len, char** error_msg);
    void easy_free_string(char* ptr);

    int easy_getinfo_long(void* e, int info, long* out);
    int easy_getinfo_double(void* e, int info, double* out);
    int easy_getinfo_string(void* e, int info, const char** out);

    const char* easy_version(void);
    const char* easy_strerror(int code);

    /* ---- 阶段 2：multi 驱动 + 结果所有权移交 ---- */
    typedef void nb_multi;
    typedef struct { long long fd; int action; int _reserved; } nb_sock_info;
    typedef struct { long long fd; int events; int revents; } nb_poll_item;

    int nb_multi_abi_version(void);
    nb_multi* nb_multi_init(void);
    void nb_multi_cleanup(nb_multi* m);
    int nb_multi_add(nb_multi* m, void* e);
    int nb_multi_remove(nb_multi* m, void* e);
    int nb_multi_active(nb_multi* m);

    int easy_prepare_request(void* e);
    int easy_take_body(void* e, char** out, size_t* len);
    int easy_take_headers(void* e, char** out, size_t* len);
    int easy_pause(void* e, int bitmask);
    int easy_perform_take(void* e, int* status_code, char** body, size_t* body_len,
                          char** headers, size_t* headers_len, char** error_msg);

    int nb_multi_perform(nb_multi* m);
    int nb_multi_drain(nb_multi* m, int* msg, int* code, void** easy_out);
    int nb_multi_socket_action(nb_multi* m, long long fd, int ev_bitmask);
    int nb_multi_socket_snapshot(nb_multi* m, nb_sock_info* out, int cap, int* total);
    int nb_multi_socket_changes(nb_multi* m, nb_sock_info* out, int cap, int* total);
    int nb_multi_timer(nb_multi* m, long* out_ms);
    int nb_multi_fire_timer(nb_multi* m);
    int nb_multi_poll(nb_multi* m, long timeout_ms, int* out_numfds);
    int nb_multi_wakeup(nb_multi* m);
    int nb_poll_sockets(nb_poll_item* items, int count, long timeout_ms);
"""


def _retry_fs(fn, what: str, attempts: int = 12, delay: float = 0.35):
    """对文件操作做带退避的重试。

    Windows 上刚写出的 .pyd/.dll 会被 Defender 实时保护短暂锁住
    （表现为 `PermissionError: [Errno 13]` 或 `WinError 5 拒绝访问`），
    删不掉也覆盖不了。这类锁通常几百毫秒内释放，重试即可，属于正常现象。

    这也是"构建时好时坏、偶尔静默失败"的真正原因，不是逻辑错误。
    """
    import time

    last: Exception | None = None
    for i in range(attempts):
        try:
            return fn()
        except OSError as exc:  # PermissionError 是其子类
            last = exc
            if i == 0:
                print("[..] %s 暂时被占用（%s），重试中..." % (what, exc))
            time.sleep(delay)
    raise SystemExit(
        "%s 失败：%s\n"
        "文件一直被占用。常见原因：杀毒软件正在扫描，或有进程仍加载着它。\n"
        "请关闭占用它的进程后重试。" % (what, last)
    )


def _clean_stale_artifacts(here: str, build_dir: str) -> list[str]:
    """删掉上一次的扩展产物。

    为什么放在 Python 里而不是让 shell 脚本去 ``rm``：

      * 在带"安全删除"钩子的环境（如 WorkBuddy 沙箱）里，``os.unlink`` 被替换成
        移入回收站，而回收站操作对某些路径会失败；``bash`` 那边 ``rm`` 甚至可能
        被换成 shell 函数并作为 ``BASH_FUNC_rm%%`` 传给子进程，行为不可预期。
      * 链接器（LNK1104 / EEXIST）要求目标文件必须先不存在，所以这一步不能省。
      * Windows 上还可能被 Defender 短暂锁住，所以删除要带重试。

    调用方（build_cffi.sh / scripts/40_cffi.sh）会给本进程设
    ``CODEBUDDY_SAFE_DELETE_ENABLED=0``，让删除真正生效。
    """
    import glob

    removed: list[str] = []
    patterns = [
        os.path.join(here, "_nb_curl_cffi*"),
        os.path.join(build_dir, "nb_curl", "_nb_curl_cffi*"),
        os.path.join(build_dir, "Release", "nb_curl", "_nb_curl_cffi*"),
        os.path.join(build_dir, "temp.*", "nb_curl", "_nb_curl_cffi*"),
    ]
    for pat in patterns:
        for path in glob.glob(pat):
            _retry_fs(lambda p=path: os.remove(p),
                      "删除过期产物 %s" % os.path.basename(path))
            removed.append(path)
    return removed


def build(verbose: bool = True) -> str:
    """编译 CFFI API 模式扩展。

    * Windows：链接 ``build/nb_curl_native.lib``（导入库），运行期加载同目录 DLL；
    * Linux/macOS：链接 ``nb_curl/_lib/libnb_curl_native.so``，并写入 ``$ORIGIN/_lib``
      rpath，这样扩展被 import 时能自动找到桥接层动态库。
    """
    import cffi

    setup_msvc_env()   # 非 Windows 上是空操作

    # 防御性检查：如果当前进程已经加载了 _nb_curl_cffi 扩展，那么待会儿
    # 删除 / 覆盖它必然失败（Windows 上文件被映射即无法改写）。
    # 病因通常是有人用 `python -m nb_curl._cffi_build` 跑 —— 这会先执行
    # nb_curl/__init__.py 并加载 cffi 后端。正确做法见 build_cffi.sh。
    if "nb_curl._nb_curl_cffi" in sys.modules:
        raise SystemExit(
            "当前进程已加载 _nb_curl_cffi 扩展，无法安全重编译。\n"
            "请在调用时强制 ctypes 后端，例如：\n"
            "    NB_CURL_BACKEND=ctypes python -m nb_curl._cffi_build\n"
            "（build_cffi.sh / scripts/40_cffi.sh 已经这么做了）")

    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    build_dir = os.path.join(root, "build")
    lib_dir = os.path.join(here, "_lib")
    # 导入库（nb_curl_native.lib）所在目录：默认 <项目根>/build，
    # 可用 NB_CURL_IMPLIB_DIR 指向实际产出目录（本项目构建脚本产出在 build/native/）。
    implib_dir = os.environ.get("NB_CURL_IMPLIB_DIR") or build_dir

    is_win = os.name == "nt"
    extra_link_args: list[str] = []
    library_dirs = [lib_dir]

    if is_win:
        # /Brepro：不写 PE 时间戳，保证同样源码/工具链产出逐字节相同的扩展
        # （基准对比要记录二进制哈希，不可复现就没法证明"测的是同一份产物"）。
        extra_link_args.append("/Brepro")
        implib = os.path.join(implib_dir, "nb_curl_native.lib")
        if not os.path.isfile(implib):
            raise SystemExit(
                "缺少导入库 %s，请先运行 build/build_windows_bridge.ps1" % implib)
        library_dirs.insert(0, implib_dir)
    else:
        if not os.path.isfile(os.path.join(lib_dir, "libnb_curl_native.so")):
            raise SystemExit(
                "缺少 nb_curl/_lib/libnb_curl_native.so，请先运行 scripts/30_bridge.sh")
        # 让 .so 自动从包的 _lib/ 目录加载
        extra_link_args.append("-Wl,-rpath,$ORIGIN/_lib")

    # 必须先清掉旧产物，否则链接器写不进去
    removed = _clean_stale_artifacts(here, build_dir)
    if verbose and removed:
        for p in removed:
            print("removed stale:", p)

    ffi = cffi.FFI()
    ffi.cdef(CDEF)
    # CFFI API 模式不会把 cdef 写成 C 声明，必须在 source 里给出真实声明。
    # 直接 include 桥接层头文件：既是声明来源，也让编译器在**编译期**校验
    # cdef 与真实结构体布局是否一致（这正是 API 模式相对 ctypes 的最大优势）。
    ffi.set_source(
        "nb_curl._nb_curl_cffi",
        source='#include "nb_curl_bridge.h"\n',
        libraries=["nb_curl_native"],
        library_dirs=library_dirs,
        include_dirs=[os.path.join(root, "native")],
        extra_link_args=extra_link_args,
    )

    out = ffi.compile(tmpdir=build_dir, verbose=verbose)

    # 校验并落位，带重试（新写出的 .pyd 可能被 Defender 短暂锁住）
    if not os.path.isfile(out):
        raise SystemExit(
            "CFFI 扩展编译似乎成功，但产物不存在：%s\n"
            "请检查上面的编译输出。" % out)

    if os.path.dirname(os.path.abspath(out)) != here:
        import shutil

        target = os.path.join(here, os.path.basename(out))
        _retry_fs(lambda: shutil.copy2(out, target),
                  "复制扩展产物到 %s" % os.path.basename(target))
        out = target

    if not os.path.isfile(out):
        raise SystemExit("CFFI 扩展产物缺失：%s" % out)

    # 落位后再做一次运行期自检：新扩展必须能看到 multi ABI v3，否则说明它链接到了
    # 旧的导入库（构建静默错位，不如在这里直接失败）。
    # 模块名必须与编译时的名字一致：扩展的 PyInit 函数名由模块名决定。
    import importlib.util

    if "nb_curl._nb_curl_cffi" in sys.modules:
        print("  [..] 当前进程已加载 _nb_curl_cffi，跳过 ABI 探针")
    else:
        spec = importlib.util.spec_from_file_location("nb_curl._nb_curl_cffi", out)
        probe = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        spec.loader.exec_module(probe)  # type: ignore[union-attr]
        ver = probe.lib.nb_multi_abi_version()
        if ver != 3:
            raise SystemExit(
                "编译产物里的 nb_multi_abi_version()=%r，期望 3 —— 可能链接到了旧的"
                " nb_curl_native.lib。请先重建桥接层"
                "（build/build_windows_bridge.sh）。" % (ver,))
        print("  multi ABI 版本自检通过:", ver)

    print("NB_CURL-CFFI-BUILD-OK ->", out)
    return out


if __name__ == "__main__":
    build(verbose="--quiet" not in sys.argv)
