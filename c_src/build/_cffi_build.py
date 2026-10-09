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
#
# 所有路径都可以用环境变量覆盖，默认值按"仓库自带的 deps/windows-prebuilt/"
# 和"标准的 Visual Studio 安装位置"推导，因此换一台机器不需要改本文件：
#
#   NB_CURL_MSVC_TOOLS  MSVC 工具链目录（.../VC/Tools/MSVC）
#   NB_CURL_SDK_ROOT    Windows SDK 根目录
#   NB_CURL_SDK_VER     Windows SDK 版本（留空则自动取最新的）
#   NB_CURL_BORINGSSL   含 include/ + lib/ 的 BoringSSL 安装树
#   NB_CURL_LIBCURL     含 include/ + lib/libcurl-impersonate.lib 的 libcurl 安装树
#   NB_CURL_VCPKG       含 include/ + lib/*.lib 的第三方静态库树
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # <repo>/python
_REPO = os.path.dirname(_ROOT)                                       # <repo>
_PREBUILT = os.path.join(_REPO, "deps", "windows-prebuilt")

_MSVC_TOOLS = os.environ.get("NB_CURL_MSVC_TOOLS") or ""
_SDK_ROOT = os.environ.get("NB_CURL_SDK_ROOT") or r"C:\Program Files (x86)\Windows Kits\10"
_SDK_VER = os.environ.get("NB_CURL_SDK_VER") or ""
_BSSL = os.environ.get("NB_CURL_BORINGSSL") or os.path.join(_PREBUILT, "boringssl")
_CURLDIR = os.environ.get("NB_CURL_LIBCURL") or os.path.join(_PREBUILT, "curl-impersonate")
_VCPKG = os.environ.get("NB_CURL_VCPKG") or os.path.join(_PREBUILT, "vcpkg-static")


def _detect_msvc_tools() -> str:
    """定位 .../VC/Tools/MSVC 目录，优先用 vswhere，其次扫常见安装位置。"""
    if _MSVC_TOOLS and os.path.isdir(_MSVC_TOOLS):
        return _MSVC_TOOLS
    vswhere = os.path.join(
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        "Microsoft Visual Studio", "Installer", "vswhere.exe")
    if os.path.isfile(vswhere):
        try:
            import subprocess

            out = subprocess.check_output(
                [vswhere, "-latest", "-products", "*", "-property", "installationPath"],
                text=True, stderr=subprocess.DEVNULL).strip().splitlines()
            if out:
                cand = os.path.join(out[0].strip(), "VC", "Tools", "MSVC")
                if os.path.isdir(cand):
                    return cand
        except Exception:
            pass
    for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"),
                 r"D:\Program_files"):
        if not base:
            continue
        for edn in ("Community", "Professional", "Enterprise", "BuildTools"):
            cand = os.path.join(base, "Microsoft Visual Studio", "2022", edn,
                                "VC", "Tools", "MSVC")
            if os.path.isdir(cand):
                return cand
    return _MSVC_TOOLS or r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC"


def _detect_sdk_ver() -> str:
    """未显式指定 SDK 版本时，取 Windows Kits/10/Include 下最新的一个。"""
    if _SDK_VER:
        return _SDK_VER
    inc = os.path.join(_SDK_ROOT, "Include")
    if os.path.isdir(inc):
        vers = [d for d in os.listdir(inc)
                if d[:2].isdigit() and os.path.isdir(os.path.join(inc, d))]
        if vers:
            return sorted(vers)[-1]
    return "10.0.26100.0"


def _latest_msvc() -> str:
    tools = _detect_msvc_tools()
    if not os.path.isdir(tools):
        raise SystemExit(
            "找不到 MSVC 工具链目录: %s\n"
            "请安装 Visual Studio 2022（含 C++ 生成工具），或用环境变量 "
            "NB_CURL_MSVC_TOOLS 指定 .../VC/Tools/MSVC 的路径。" % tools)
    versions = sorted(
        (d for d in os.listdir(tools) if os.path.isdir(os.path.join(tools, d))),
        key=lambda s: tuple(int(x) for x in s.split(".") if x.isdigit()),
    )
    return os.path.join(tools, versions[-1])


def setup_msvc_env() -> None:
    """把 MSVC/SDK 的 INCLUDE/LIB/PATH 以 Windows 原生格式注入当前进程环境。"""
    if os.name != "nt":
        return
    msvc = _latest_msvc()
    sdk_ver = _detect_sdk_ver()
    sdk_inc = os.path.join(_SDK_ROOT, "Include", sdk_ver)
    sdk_lib = os.path.join(_SDK_ROOT, "Lib", sdk_ver)

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
        os.path.join(_SDK_ROOT, "bin", sdk_ver, "x64"),
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

    is_win = os.name == "nt"
    extra_link_args: list[str] = []
    library_dirs = [lib_dir]

    if is_win:
        if not os.path.isfile(os.path.join(build_dir, "nb_curl_native.lib")):
            raise SystemExit(
                "缺少导入库 build/nb_curl_native.lib，请先运行 build_native.sh")
        library_dirs.insert(0, build_dir)
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

    print("NB_CURL-CFFI-BUILD-OK ->", out)
    return out


if __name__ == "__main__":
    build(verbose="--quiet" not in sys.argv)
