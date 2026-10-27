"""nb_curl 打包配置

打包策略
--------
1. wheel 里只有 ``.dll`` / ``.so`` / ``.pyd`` 这类已编译产物；
2. 打 wheel 时不做任何 C 编译（``has_ext_modules()`` 只用于给 wheel 打上平台标签，
   不会真的调用编译器）—— 安装方**不需要编译器**；
3. 构建期专用脚本不进入 wheel（见 ``_BUILD_ONLY_MODULES``）。

wheel 标签是 ``py3-none-<平台>``：平台相关（因为带二进制），但**不绑定 Python 版本**。

两种 FFI 后端对 Python 版本的依赖不同：

* ``ctypes`` 后端 —— 纯 Python + 标准库，任何 Python 3.x 都能用；
* ``cffi`` 后端 —— 编译出的 CPython 扩展，但编译时走的是**稳定 ABI**
  （cffi 默认 ``py_limited_api=True``），文件名特意不带版本号
  （``_nb_curl_cffi.pyd`` / ``_nb_curl_cffi.abi3.so``），
  所以**一份产物所有 Python 3.x 通用**，不需要每个版本各编一次。

因此：扩展装得上 → 走 cffi 后端；用户没装 cffi 包或加载失败 → **自动回退 ctypes 后端，
功能完全一致**。
"""

from __future__ import annotations

import os
import sys

from setuptools import Distribution, setup
from setuptools.command.build_py import build_py as _build_py

# ---------------------------------------------------------------- #
# 1) 标记为"平台相关"
#    （否则会打成 py3-none-any，被 pip 装到 Linux/macOS 上然后找不到 .dll）
# ---------------------------------------------------------------- #
class BinaryDistribution(Distribution):
    def has_ext_modules(self) -> bool:  # noqa: D102
        return True

    def is_pure(self) -> bool:  # noqa: D102
        return False


# ---------------------------------------------------------------- #
# 2) 过滤包内容：构建期专用脚本 + 平台不匹配的二进制
# ---------------------------------------------------------------- #
_BUILD_ONLY_MODULES = {
    "_cffi_build.py",      # 本地构建脚手架
}

# 二进制扩展名 → 属于哪个平台
_BINARY_SUFFIXES = (".dll", ".pyd", ".so", ".dylib")

# 当前平台"允许"的二进制扩展名
_PLATFORM_ALLOWED = {
    "win32": (".dll", ".pyd"),
    "cygwin": (".dll", ".pyd"),
    "linux": (".so",),
    "darwin": (".dylib", ".so"),
}.get(sys.platform)


class build_py(_build_py):
    """过滤包内容：

    1. 剔除构建期专用脚本（如 `_cffi_build.py`）；
    2. 剔除**平台不匹配**的二进制。

       为什么需要第 2 条：源码树里可能同时存在 Windows 的
       `nb_curl_native.dll` 和 Linux 的 `libnb_curl_native.so`
       （比如把 Windows 仓库同步到 Linux 机器上构建时）。
       如果不过滤，Linux 的 wheel 里会白白塞进一个 2.7MB 的 Windows DLL。
    """

    def find_package_modules(self, package, package_dir):
        modules = super().find_package_modules(package, package_dir)
        return [
            (pkg, mod, path)
            for pkg, mod, path in modules
            if os.path.basename(path) not in _BUILD_ONLY_MODULES
        ]

    def find_data_files(self, package, src_dir):
        files = super().find_data_files(package, src_dir)
        if not _PLATFORM_ALLOWED:
            return files
        kept = []
        for f in files:
            if f.lower().endswith(_BINARY_SUFFIXES) and not f.lower().endswith(_PLATFORM_ALLOWED):
                print("  [skip] 平台不匹配的二进制（%s 上不需要）: %s"
                      % (sys.platform, f))
                continue
            kept.append(f)
        return kept


# ---------------------------------------------------------------- #
# 3) wheel 的 python/abi 标签：改成 py3-none，只保留平台标签
# ---------------------------------------------------------------- #
try:
    from wheel.bdist_wheel import bdist_wheel as _bdist_wheel
except ImportError:  # wheel 未装（新版 setuptools 已内联）
    try:
        from setuptools.command.bdist_wheel import bdist_wheel as _bdist_wheel
    except ImportError:  # pragma: no cover
        _bdist_wheel = None


if _bdist_wheel is not None:

    class bdist_wheel(_bdist_wheel):  # type: ignore[no-redef]
        def get_tag(self):
            _py, _abi, plat = super().get_tag()
            return "py3", "none", plat

        def finalize_options(self):
            super().finalize_options()
            self.root_is_pure = False

    _cmdclass = {"bdist_wheel": bdist_wheel, "build_py": build_py}
else:  # pragma: no cover
    _cmdclass = {"build_py": build_py}


# ---------------------------------------------------------------- #
# 4) 打包前确认二进制就位（缺了直接报错，而不是打出空包）
# ---------------------------------------------------------------- #
_HERE = os.path.dirname(os.path.abspath(__file__))
_LIBDIR = os.path.join(_HERE, "nb_curl", "_lib")

_NATIVE_CANDIDATES = [
    os.path.join(_LIBDIR, "nb_curl_native.dll"),
    os.path.join(_LIBDIR, "libnb_curl_native.so"),
    os.path.join(_LIBDIR, "libnb_curl_native.dylib"),
]
_HAS_NATIVE = any(os.path.isfile(p) for p in _NATIVE_CANDIDATES)

if os.environ.get("NB_CURL_REQUIRE_NATIVE", "1") != "0" and not _HAS_NATIVE:
    if any(cmd in sys.argv for cmd in ("bdist_wheel", "install", "develop")):
        raise SystemExit(
            "缺少 nb_curl 动态库，先把它放到 nb_curl/_lib/ 下再打包。"
            "期望以下任一文件存在：\n  %s\n"
            "如确实要打一个不含二进制的包，设 NB_CURL_REQUIRE_NATIVE=0。"
            % "\n  ".join(_NATIVE_CANDIDATES)
        )

setup(
    distclass=BinaryDistribution,
    cmdclass=_cmdclass,
)
