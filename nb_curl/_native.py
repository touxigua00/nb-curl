"""nb_curl._native —— FFI 后端选择层

对外只暴露一个 ``lib`` 对象，它的方法由具体后端实现：

* ``cffi``   —— CFFI **API 模式**（编译期绑定，首选）
* ``ctypes`` —— 标准库 ctypes（兜底，无需编译 CFFI 扩展）

选择规则（环境变量 ``NB_CURL_BACKEND``）::

    auto   （默认）优先 cffi，缺失或加载失败则回退 ctypes
    cffi   强制 cffi，失败直接报错（便于 CI 暴露问题）
    ctypes 强制 ctypes（用于对比/排查）

两个后端实现完全相同的接口，所以上层 ``session`` / ``fingerprint``
不需要关心用的是哪一个。
"""

from __future__ import annotations

import os

__all__ = [
    "lib",
    "BACKEND",
    "BACKEND_PATH",
    "NativeError",
    "native_version",
    "backend_info",
    "available_backends",
]

_IS_WIN = os.name == "nt"


class NativeError(RuntimeError):
    """native 调用返回了错误码。"""

    def __init__(self, code: int, message: str):
        super().__init__("nb_curl native error %d: %s" % (code, message))
        self.code = code
        self.message = message


def _try_cffi():
    from ._backend_cffi import CffiBackend

    return CffiBackend()


def _try_ctypes():
    from ._backend_ctypes import CtypesBackend

    return CtypesBackend()


def _select_backend():
    pref = os.environ.get("NB_CURL_BACKEND", "auto").strip().lower() or "auto"

    if pref == "ctypes":
        return _try_ctypes()
    if pref == "cffi":
        return _try_cffi()
    if pref not in ("auto", ""):
        raise ValueError(
            "NB_CURL_BACKEND 只能是 auto / cffi / ctypes，实际 %r" % pref)

    # auto：优先 CFFI API 模式
    cffi_error = None
    try:
        return _try_cffi()
    except Exception as exc:  # noqa: BLE001 - 回退是预期路径
        cffi_error = exc
    try:
        backend = _try_ctypes()
    except Exception as exc:  # noqa: BLE001
        native = "nb_curl_native.dll" if os.name == "nt" else "libnb_curl_native.so"
        raise ImportError(
            "nb_curl 无法加载任何 FFI 后端。\n"
            "  CFFI API 模式失败: %r\n"
            "  ctypes 兜底也失败: %r\n"
            "请确认 nb_curl/_lib/ 下的动态库（%s）存在，且与本机平台一致。\n"
            % (cffi_error, exc, native)
        ) from exc
    backend.cffi_error = cffi_error  # 供 backend_info() 展示
    return backend


def _explain_cffi_error(exc) -> str:
    """把 CFFI 后端加载失败翻译成可执行的建议。"""
    if exc is None:
        return ""
    text = repr(exc)
    if "_cffi_backend" in text or "No module named 'cffi'" in text:
        return "未安装 cffi 包（CFFI API 模式扩展运行期依赖它）→ pip install cffi"
    if "_nb_curl_cffi" in text:
        return ("当前 Python 版本没有对应的 CFFI 扩展 → 已自动回退 ctypes 后端，功能一致；"
                "想用 cffi 后端请使用 wheel 支持的 Python 版本")
    if "DLL load failed" in text or "cannot open shared object" in text:
        return "扩展或 native 库加载失败，检查 nb_curl/_lib/ 下的动态库是否齐全"
    return text


lib = _select_backend()

BACKEND: str = getattr(lib, "name", "unknown")
BACKEND_PATH: str = getattr(lib, "path", "")


def native_version() -> str:
    """返回底层 libcurl 的版本字符串。"""
    return lib.version()


def backend_info() -> dict:
    """当前后端信息（用于自检/日志）。"""
    info = {
        "backend": BACKEND,
        "native_lib": BACKEND_PATH,
        "curl": native_version(),
    }
    if BACKEND != "cffi":
        reason = _explain_cffi_error(getattr(lib, "cffi_error", None))
        if reason:
            info["cffi_fallback_reason"] = reason
    return info


def available_backends() -> list[str]:
    """探测哪些后端当前可用（会实际尝试加载）。"""
    out: list[str] = []
    try:
        _try_cffi()
        out.append("cffi")
    except Exception:  # noqa: BLE001
        pass
    try:
        _try_ctypes()
        out.append("ctypes")
    except Exception:  # noqa: BLE001
        pass
    return out
