"""nb_curl —— 自带浏览器 TLS 指纹的 HTTP 客户端

    >>> import nb_curl
    >>> r = nb_curl.get("https://example.com", impersonate="chrome152")
    >>> r.status_code
    200
    >>> r.text[:20]

内置指纹（chrome99/116/131/146/150/152、firefox147 等 40 个预设）在 libcurl
内核原生支持；自定义指纹通过 ``ja3`` / ``akamai`` / ``diy_fp`` /
``fp_file``（xcctls.top/all 快照）在 Python 侧下发，无需重编译。
自定义参数的合法取值范围用 ``nb_curl.tls`` 自省（如 ``nb_curl.tls.supported_ciphers()``），
给错值会在请求发出前抛 ``nb_curl.FingerprintError``，不会到建连时才报难懂的 CURLcode。
"""

from __future__ import annotations

from ._native import (
    BACKEND as _BACKEND,
    available_backends,
    backend_info,
    native_version,
)
from .exceptions import (
    ConnectTimeout,
    NbCurlError,
    FingerprintError,
    HTTPError,
    ImpersonateError,
    ProxyError,
    RequestError,
    Timeout,
    TooManyRedirects,
    UnsupportedError,
)
from .fingerprint import Fingerprint, FingerprintOverrides, diy_fp_fields
from .impersonate import RECOMMENDED_TARGETS, available_targets, is_available
from .models import Cookies, Headers, Request, Response
from .session import (
    Session,
    delete,
    get,
    head,
    options,
    patch,
    post,
    put,
    request,
)
from .xcctls import load_fp_snapshot, parse_xcctls
from . import tls as tls

__version__ = "0.2.2"


def backend_name() -> str:
    """当前生效的 FFI 后端（``cffi`` = CFFI API 模式 / ``ctypes`` = 兜底）。"""
    return _BACKEND


__all__ = [
    "__version__",
    "native_version",
    "backend_name",
    "backend_info",
    "available_backends",
    # 核心
    "Session",
    "Response",
    "Request",
    "Headers",
    "Cookies",
    "Fingerprint",
    "FingerprintOverrides",
    # 便捷函数
    "request",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    # 指纹自省
    "available_targets",
    "is_available",
    "RECOMMENDED_TARGETS",
    # TLS 取值范围自省（自定义指纹允许哪些值，看这里）
    "tls",
    # diy_fp 字段类型/取值自省
    "diy_fp_fields",
    # xcctls.top/all 快照：解析与加载
    "parse_xcctls",
    "load_fp_snapshot",
    # 异常
    "NbCurlError",
    "RequestError",
    "ImpersonateError",
    "FingerprintError",
    "HTTPError",
    "Timeout",
    "ConnectTimeout",
    "ProxyError",
    "TooManyRedirects",
    "UnsupportedError",
]


def __getattr__(name: str):
    """延迟导入 AsyncSession，避免没装 asyncio 场景下的额外开销。"""
    if name == "AsyncSession":
        from .aio import AsyncSession

        return AsyncSession
    raise AttributeError("module %r has no attribute %r" % (__name__, name))
