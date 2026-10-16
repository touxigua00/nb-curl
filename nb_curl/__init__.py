"""nb_curl —— 自带浏览器 TLS 指纹的 HTTP 客户端

    >>> import nb_curl
    >>> r = nb_curl.get("https://example.com", impersonate="chrome155")
    >>> r.status_code
    200
    >>> r.text[:20]

内置指纹（chrome99/116/131/146/150/155、firefox147 等 40 个预设）在 libcurl
内核原生支持；自定义指纹通过 ``ja3`` / ``akamai`` / ``diy_fp`` /
``fp_file``（xcctls.top/all 快照）在 Python 侧下发，无需重编译。
自定义参数的合法取值范围用 ``nb_curl.tls`` 自省（如 ``nb_curl.tls.supported_ciphers()``），
给错值会在请求发出前抛 ``nb_curl.FingerprintError``，不会到建连时才报难懂的 CURLcode。

**所有参数（能传什么、怎么给）见 :mod:`nb_curl.params`**：
``help(nb_curl.params.RequestOptions)`` 或 ``print(nb_curl.params.describe())``。
"""

from __future__ import annotations

# AsyncSession 直接导入：模块级 __getattr__ 会让 IDE 认为本模块属性是动态的，
# 从而失去补全与 Ctrl+B 跳转（asyncio 是标准库，导入开销可忽略）
from .aio import AsyncSession
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
    TCPShapeError,
    TCPShapeWarning,
    Timeout,
    TooManyRedirects,
    UnsupportedError,
)
from .fingerprint import Fingerprint, FingerprintOverrides, diy_fp_fields
from .impersonate import RECOMMENDED_TARGETS, available_targets, is_available
from .models import CookieJar, Cookies, Headers, Request, Response
from .options import CurlOpt, apply_curl_options
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
from .ws import WebSocket
from .xcctls import load_fp_snapshot, parse_xcctls
from . import params as params
from . import tcp as tcp
from . import tls as tls
from .tcp import set_tcp_warnings, tcp_support

__version__ = "0.3.1"


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
    "CookieJar",
    "Fingerprint",
    "FingerprintOverrides",
    "WebSocket",
    "CurlOpt",
    "apply_curl_options",
    # 异步
    "AsyncSession",
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
    # 参数总表：能传什么、怎么给（help(nb_curl.params.RequestOptions)）
    "params",
    # TCP 层画像（JA4T）：socket 级设定 + 能力自省
    "tcp",
    "tcp_support",
    "set_tcp_warnings",
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
    "TCPShapeError",
    "TCPShapeWarning",
]
