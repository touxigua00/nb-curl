"""nb_curl.requests —— requests 风格的调用入口

    >>> from nb_curl import requests
    >>> r = requests.get("https://example.com", impersonate="chrome152")
    >>> r.status_code
    200

本模块只是 :mod:`nb_curl` 顶层 API 的再导出，两种写法完全等价：

    import nb_curl
    nb_curl.get(url, impersonate="chrome152")

    from nb_curl import requests           # 或 from nb_curl.requests import get
    requests.get(url, impersonate="chrome152")

每个函数的参数说明见 :class:`nb_curl.Session` 与
:meth:`nb_curl.Session._request` 的 docstring（``impersonate`` /
``proxy`` / ``proxies`` / ``headers`` / ``ja3`` / ``akamai`` / ``diy_fp`` /
``fp_file`` …）。
"""

from __future__ import annotations

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

__all__ = [
    # HTTP 方法
    "request", "get", "post", "put", "patch", "delete", "head", "options",
    # 会话与对象
    "Session", "Response", "Request", "Headers", "Cookies",
    # 异常
    "NbCurlError", "RequestError", "ImpersonateError", "FingerprintError",
    "HTTPError", "Timeout", "ConnectTimeout", "ProxyError",
    "TooManyRedirects", "UnsupportedError",
]
