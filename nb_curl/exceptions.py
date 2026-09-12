"""nb_curl 异常体系（对齐 requests / curl_cffi 的习惯叫法）。"""

from __future__ import annotations

__all__ = [
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


class NbCurlError(Exception):
    """所有 nb_curl 异常的基类。"""


class RequestError(NbCurlError):
    """请求执行失败（对应 CURLcode != CURLE_OK）。"""

    def __init__(self, message: str, code: int | None = None):
        super().__init__(message)
        self.code = code


class ImpersonateError(NbCurlError):
    """impersonate target 不存在或不可用。"""


class FingerprintError(NbCurlError):
    """ja3 / akamai / diy_fp / fp_file 解析或下发失败。"""


class HTTPError(NbCurlError):
    """HTTP 状态码异常（raise_for_status 抛出）。"""

    def __init__(self, message: str, response=None):
        super().__init__(message)
        self.response = response


class Timeout(RequestError):
    """请求超时。"""


class ConnectTimeout(Timeout):
    """连接超时。"""


class ProxyError(RequestError):
    """代理相关失败。"""


class TooManyRedirects(RequestError):
    """重定向次数超限。"""


class UnsupportedError(NbCurlError):
    """使用了本库尚未支持的特性。"""
