"""nb_curl._facade —— 公开入口的转发层（手写，很短）。

**为什么要有这一层**：请求本身实现在 :mod:`nb_curl.session`，那儿是业务逻辑。
这一层只干两件事：

1. 把公开方法的**签名位置**摆出来，让 IDE 有落点（``session.get`` → 这里 → 再往下是实现）；
2. 参数由 :mod:`nb_curl.params` 的 TypedDict 声明 —— 补全、参数提示（Ctrl+P）、
   快速文档（Ctrl+Q）全从那儿来，所以**这里不用把参数表抄第二遍**。

加 / 改一个参数，只动 ``params.py`` 一处即可。
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from .models import Response
from .params import (
    MODULE_SESSION_KEYS,
    SESSION_KEYS,
    RequestOptions,
    SessionOptions,
    Unpack,
    check_options,
)

__all__ = [
    "SessionShortcuts",
    "AsyncSessionShortcuts",
    "request",
    "get",
    "options",
    "head",
    "post",
    "put",
    "patch",
    "delete",
]


# --------------------------------------------------------------------------- #
# 同步
# --------------------------------------------------------------------------- #
class SessionShortcuts:
    """``Session`` / ``AsyncSession`` 的 8 个 HTTP 方法快捷入口。

    参数见 :class:`nb_curl.params.RequestOptions`。每个方法都只是转发到
    ``Session._request``。
    """

    if TYPE_CHECKING:  # 实现见 nb_curl.session.Session._request，这里只给 IDE 一个落点
        def _request(self, method: str, url: str,
                     **options: Unpack[RequestOptions]) -> Response: ...

    def request(self, method: str, url: str, **options: Unpack[RequestOptions]) -> Response:
        """任意方法。参数见 :class:`nb_curl.params.RequestOptions`。"""
        return self._request(method, url, **options)

    def get(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """GET 请求。参数见 :class:`nb_curl.params.RequestOptions`。"""
        return self._request("GET", url, **options)

    def options(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """OPTIONS 请求。参数见 :class:`nb_curl.params.RequestOptions`。"""
        return self._request("OPTIONS", url, **options)

    def head(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """HEAD 请求。参数见 :class:`nb_curl.params.RequestOptions`。"""
        return self._request("HEAD", url, **options)

    def post(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """POST 请求。参数见 :class:`nb_curl.params.RequestOptions`。"""
        return self._request("POST", url, **options)

    def put(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """PUT 请求。参数见 :class:`nb_curl.params.RequestOptions`。"""
        return self._request("PUT", url, **options)

    def patch(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """PATCH 请求。参数见 :class:`nb_curl.params.RequestOptions`。"""
        return self._request("PATCH", url, **options)

    def delete(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """DELETE 请求。参数见 :class:`nb_curl.params.RequestOptions`。"""
        return self._request("DELETE", url, **options)


# --------------------------------------------------------------------------- #
# 异步（同一套转发，只是丢进线程池跑）
# --------------------------------------------------------------------------- #
class AsyncSessionShortcuts:
    """``AsyncSession`` 的 8 个异步入口，参数与同步版一致。

    实现都在 :meth:`nb_curl.aio.AsyncSession._request_async`：非流式走 libcurl
    multi 驱动（不再每请求一个线程），流式走兼容的独立线程路径。这一层只负责
    摆签名，不做任何请求装配。
    """

    if TYPE_CHECKING:
        async def _request_async(self, method: str, url: str,
                                 **options: Unpack[RequestOptions]) -> Response: ...

    async def request(self, method: str, url: str,
                      **options: Unpack[RequestOptions]) -> Response:
        """任意方法（异步）。参数见 :class:`nb_curl.params.RequestOptions`。"""
        return await self._request_async(method, url, **options)

    async def get(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """GET 请求（异步）。参数见 :class:`nb_curl.params.RequestOptions`。"""
        return await self.request("GET", url, **options)

    async def options(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """OPTIONS 请求（异步）。参数见 :class:`nb_curl.params.RequestOptions`。"""
        return await self.request("OPTIONS", url, **options)

    async def head(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """HEAD 请求（异步）。参数见 :class:`nb_curl.params.RequestOptions`。"""
        return await self.request("HEAD", url, **options)

    async def post(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """POST 请求（异步）。参数见 :class:`nb_curl.params.RequestOptions`。"""
        return await self.request("POST", url, **options)

    async def put(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """PUT 请求（异步）。参数见 :class:`nb_curl.params.RequestOptions`。"""
        return await self.request("PUT", url, **options)

    async def patch(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """PATCH 请求（异步）。参数见 :class:`nb_curl.params.RequestOptions`。"""
        return await self.request("PATCH", url, **options)

    async def delete(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """DELETE 请求（异步）。参数见 :class:`nb_curl.params.RequestOptions`。"""
        return await self.request("DELETE", url, **options)


# --------------------------------------------------------------------------- #
# 模块级：一次性请求（临时 Session，用完即关）
# --------------------------------------------------------------------------- #
def _split_options(options: dict) -> tuple[dict, dict]:
    """按「会话级 / 请求级」拆开 —— 模块级入口两者都能传，各归各位。"""
    session_opts = {k: v for k, v in options.items() if k in MODULE_SESSION_KEYS}
    request_opts = {k: v for k, v in options.items() if k not in MODULE_SESSION_KEYS}
    return session_opts, request_opts


def request(method: str, url: str, **options: Unpack[SessionOptions]) -> Response:
    """一次性请求：内部建一个临时 Session，用完即关。

    唯一例外是 ``stream=True``：响应体还在传，临时会话不能当场关掉，
    于是把它的所有权交给响应，等 ``response.close()``（或用 ``with``）时再关。

    参数见 :class:`nb_curl.params.SessionOptions`。
    """
    from .session import Session

    check_options("nb_curl.request", options, SESSION_KEYS)
    session_opts, request_opts = _split_options(options)
    session = Session(**session_opts)
    try:
        response = session._request(method, url, **request_opts)
    except BaseException:
        session.close()
        raise
    if response.is_stream:
        response._owned_session = session   # 传输还在进行，会话得陪着响应一起活
        return response
    session.close()
    return response


def get(url: str, **options: Unpack[SessionOptions]) -> Response:
    """GET 请求（一次性）。参数见 :class:`nb_curl.params.SessionOptions`。"""
    return request("GET", url, **options)


def options(url: str, **options: Unpack[SessionOptions]) -> Response:  # noqa: A001
    """OPTIONS 请求（一次性）。参数见 :class:`nb_curl.params.SessionOptions`。"""
    return request("OPTIONS", url, **options)


def head(url: str, **options: Unpack[SessionOptions]) -> Response:
    """HEAD 请求（一次性）。参数见 :class:`nb_curl.params.SessionOptions`。"""
    return request("HEAD", url, **options)


def post(url: str, **options: Unpack[SessionOptions]) -> Response:
    """POST 请求（一次性）。参数见 :class:`nb_curl.params.SessionOptions`。"""
    return request("POST", url, **options)


def put(url: str, **options: Unpack[SessionOptions]) -> Response:
    """PUT 请求（一次性）。参数见 :class:`nb_curl.params.SessionOptions`。"""
    return request("PUT", url, **options)


def patch(url: str, **options: Unpack[SessionOptions]) -> Response:
    """PATCH 请求（一次性）。参数见 :class:`nb_curl.params.SessionOptions`。"""
    return request("PATCH", url, **options)


def delete(url: str, **options: Unpack[SessionOptions]) -> Response:
    """DELETE 请求（一次性）。参数见 :class:`nb_curl.params.SessionOptions`。"""
    return request("DELETE", url, **options)
