"""nb_curl.aio —— 异步会话

实现说明（诚实版）：本版用线程池驱动同步 native 调用，而不是基于 libcurl multi +
事件循环直连。原因：

* native 层的 easy handle 是阻塞式的（``curl_easy_perform``），没有暴露 multi 接口；
* 线程池方案在 Windows/Linux 行为一致，且天然支持连接复用（同一指纹下的 handle
  由 ``_Pool`` 复用，不会每个请求新建连接）。

因此它**不是**零开销的真异步，但相对"每个请求起一个子进程"已经是数量级的提升。
后续如需极限吞吐，可在 C 层补 ``curl_multi_*`` 桥接后替换本模块，Python 接口不变。
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .models import Response
from .session import Session

__all__ = ["AsyncSession"]


class AsyncSession(Session):
    """基于线程池的异步 Session，API 与 Session 一致，方法需 await。"""

    def __init__(self, *, max_clients: int = 20, **kwargs: Any):
        super().__init__(max_clients=max_clients, **kwargs)
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, int(max_clients)), thread_name_prefix="nb_curl"
        )
        self._closed_executor = False

    async def __aenter__(self) -> "AsyncSession":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def request(self, method: str, url: str, **kwargs: Any) -> Response:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor, lambda: self._request(method, url, **kwargs)
        )

    async def get(self, url: str, **kwargs: Any) -> Response:
        return await self.request("GET", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> Response:
        return await self.request("OPTIONS", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> Response:
        return await self.request("HEAD", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> Response:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> Response:
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> Response:
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> Response:
        return await self.request("DELETE", url, **kwargs)

    async def close(self) -> None:
        # 先等所有在飞的请求结束，再关连接与线程池；
        # 否则会与 executor 线程里的 curl_easy_perform 并发 free 同一个 handle（段错误）。
        if not self._closed_executor:
            await asyncio.to_thread(self._executor.shutdown, True)
            self._closed_executor = True
        await asyncio.to_thread(super().close)

    def __del__(self) -> None:  # pragma: no cover - 兜底（无事件循环，同步关）
        try:
            if not self._closed_executor:
                self._executor.shutdown(wait=False)
                self._closed_executor = True
            super().close()
        except Exception:  # noqa: BLE001
            pass
