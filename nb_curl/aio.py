"""nb_curl.aio —— 异步会话（native multi 驱动）

本版与旧版的根本差别
====================

旧版：``ThreadPoolExecutor(max_workers=max_clients)`` + 每个在飞请求一个 Python
线程，线程整段时间阻塞在 ``curl_easy_perform``。异步只是"换个线程同步跑"。

新版（非流式）：一个会话一个**有界 multi 驱动**（见 :mod:`nb_curl._multi`），
请求进 libcurl multi，由 socket/timer 事件推进；没有每请求线程，也没有按并发
扩张的线程池。连接复用、重定向、解压、cookie 引擎仍由 libcurl 负责。

驱动实现按平台选（可用 ``NB_CURL_ASYNC_DRIVER=thread|loop`` 覆盖）：

* ``thread``（Windows 默认，Proactor 事件循环没有 ``add_reader``）：
  一个专职驱动线程 + ``nb_poll_sockets`` + ``socketpair`` 唤醒；
* ``loop``（POSIX 默认）：把 multi 的 socket 直接挂到调用方事件循环上
  （``add_reader`` / ``add_writer`` + libcurl timer）。

**不修改**用户的事件循环策略（不调用 ``set_event_loop_policy``）。

流式（``stream=True``）：会话级专职 reactor
==========================================

``stream=True`` 走 :mod:`nb_curl._stream_reactor` 的 ``StreamReactor``：
**每 Session 至多 1 个专职线程**驱动该会话的全部流（每连接分区一个 multi、
每条流一个独立 easy 句柄，背压用 ``CURL_WRITEFUNC_PAUSE`` 高/低水位实现）。
不再有"每条流一个线程"的兼容执行器；同步 ``content`` / ``iter_content()``
在事件循环线程上调用也只会阻塞调用线程（reactor 独立推进，不死锁）。
"""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ._facade import AsyncSessionShortcuts
from ._multi import AsyncDriver, async_result_to_response
from .exceptions import NbCurlError
from .models import Response
from .params import REQUEST_KEYS, SessionOptions, Unpack, check_options
from .session import Session, _merge_url

__all__ = ["AsyncSession"]

#: close 排空已接纳请求：不再设人为上限。
#:
#: 旧契约（``python/nb_curl/aio.py``）是 ``executor.shutdown(wait=True)``：
#: **没有**超时上限，等在飞/排队的请求自然跑完。这里同样不设预算 —— 否则
#: 一个 ``timeout=60`` 的合法请求会在 30s 被活活中止，那是新引入的行为变化。
#: 每个请求自己的 ``timeout`` 才决定它何时结束（``timeout=None`` 且对端不响应
#: 时，旧版同样会一直等下去，本版保持一致）。
_CLOSE_DRAIN_POLL_S = 0.02


class AsyncSession(AsyncSessionShortcuts, Session):
    """基于 libcurl multi 的异步 Session。

    参数与 :class:`nb_curl.Session` 完全一致（见 :class:`nb_curl.params.SessionOptions`），
    只有 ``max_clients`` 默认值不同（20）。``max_clients`` 在这里的含义与同步版
    一致（每个连接分区的句柄上限），同时保持旧线程池隐含的**全会话活动上限**：
    异步在飞请求数（流式为"到响应头为止"）不超过 ``max_clients``。
    """

    def __init__(self, **options: Unpack[SessionOptions]):
        if options.get("max_clients") is None:
            options["max_clients"] = 20
        super().__init__(**options)
        self._driver: AsyncDriver | None = None
        self._async_limit: asyncio.Semaphore | None = None
        # 并发 close 共享的收尾任务（None = 还没人发起 close）
        self._close_task: Any = None
        # **关闭已发起**（新请求一律拒绝）但 **native 还没收尾**（已接纳的请求
        # 照常跑完）。这两个必须是不同的状态：
        #
        # 旧契约（``executor.shutdown(wait=True)``）里，已接纳的排队任务在 close
        # 之后仍然会执行完。若这里复用 ``_closed``（``Session.close`` 用它表示
        # "池已关/句柄已回收"），排队者拿到名额后会看到 ``_closed`` 而被拒 ——
        # 那正是把"拒绝新请求"和"资源已回收"混为一谈造成的回归。
        self._close_started = False
        # 已接纳请求：从"拿到在飞名额（含还在等信号量的排队者）"到"交付完成"
        # 之间的请求。close 的旧契约是等它们自然跑完，所以必须在**拿到名额之前**
        # 登记 —— 只数 native 在飞会把排队者漏掉，它们醒来时只会被 `_closed` 拒绝。
        self._accepted: set[asyncio.Task] = set()
        self._accepted_drained: asyncio.Event | None = None

    # ------------------------------------------------------------------ #
    # 已接纳请求的登记（close 排空语义的基础）
    # ------------------------------------------------------------------ #
    def _accept(self) -> asyncio.Task | None:
        """把当前任务登记为"已接纳"；返回登记句柄（无处登记时返回 ``None``）。

        登记必须在**等待在飞名额之前**完成：还在 ``async with limit`` 上排队的请求
        同样是"已接纳"，close 必须等它。``close()`` 置位后本函数返回 ``None``，
        调用方据此拒绝新请求。
        """
        if self._closing:
            return None
        task = asyncio.current_task()
        if task is None:
            return None                    # 无任务上下文（不应发生）：不参与排空
        self._accepted.add(task)
        return task

    def _release_accepted(self, task: asyncio.Task | None) -> None:
        """请求交付完成（或被取消）：注销登记并在排空时唤醒 close。"""
        if task is None:
            return
        self._accepted.discard(task)
        if not self._accepted and self._accepted_drained is not None:
            self._accepted_drained.set()

    @property
    def _closing(self) -> bool:
        """是否已进入关闭流程（新请求一律拒绝）。"""
        return self._close_started or self._closed

    async def __aenter__(self) -> "AsyncSession":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    # request / get / post / put / patch / delete / head / options
    # 由 `_facade.AsyncSessionShortcuts` 提供，统一转到这里。

    # ------------------------------------------------------------------ #
    # 驱动与限流
    # ------------------------------------------------------------------ #
    @property
    def driver_mode(self) -> str:
        """当前生效的异步驱动：``thread``（专职线程）或 ``loop``（挂在事件循环）。"""
        return self._driver.mode if self._driver is not None else "unstarted"

    def _async_context(self):
        """取出（首次则创建）绑定到当前事件循环的驱动与全局限流信号量。"""
        loop = asyncio.get_running_loop()
        driver = self._driver
        if driver is None:
            if self._closing:
                # 只拦"新请求"：已接纳的排队请求在驱动已经建好的情况下不会走到
                # 这里；会话从来没发过请求却还在排队是不可能的。
                raise NbCurlError("Session 已关闭")
            driver = AsyncDriver(self, loop)
            self._driver = driver
            self._async_driver = driver      # 基类 close() 用的是同一个引用
            self._async_limit = asyncio.Semaphore(self.max_clients)
        elif driver.loop is not loop:
            raise NbCurlError(
                "AsyncSession 必须始终在同一个事件循环里使用"
                "（驱动已绑定到另一个 loop）")
        return driver, self._async_limit

    # ------------------------------------------------------------------ #
    # 请求
    # ------------------------------------------------------------------ #
    async def _request_async(self, method: str, url: str, **options: Any) -> Response:
        """异步执行一次请求。

        非流式走 multi 驱动；流式走会话级专职 reactor（见模块说明）。
        两者共用 ``Session`` 的 prepare / configure / finish / retry 阶段。
        """
        check_options("请求", options, REQUEST_KEYS)
        if self._closing:
            raise NbCurlError("Session 已关闭")

        prep = self._prepare(method, _merge_url(url, options.get("params")), options)
        tcp_profile = self._build_tcp(options, prep)

        driver, limit = self._async_context()
        # 登记必须早于等名额：排队的请求也是"已接纳"，close 要等它们跑完。
        # 关闭已经开始 -> ``accepted is None``，拒绝。
        accepted = self._accept()
        if accepted is None:
            raise NbCurlError("Session 已关闭")

        try:
            if prep.stream:
                return await self._request_stream_async(prep, tcp_profile, limit)
            return await self._request_nonstream_async(
                prep, tcp_profile, driver, limit)
        finally:
            self._release_accepted(accepted)

    async def _request_nonstream_async(self, prep: Any, tcp_profile: Any,
                                       driver: Any, limit: Any) -> Response:
        """非流式请求：进 multi 驱动，等它交付。"""
        async with limit:
            # 注意：这里**不能**用 ``_closed`` 判断。排队中的请求是"已接纳"的，
            # 它等到名额时 ``Session.close`` 可能已经把 ``_closed`` 置起（资源回收
            # 发生在排空**之后**，但状态位是先置的）—— 用 ``_closed`` 等于把排队者
            # 当成新请求掐掉。是否新请求已在 :meth:`_request_async` 入口判定过了。
            pool, handle, staged = self._acquire_configured(prep, tcp_profile)
            tr = driver.submit(prep, tcp_profile, pool, handle, staged)
            try:
                await tr.future
            except asyncio.CancelledError:
                # 取消 await **不等于**取消 native 传输：必须让驱动把它从 multi
                # 里移出去并释放句柄 —— 而且**必须等它真的收尾**再让出在飞配额，
                # 否则下一个请求会在 pool.acquire() 上把事件循环堵住（native 还
                # 攥着句柄时池是满的）。等待本身是异步的，不阻塞 loop。
                #
                # 第二次（甚至更多次）cancel() 不能打破这个等待：那时配额还没还，
                # 提前传播取消就等于把"池已满"的状态丢给下一个请求去撞。
                driver.cancel(tr)
                waiter = driver.wait_finished(tr)
                while waiter is not None and not waiter.done():
                    try:
                        await asyncio.shield(waiter)
                    except asyncio.CancelledError:
                        continue        # 只重复取消，收尾完成后再传播
                raise
            return async_result_to_response(self, tr)

    async def _request_stream_async(self, prep: Any, tcp_profile: Any,
                                    limit: Any) -> Response:
        """流式请求：提交给会话级专职 reactor（每 Session 至多 1 个线程），
        等到响应头就返回。

        返回的 :class:`Response` 挂着 :class:`_StreamBody` 读取器：同步的
        ``content`` / ``iter_content()`` 在事件循环里直接调用只会阻塞调用者线程
        （reactor 独立推进，不死锁）；``aiter_content()`` 每挂起一次一个 Future。

        响应/读取器**先在事件循环线程里建好**（构造时即登记进 ``session._streams``），
        因此"响应头还没到就取消 / 会话关闭"也能被及时中止。
        """
        async with limit:
            response, reader = self._stream_reader(prep)
            if tcp_profile is not None:
                self._warn_stream_tcp(tcp_profile)
            try:
                # 等头就绪是异步的（reactor 经 call_soon_threadsafe 唤醒 Future）
                reactor = self._reactor_for_streams()
                reactor.submit(reader, tcp_profile)
                await reader.wait_ready_async()
            except BaseException:
                # 取消 / 异常 / 关闭：立刻中止这条流（含"还没收到响应头"的阶段）
                reader.abort()
                raise
            return response

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #
    async def close(self) -> None:
        """关闭会话（幂等、并发共享同一收尾；旧契约排空语义）。

        旧版（python/nb_curl/aio.py close）是"先等 executor 所有在飞/排队请求
        结束，再关 Session"。本实现恢复同一契约（见 reports/close-compatibility-decision.md）：

        1. 原子标记 closing：之后的新请求立刻被拒；**已被接纳**的普通非流请求
           不被中止，等它们自然结束（各自 timeout / 用户 cancel 仍有效）。
        2. 等待是**异步**的（每轮 ``await asyncio.sleep`` 让 loop 其它任务继续
           跑、驱动线程继续推进 native），绝不阻塞事件循环。
        3. 在飞清空之后才做最终收尾：停 reactor / 关驱动 / 关池（该收尾转给
           ``to_thread``，也不堵 loop）。返回的流式请求体由 Session.close 中止
           （旧语义：头就绪后 executor 已退出，正文归 close 中止）。
           ``graceful_close``（默认开）时这一步**等驱动把残留连接关完**再关池：
           连接释放与 easy_cleanup 并发会让 libcurl 直接 close（有未读字节就是 RST）。
        4. 并发 close 共享同一个收尾任务（幂等）；发起方对收尾任务 cancel 并不会
           让 native 资源失去最终 owner —— 收尾任务内部 shield。
        5. 用户 task.cancel()：finally 里**先**等 native 收尾（cancel 意图已发、
           驱动会释放句柄），**再**传播 CancelledError。
        """
        # 幂等 + 并发共享：第一个 close 建收尾任务，后来的都等同一个任务。
        #
        # 关闭位**同步**置起（不等收尾任务被调度）：这样 close() 与随后的新请求
        # 之间没有"窗口"，不会出现"close 已发起但请求还被接受"的竞态。
        #
        # ``_close_started`` 只表示"不再接受新请求"；``_closed``（资源已回收）
        # 由 :meth:`_close_drain_and_finalize` 在排空之后才置起 —— 两者分开正是
        # 为了让已接纳的排队请求能跑完。
        task = self._close_task
        if task is None or task.done():
            self._close_started = True
            task = asyncio.ensure_future(self._close_drain_and_finalize())
            self._close_task = task
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            # close 的调用方被取消：native 收尾继续由收尾任务负责（shield 保证
            # 它不被连带取消），这里只把取消传播给调用方。
            raise

    async def _close_drain_and_finalize(self) -> None:
        """旧契约收尾：先排空已接纳请求，再关 stream/driver/pool。"""
        # 1) 等**已接纳**的请求自然跑完（含还在等 ``max_clients`` 名额的排队者）。
        #
        #    关键：旧契约是 ``executor.shutdown(wait=True)`` —— 排队中的任务同样
        #    会被执行完。所以这里等的是请求级登记（``_accepted``），不是 native
        #    在飞数（后者看不到排队的任务，会提前进入收尾把它们掐掉）。
        self._accepted_drained = asyncio.Event()
        while self._accepted:
            self._accepted_drained.clear()
            # 双重检查：clear() 之后可能有任务刚好注销完（此时 Event 已被 set）。
            if not self._accepted:
                break
            await self._accepted_drained.wait()
        # 2) 驱动侧再确认一次（native 已交付的请求此刻一定不在 multi 里）。
        driver = self._async_driver
        while driver is not None and driver.inflight_count() > 0:
            await asyncio.sleep(_CLOSE_DRAIN_POLL_S)
        # 3) 最终收尾：流式正文按旧语义由 close 中止（头就绪后旧版 executor 已
        #    退出，正文归 close 中止）；停 reactor / 驱动 / 池都放到线程池线程上
        #    做有界等待 —— 不堵事件循环。
        await asyncio.to_thread(self._finalize_native)

    def _finalize_native(self) -> None:
        """native 最终收尾（线程池线程）：Session.close 的全部尾段。

        ``Session.close()`` 内部会把 ``_stream_reactor`` / ``_async_driver`` 置空
        并**自己**等它们的 owner 线程退出，所以这里必须在调用**之前**取到引用：
        调用后再读这两个属性只会得到 ``None``（那是"已收尾"的正常表现，不是漏收尾）。
        """
        reactor = self._stream_reactor
        driver = self._async_driver
        try:
            Session.close(self)     # 停驱动/收流/关池（幂等；_closed 已置位）
        except Exception:  # noqa: BLE001
            pass
        # Session.close 已经等过；这里只在"它有界等待超时"时再补一次有界等待。
        if reactor is not None:
            try:
                reactor.wait_closed(_STREAM_REACTOR_GRACE)
            except Exception:  # noqa: BLE001
                pass
        if driver is not None:
            try:
                driver.wait_closed(_STREAM_REACTOR_GRACE)
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    def _join_owners(reactor: Any, driver: Any) -> None:
        if reactor is not None:
            try:
                reactor.wait_closed(5.0)
            except Exception:  # noqa: BLE001
                pass
        if driver is not None:
            try:
                driver.wait_closed(5.0)
            except Exception:  # noqa: BLE001
                pass

    def __del__(self) -> None:  # pragma: no cover - 兜底
        """析构只发"取消意图"：不与驱动线程同时 free 任何 multi/easy。"""
        try:
            self._close_abandoned()
        except Exception:  # noqa: BLE001
            pass

    def __repr__(self) -> str:
        return "<AsyncSession impersonate=%r pools=%d driver=%s>" % (
            self.impersonate, len(self._pools), self.driver_mode)
