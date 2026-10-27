"""nb_curl._multi —— 异步非流式请求的 native multi 驱动

旧实现是"按并发数扩张的线程池 + 阻塞的 ``easy_perform``"：每个在飞请求占一个
Python 线程。本模块改成"一个会话一个有界驱动 + libcurl multi"：非流式异步请求
不再有每请求线程，连接复用/重定向/解压/cookie 仍由 libcurl 负责，Python 只做
状态机与结果装配，prepare/configure/finish/retry 与同步路径**共用** ``Session``
的同一批阶段函数。

分区隔离：libcurl 的连接缓存属于 ``CURLM*``，只隔离 easy 池不足以阻止"连接身份
不同"的请求复用彼此的连接，所以每个连接分区持有自己的 ``nb_multi``。

唯一所有者线程：一个 multi（及放进它的每个 easy）只有一个所有者线程。Windows 的
Proactor 循环没有 ``add_reader``，默认走 ``thread`` 模式（专职线程 + socketpair
唤醒）；POSIX 上若循环支持 ``add_reader`` 则用 ``loop`` 模式挂在调用方循环上。
绝不改用户的事件循环策略，也不做忙轮询（等待时长由 libcurl 定时器决定，另有 1s
上限兜底）。流式 ``stream=True`` 不走本模块（见 :mod:`nb_curl.aio`）。

收尾约定（正确性关键）：

1. ``_settle`` 是**唯一**交付点；thread 模式一律经 ``loop.call_soon_threadsafe``，
   绝不在驱动线程上直接 ``Future.set_result``。交付的 transfer 一定带完整收尾
   信息，中止/失败路径交付明确异常，绝不变成"成功空正文"。
2. ``_finish_transfer`` 检查 ``multi_remove`` 返回码：remove 失败说明 libcurl 状态
   不确定，整个分区作废，句柄不复用。
3. 定时器用**单调绝对 deadline**，剩余毫秒每次由 native 现算
   （``curl_multi_timeout``）—— 不靠"相对值没变"猜，libcurl 对同一个 multi 用
   相同相对值给出的是**新**到期点。
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from typing import Any

from ._native import lib
from ._stream_core import (
    MAX_DRIVE_PASSES,
    NB_CSELECT_IN,
    NB_CSELECT_OUT,
    WAIT_CAP_MS,
    PollCore,
)
from .const import CURLINFO_RESPONSE_CODE
from .exceptions import NbCurlError, RequestError
from .session import _Prep, _Retry, _build_response

__all__ = ["AsyncDriver", "driver_mode"]


def _noop(*_args: Any) -> None:
    """loop 能力探测用的空回调。"""
    return None


def driver_mode(requested: str | None = None) -> str:
    """选定驱动实现：``loop``（挂在事件循环上）或 ``thread``（专职线程）。

    默认：Windows 一律 ``thread``（Proactor 没有 ``add_reader``）；其余平台优先
    ``loop``。可用 ``NB_CURL_ASYNC_DRIVER=thread|loop`` 显式覆盖（两种路径都能测）。
    """
    pref = (requested or os.environ.get("NB_CURL_ASYNC_DRIVER") or "auto").strip().lower()
    if pref in ("thread", "loop"):
        return pref
    if pref not in ("auto", ""):
        raise ValueError(
            "NB_CURL_ASYNC_DRIVER 只能是 auto / thread / loop，实际 %r" % pref)
    return "thread" if os.name == "nt" else "loop"


class _Transfer:
    """一次异步请求的完整状态（在飞期间由驱动持有）。"""

    __slots__ = (
        "prep", "tcp_profile", "retry", "future", "loop", "pool", "handle",
        "partition", "rcvbuf_plan", "tcp_switched",
        "cancel_requested", "finished", "settled", "finish_waiter",
        "code", "error", "status",
        "body", "raw_headers", "info", "cookie_dump", "wall", "started",
    )

    def __init__(self, prep: _Prep, tcp_profile: Any, retry: _Retry,
                 future: Any, loop: Any):
        self.prep = prep
        self.tcp_profile = tcp_profile
        self.retry = retry
        self.future = future
        self.loop = loop
        self.pool: Any = None
        self.handle: Any = None
        self.partition: Any = None
        self.rcvbuf_plan: int | None = None
        self.tcp_switched = False
        self.cancel_requested = False
        self.finished = False          # 收尾流程只走一次
        self.settled = False           # 已经交付（future / 等待者都处理过了）
        self.finish_waiter: Any = None  # 取消方用来等 native 真正收尾的 future
        self.code = 0
        self.error: str | None = None
        self.status = 0
        self.body = b""
        self.raw_headers = b""
        self.info: Any = None
        self.cookie_dump = ""
        self.wall = 0.0                # 累计墙钟（含重试）
        self.started = 0.0


class _Partition:
    """一个连接分区：一个 ``nb_multi`` + 该分区的连接池。

    ``timer_at`` 是 libcurl 定时器换算出的**单调绝对**到期点；剩余毫秒每次都由
    native 现算（``curl_multi_timeout``），所以无关的 socket 事件既不会推迟它，
    也不会让 Python 拿旧值猜出一个已经过去的到期点。
    """

    __slots__ = ("key", "multi", "transfers", "by_easy", "broken", "timer_at")

    def __init__(self, key: tuple, multi: Any):
        self.key = key
        self.multi = multi
        self.transfers: set[_Transfer] = set()
        self.by_easy: dict[Any, _Transfer] = {}
        self.broken = False
        self.timer_at: float | None = None   # 单调绝对到期点


class AsyncDriver(PollCore):
    """一个 :class:`AsyncSession` 的 multi 驱动。

    所有 multi / socket-action / timer 调用都发生在**唯一所有者**上下文里：
    ``thread`` 模式是驱动线程，``loop`` 模式是事件循环线程。只有
    :meth:`submit` / :meth:`cancel` / :meth:`close` 允许从事件循环线程调用。

    "怎么等"（唤醒管道 / fd 差分 / timer 到期点 / 一轮 poll 派发）与流式 reactor
    共用 :class:`nb_curl._stream_core.PollCore`；这里只保留驱动自身的东西：
    loop 模式的事件循环注册、传输状态机与结果交付。
    """

    def __init__(self, session: Any, loop: Any, mode: str | None = None):
        super().__init__(session)
        self.loop = loop
        self.mode = driver_mode(mode)
        self._pending: list[_Transfer] = []
        self._cancelled: list[_Transfer] = []
        self._parts: dict[tuple, _Partition] = {}
        # loop 模式另有真实注册集
        self._read_fds: set[int] = set()
        self._write_fds: set[int] = set()
        self._timer_handle: Any = None
        self._round_handle: Any = None
        # loop 能力探测结果（None = 还没探过）
        self._loop_ok: bool | None = None
        self._loop_hint = ""

    # ================================================================== #
    # 提交 / 取消 / 关闭（事件循环线程调用）
    # ================================================================== #
    def submit(self, prep: _Prep, tcp_profile: Any, pool: Any, handle: Any,
               staged: tuple) -> _Transfer:
        """把一个**已经配置好**的句柄交给驱动，返回 :class:`_Transfer`。

        句柄的获取与配置在调用方线程完成（可能阻塞在池上限上，这正是排队语义），
        驱动线程只做 multi 记账 —— 所以驱动永远不会因为"等池"而卡住所有请求。
        调用方 ``await tr.future``；``tr`` 同时是取消时要传回 :meth:`cancel` 的凭据。

        本函数**不持有**句柄的所有权：任何一条失败路径都会把句柄 ``discard``，
        绝不留下"配置了一半又没人管"的句柄。
        """
        try:
            if self._stopping or self._shut:
                raise NbCurlError("Session 已关闭")
            if not self._same_loop():
                raise NbCurlError(
                    "AsyncSession 必须始终在同一个事件循环里使用"
                    "（本次请求来自另一个 loop）")
            if self.mode == "loop":
                self._require_loop_capable()

            retry = _Retry(self._session, prep)  # 与同步路径同一套重试判定
            tr = _Transfer(prep, tcp_profile, retry,
                           self.loop.create_future(), self.loop)
            tr.pool = pool
            tr.handle = handle
            tr.rcvbuf_plan, tr.tcp_switched = staged
            lib.easy_set_fresh_connect(
                handle.ptr, 1 if retry.fresh_connect(tr.tcp_switched) else 0)
            if lib.prepare_request(handle.ptr) != 0:
                raise NbCurlError("native 准备请求失败（easy_prepare_request）")
            if self.mode == "thread":
                self._ensure_thread()   # 已停机就不起线程 -> 走 except 丢弃句柄
        except BaseException:
            pool.discard(handle)              # 半配置句柄绝不进池
            raise

        with self._lock:
            orphan = self._shut
            if not orphan:
                self._pending.append(tr)
        if orphan:
            # 与 close() 赛跑输了：没有线程会来接它，就地确定失败
            self._fail_transfer(tr, NbCurlError("Session 已关闭"))
            return tr
        if self.mode == "thread":
            self._wake()
        else:
            self._owner_tid = threading.get_ident()
            if self._round_handle is None:
                self._round_handle = self.loop.call_soon(self._round)
        return tr

    def cancel(self, tr: _Transfer) -> None:
        """撤销一次在飞传输（调用方任务被取消时）。

        cancel 掉 future **不等于**撤销 native 传输：必须真的把它从 multi 里移出
        并释放句柄，否则连接与句柄会一直挂在 multi 上。
        """
        tr.cancel_requested = True
        if tr.finished:
            return
        with self._lock:
            self._cancelled.append(tr)
        if self.mode == "thread":
            self._wake()
            return
        if self._owner_tid == threading.get_ident():
            self._round()
            return
        try:
            self.loop.call_soon_threadsafe(self._round)
        except RuntimeError:      # 循环已关闭
            pass

    def wait_finished(self, tr: _Transfer) -> Any:
        """返回一个"native 侧真的收尾了"的 future（已经收尾则返回 ``None``）。

        取消 await **不等于**释放配额：在 native 把句柄从 multi 摘掉并销毁之前
        释放 ``AsyncSession`` 的在飞名额，下一个请求就会在 ``pool.acquire()`` 上
        把**调用方事件循环**堵住。所以取消路径用这个 future 异步等待，而不是
        阻塞等待。future 永远以结果收尾（异常由 ``tr.future`` 那条路径负责）。
        """
        with self._lock:
            if tr.settled:
                return None
            fut = self.loop.create_future()
            tr.finish_waiter = fut
        return fut

    def inflight_count(self) -> int:
        """当前 native 在飞（multi 里还挂着 / 已配置待装填）的传输数。

        close 排空语义（旧契约）靠它判断"已接纳请求是否全部落地"：只统计
        native 侧还活着的，已交付（含失败）的不再算。
        """
        with self._lock:
            n = len(self._pending)
        for part in self._parts.values():
            if not part.broken:
                n += len(part.transfers)
        return n

    def close(self, wait: bool = False) -> None:
        """停机：只发"停止 + 取消"意图并唤醒，真正的释放由所有者线程完成。

        这样析构路径（``__del__``）不会在事件循环还在跑时与驱动同时 free 同一个
        multi / easy。从未启动过驱动线程的会话（只有唤醒管道）在这里就地收尾，
        否则那对 socket 就泄漏了。
        """
        self._stopping = True
        if self.mode == "thread":
            if self._driver_thread is None:
                self._shutdown_owned()     # 没有所有者线程：本线程就是所有者
            else:
                self._wake()
        elif self._owner_tid == threading.get_ident() or self._owner_tid is None:
            self._shutdown_owned()
        else:
            try:
                self.loop.call_soon_threadsafe(self._shutdown_owned)
            except RuntimeError:
                pass
        if wait:
            self.wait_closed()

    # ================================================================== #
    # 唤醒管道与事件循环绑定
    # ================================================================== #
    def _same_loop(self) -> bool:
        """确认仍在同一个事件循环里（AsyncSession 不跨循环使用）。"""
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            return True
        return running is self.loop

    def _require_loop_capable(self) -> None:
        """loop 模式的前置条件：事件循环必须支持 add_reader。

        Windows 默认的 Proactor 循环**没有** add_reader。这里明确报错并给出两条
        可行路径，而不是悄悄退回线程驱动 —— 回退会让"我选了 loop 驱动"变成谎话。
        我们也不会替用户改全局事件循环策略。
        """
        if self._loop_ok is True:
            return
        if self._loop_ok is False:
            raise NbCurlError(self._loop_hint)
        try:
            self.loop.add_reader(self._wake_r.fileno(), _noop)
            self.loop.remove_reader(self._wake_r.fileno())
        except (AttributeError, NotImplementedError, ValueError, OSError):
            self._loop_ok = False
            self._loop_hint = (
                "当前事件循环不支持 add_reader（Windows 的 Proactor 循环就是如此），"
                "无法使用 loop 驱动。\n"
                "  可做：设 NB_CURL_ASYNC_DRIVER=thread 用有界专职驱动；"
                "或在**你自己的**代码里换用 SelectorEventLoop"
                "（asyncio.set_event_loop_policy(WindowsSelectorEventLoopPolicy())）"
                "——本库不会替你改全局循环策略。")
            raise NbCurlError(self._loop_hint)
        self._loop_ok = True

    # ================================================================== #
    # thread 模式：专职驱动线程
    # ================================================================== #
    def _ensure_thread(self) -> None:
        super()._ensure_thread("nb-curl-multi")

    # ================================================================== #
    # loop 模式：挂到调用方事件循环
    # ================================================================== #
    def _remove_reader(self, fd: int) -> None:
        if fd not in self._read_fds:
            return
        self._read_fds.discard(fd)
        try:
            self.loop.remove_reader(fd)
        except Exception:  # noqa: BLE001 - 循环已关 / fd 已失效
            pass

    def _remove_writer(self, fd: int) -> None:
        if fd not in self._write_fds:
            return
        self._write_fds.discard(fd)
        try:
            self.loop.remove_writer(fd)
        except Exception:  # noqa: BLE001
            pass

    def _on_readable(self, fd: int) -> None:
        if self._shut:
            return
        part = self._fd_part.get(fd)
        if part is None or part.broken:
            return
        self._socket_action(part, fd, NB_CSELECT_IN)
        # 事件回调之后必须完整跑一轮：收完成队列 + 重算等待集合。
        # loop 模式没有"驱动线程的循环"，漏掉这一步就再也不会推进（会静默挂住）。
        self._round()

    def _on_writable(self, fd: int) -> None:
        if self._shut:
            return
        part = self._fd_part.get(fd)
        if part is None or part.broken:
            return
        self._socket_action(part, fd, NB_CSELECT_OUT)
        self._round()

    def _on_timer(self) -> None:
        if self._shut:
            return
        self._timer_handle = None
        self._fire_due_timers()
        self._round()

    def _apply_socket(self, fd: int, ev: int) -> None:
        if self.mode != "loop":
            return
        if ev & NB_CSELECT_IN:
            if fd not in self._read_fds:
                self.loop.add_reader(fd, self._on_readable, fd)
                self._read_fds.add(fd)
        else:
            self._remove_reader(fd)
        if ev & NB_CSELECT_OUT:
            if fd not in self._write_fds:
                self.loop.add_writer(fd, self._on_writable, fd)
                self._write_fds.add(fd)
        else:
            self._remove_writer(fd)

    def _apply_waits(self, now: float, want: dict[int, int]) -> None:
        if self.mode != "loop":
            return
        if self._timer_handle is not None:
            self._timer_handle.cancel()
            self._timer_handle = None
        at = self._next_timer_at()
        if at is not None:
            delay = min(max(0.0, at - now), WAIT_CAP_MS / 1000.0)
            self._timer_handle = self.loop.call_later(delay, self._on_timer)

    def _clear_loop_waits(self) -> None:
        if self.mode != "loop":
            return
        for fd in list(self._read_fds):
            self._remove_reader(fd)
        for fd in list(self._write_fds):
            self._remove_writer(fd)
        self._fd_actions.clear()
        self._fd_part.clear()
        if self._timer_handle is not None:
            self._timer_handle.cancel()
            self._timer_handle = None

    # ================================================================== #
    # 所有者线程：推进 / 完成 / 收尾
    # ================================================================== #
    def _round(self) -> None:
        """驱动一轮：装填新请求 → 触发到期 timer → 收完成 → 刷新等待集合。"""
        if self._round_handle is not None:
            self._round_handle.cancel()
            self._round_handle = None
        if self._shut:
            return
        if self._stopping:
            # 停机：在飞传输也要立即撤销（不能等它们自然传完）
            for part in list(self._parts.values()):
                if part.broken:
                    continue
                for tr in list(part.transfers):
                    self._abort_transfer(tr)
            if self._shut:
                return
        for _ in range(MAX_DRIVE_PASSES):
            self._attach_pending()
            if self._shut:
                return
            self._fire_due_timers()
            self._drain_completions()
            # 连接复用失败的自适应重试会把 transfer 重新入队；同一轮里立刻再装填，
            # 别等"下一次事件"—— loop 模式下此刻可能已经没有任何 fd/timer 了。
            if self._shut or not self._pending:
                break
        self._refresh_waits()

    def _partition_for(self, key: tuple) -> _Partition:
        part = self._parts.get(key)
        if part is None or part.broken:
            multi = lib.multi_init()
            if not multi:
                raise NbCurlError("nb_multi_init() 失败：无法创建 multi 句柄")
            part = _Partition(key, multi)
            self._parts[key] = part
        return part

    def _attach_pending(self) -> None:
        with self._lock:
            items, self._pending = self._pending, []
        added = set()
        for tr in items:
            if tr.finished:
                continue
            if tr.cancel_requested or self._stopping:
                self._abort_transfer(tr)
                continue
            try:
                part = self._partition_for(tr.prep.key)
            except Exception as exc:  # noqa: BLE001
                self._fail_transfer(tr, exc)
                continue
            tr.partition = part
            rc = lib.multi_add(part.multi, tr.handle.ptr)
            if rc != 0:
                self._fail_transfer(tr, NbCurlError(
                    "把请求加入 multi 失败（multi_add=%d）" % rc))
                continue
            part.transfers.add(tr)
            part.by_easy[tr.handle.ptr] = tr
            tr.started = time.perf_counter()
            added.add(part)
        for part in added:
            self._kick(part)

        with self._lock:
            cancelled, self._cancelled = self._cancelled, []
        for tr in cancelled:
            self._abort_transfer(tr)

    def _drain_completions(self) -> None:
        """排空完成队列。

        **顺序很关键**：先把完成消息（含 CURLcode）读出来保存，再 remove，
        最后才读结果 / 回收句柄 —— 否则消息随 remove 一起丢掉，结果也就无从判断。
        """
        for part in list(self._parts.values()):
            if part.broken:
                continue
            while True:
                item = lib.multi_drain(part.multi)
                if item is None:
                    break
                _msg, code, easy = item
                tr = part.by_easy.get(easy)
                if tr is None:
                    continue
                self._finish_transfer(tr, code)
                if part.broken or self._shut:
                    break

    def _finish_transfer(self, tr: _Transfer, code: int) -> None:
        if tr.finished:
            return
        part = tr.partition
        session = self._session
        if tr.started:
            tr.wall += max(0.0, time.perf_counter() - tr.started)
            tr.started = 0.0

        # 1) 完成消息里的 code 已由 _drain_completions 读出 -> 2) 移出 multi
        if part is not None and not part.broken and tr.handle is not None:
            rc = lib.multi_remove(part.multi, tr.handle.ptr)
            if rc != 0:
                # remove 失败 = libcurl 状态不确定：句柄既不能读结果也不能复用，
                # 整个分区作废（它仍在 part.transfers 里，会被统一确定失败）。
                self._break_partition(part, rc)
                return
            part.transfers.discard(tr)
            part.by_easy.pop(tr.handle.ptr, None)
        tr.finished = True
        tr.code = int(code)

        # 3) 读结果：body/headers 走"所有权移交"，只复制一次到 Python bytes
        try:
            tr.body = lib.take_body(tr.handle.ptr)
            tr.raw_headers = lib.take_headers(tr.handle.ptr)
            tr.status = lib.getinfo_long(tr.handle.ptr, CURLINFO_RESPONSE_CODE) or 0
        except Exception as exc:  # noqa: BLE001
            self._discard_failed(tr, "读取 native 结果失败: %r" % (exc,))
            return
        tr.error = None if tr.code == 0 else lib.strerror(tr.code)

        # 4) 收尾读数 + TCP 回读校验（都在所有者线程上，句柄已不在 multi 里）
        try:
            session._verify_tcp(tr.handle, tr.code, tr.tcp_profile, tr.rcvbuf_plan)
            tr.info, tr.cookie_dump = session._collect_result(tr.handle, tr.prep)
        except Exception as exc:  # noqa: BLE001
            # 收尾失败**不能**降级成"成功空正文"：句柄状态已不确定，弃掉并真实失败。
            self._discard_failed(tr, "收尾读数失败: %r" % (exc,))
            return

        cancelled = tr.cancel_requested
        # 5) 句柄回收：取消/停机时销毁，否则归还池
        self._release_handle(tr, discard=cancelled)

        # 6) 连接复用失败的自适应重试（与同步路径同一套判定）
        if (not cancelled and not self._stopping and tr.code != 0
                and tr.retry.on_failure(session, tr.code, tr.prep.url)
                and self._retry_transfer(tr)):
            return

        self._settle(tr, None)

    def _discard_failed(self, tr: _Transfer, message: str) -> None:
        """收尾阶段失败的统一出口：句柄丢弃（**绝不复用**）+ 明确交付异常。"""
        tr.finished = True
        tr.error = message
        self._release_handle(tr, discard=True)
        self._settle(tr, RequestError(message))

    def _retry_transfer(self, tr: _Transfer) -> bool:
        """换一只干净句柄重投一次（连接复用失败专用路径）。

        这里不会阻塞在池上限上：本 transfer 的旧句柄刚被归还/销毁，而池的容量是
        ``max_clients``、在飞请求数 ≤ ``max_clients`` —— 池里必然还有一个名额。
        """
        try:
            tr.handle = tr.pool.acquire()
        except Exception:  # noqa: BLE001 - 池已关闭 / 建句柄失败：放弃重试
            tr.handle = None
            return False
        try:
            staged = self._session._configure(tr.handle, tr.prep, tr.tcp_profile)
            tr.rcvbuf_plan, tr.tcp_switched = staged
            lib.easy_set_fresh_connect(tr.handle.ptr, 1)
            if lib.prepare_request(tr.handle.ptr) != 0:
                raise NbCurlError("native 准备请求失败（重试）")
        except BaseException:  # noqa: BLE001
            tr.pool.discard(tr.handle)
            tr.handle = None
            return False
        # 新的一次尝试：清掉"已收尾"标记，重新排队（future 不变，只交付一次）
        tr.finished = False
        tr.code = 0
        tr.error = None
        tr.partition = None
        with self._lock:
            self._pending.append(tr)
        return True

    def _abort_transfer(self, tr: _Transfer, exc: BaseException | None = None) -> None:
        """取消 / 停机：先移出 multi，再释放句柄，**只收尾一次**。"""
        if tr.finished:
            return
        tr.finished = True
        part = tr.partition
        if part is not None and not part.broken and tr.handle is not None:
            rc = lib.multi_remove(part.multi, tr.handle.ptr)
            if rc != 0:
                # remove 失败 = libcurl 状态不确定：句柄/连接都不能复用。
                # 分区作废（其中还包括本 tr，会走统一失败路径），不再继续。
                self._break_partition(part, rc)
                return
            part.transfers.discard(tr)
            part.by_easy.pop(tr.handle.ptr, None)
        if tr.handle is not None:
            # 被中止的传输不能复用它的连接（响应可能只读了一半）：
            # 把 C 缓冲取走丢掉（所有权移交 = 不会泄漏），再销毁句柄。
            try:
                lib.take_body(tr.handle.ptr)
                lib.take_headers(tr.handle.ptr)
            except Exception:  # noqa: BLE001
                pass
            self._release_handle(tr, discard=True)
        if exc is None:
            exc = (asyncio.CancelledError() if tr.cancel_requested
                   else NbCurlError("Session 已关闭"))
        self._settle(tr, exc)

    def _fail_transfer(self, tr: _Transfer, exc: BaseException) -> None:
        """单条传输失败（add 失败等）：句柄销毁，future 收到异常。"""
        if tr.finished:
            return
        tr.finished = True
        if tr.handle is not None:
            self._release_handle(tr, discard=True)
        self._settle(tr, exc)

    def _break_partition(self, part: _Partition, rc: int) -> None:
        """multi 出错：统一失败该分区所有在飞任务，并且**不再使用这个 multi**。"""
        if part.broken:
            return
        part.broken = True
        self._forget_sockets(part)
        transfers = list(part.transfers)
        part.transfers.clear()
        part.by_easy.clear()
        self._parts.pop(part.key, None)
        # 顺序：先逐个 remove（把 easy 从 multi 摘出去），再 cleanup ——
        # 直接 cleanup 一个还挂着 easy 的 multi 会把"谁拥有句柄"弄乱。
        for tr in transfers:
            if tr.handle is not None:
                try:
                    lib.multi_remove(part.multi, tr.handle.ptr)
                except Exception:  # noqa: BLE001
                    pass
        try:
            lib.multi_cleanup(part.multi)
        except Exception:  # noqa: BLE001
            pass
        err = RequestError(
            "libcurl multi 内部错误（CURLMcode=%d）：本次传输已失败，"
            "该分区的 multi 已丢弃" % rc)
        for tr in transfers:
            tr.finished = True
            if tr.handle is not None:
                try:
                    lib.take_body(tr.handle.ptr)
                    lib.take_headers(tr.handle.ptr)
                except Exception:  # noqa: BLE001
                    pass
                self._release_handle(tr, discard=True)
            self._settle(tr, err)

    def _release_handle(self, tr: _Transfer, *, discard: bool) -> None:
        handle = tr.handle
        if handle is None:
            return
        tr.handle = None
        try:
            if discard:
                tr.pool.discard(handle)
            else:
                tr.pool.release(handle)
        except Exception as exc:  # noqa: BLE001
            # 池释放失败是所有权错误（可能静默泄漏句柄），不能无声吞掉：
            # 记录到 transfer 上，调试模式下显式输出，便于定位而不是假装成功。
            tr.error = tr.error or ("句柄归还池失败: %r" % (exc,))
            if self._session.debug:
                print("[nb_curl] 句柄归还池失败: %r" % (exc,))

    # ================================================================== #
    # 交付（唯一入口）
    # ================================================================== #
    def _settle(self, tr: _Transfer, exc: BaseException | None) -> None:
        """把 transfer 交付给事件循环线程 —— **跨线程安全**的唯一交付点。"""
        with self._lock:
            waiter, tr.finish_waiter = tr.finish_waiter, None
            tr.settled = True
        self._post(self._resolve, tr, exc, waiter)

    def _post(self, fn: Any, *args: Any) -> None:
        """在事件循环线程上执行；thread 模式必须经 call_soon_threadsafe。"""
        if self.mode == "thread":
            try:
                self.loop.call_soon_threadsafe(fn, *args)
                return
            except RuntimeError:
                return          # 循环已关闭：没有等待者，收尾状态已经记录在 tr 上
        try:
            fn(*args)
        except RuntimeError:    # 循环已关闭（Future 无法再调度回调）
            pass

    def _resolve(self, tr: _Transfer, exc: BaseException | None, waiter: Any) -> None:
        fut = tr.future
        if fut is not None and not fut.done():
            if exc is not None:
                fut.set_exception(exc)
            else:
                fut.set_result(tr)
        if waiter is not None and not waiter.done():
            # 取消路径只关心"native 真的收尾了"；异常由 fut 那条路径负责，
            # 这里绝不能把 CancelledError 换成别的异常。
            waiter.set_result(tr)

    # ================================================================== #
    # 停机
    # ================================================================== #
    def _shutdown_owned(self) -> None:
        """所有者线程：撤销所有排队/在飞传输并释放所有 multi。幂等。"""
        if self._shut:
            return
        self._shut = True
        self._stopping = True
        err: BaseException = self._fatal or NbCurlError("Session 已关闭")
        with self._lock:
            pend, self._pending = self._pending, []
        for tr in pend:
            if tr.finished:
                continue
            tr.finished = True
            if tr.handle is not None:
                self._release_handle(tr, discard=True)
            self._settle(tr, err)
        for part in list(self._parts.values()):
            for tr in list(part.transfers):
                self._abort_transfer(tr, err)
            if not part.broken:
                try:
                    lib.multi_cleanup(part.multi)
                except Exception:  # noqa: BLE001
                    pass
        self._parts.clear()
        self._clear_loop_waits()
        self._close_wake()


def async_result_to_response(session: Any, tr: _Transfer) -> Any:
    """把收尾好的 transfer 变成 :class:`nb_curl.Response`（在事件循环线程里调用）。

    Cookie 吸收与错误码映射走 :meth:`Session._finish` —— 与同步路径**同一份**语义；
    ``_build_response`` 也是同步路径用的那个函数（含 history / 1xx 过滤）。
    """
    response = _build_response(tr.prep, tr.info, tr.status, tr.body, tr.raw_headers,
                               tr.wall, tr.cookie_dump)
    session._finish(tr.prep, tr.info, tr.cookie_dump, tr.code, tr.error, response)
    return response
