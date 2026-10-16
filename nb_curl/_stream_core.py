"""nb_curl._stream_core —— 线程模式有界驱动内核（非流式驱动与流式 reactor 共用）

为什么单独一层：异步非流式驱动（:mod:`nb_curl._multi`）与流式专职 reactor
（:mod:`nb_curl._stream_reactor`）在"**怎么等**"这件事上完全一样 —— 唤醒管道 +
一次 ``nb_poll_sockets`` + libcurl timer 到点；差别只在"等到了之后怎么收尾"。
把这一层提出来共用，避免出现第二套 poll/timer 逻辑：第二套脆弱逻辑迟早会和
第一套给出不同的到期点判断。

线程契约（两个使用者都必须遵守）：

* 只有**所有者线程**（专职驱动线程）调用 poll / socket_action / fire_timer 等 native；
* 其它线程只允许：写 1 字节到唤醒管道、在锁内改标志位、置取消意图；
* 等待时长由 libcurl timer **现算的剩余毫秒**换算成单调绝对到期点
  （``nb_multi_timer`` = ``curl_multi_timeout``），绝不靠"相对值没变"去猜；
  另加 1s 上限兜底（Windows 的 WSAPoll 对"连接失败"的事件报送有已知缺陷，
  靠它保证最多 1s 必然推进一次）。
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Any

from ._native import lib
from .exceptions import NbCurlError

__all__ = ["PollCore"]

# --- CURL_POLL_*（数值来自 curl/multi.h）与桥接层事件位的映射 ---------------- #
_CURL_POLL_IN = 1
_CURL_POLL_OUT = 2
_CURL_POLL_INOUT = 3

NB_CSELECT_IN = 1
NB_CSELECT_OUT = 2
NB_CSELECT_ERR = 4

_POLL_TO_EV = {
    _CURL_POLL_IN: NB_CSELECT_IN,
    _CURL_POLL_OUT: NB_CSELECT_OUT,
    _CURL_POLL_INOUT: NB_CSELECT_IN | NB_CSELECT_OUT,
}

#: 单次等待上限（毫秒）：libcurl timer 已给出精确唤醒点，这里只是兜底。
WAIT_CAP_MS = 1000

#: 一轮驱动里"装填 -> 收完成 -> 再装填"的最大次数。
MAX_DRIVE_PASSES = 8


class PollCore:
    """线程模式有界驱动内核：唤醒管道 + fd 等待表 + timer 到期点 + 一轮等待/派发。

    需要子类提供的东西（两个使用者的差别全在这里）：

    * ``self._parts``：``{分区键: part}``，part 需有 ``key/multi/transfers/broken/timer_at``；
    * ``self._pending``：待装填队列（``_has_work`` 只看它非空 + 任一分区有在飞）；
    * :meth:`_round`：装填/推进/收完成/刷新等待集合；
    * :meth:`_break_partition`：multi 出错时统一失败该分区；
    * :meth:`_shutdown_owned`：所有者线程的收尾（释放 multi / 交付在飞）。
    """

    def __init__(self, session: Any):
        self._session = session
        self._lock = threading.Lock()
        self._pending: list[Any] = []
        self._parts: dict[Any, Any] = {}
        self._stopping = False
        self._shut = False
        self._fatal: BaseException | None = None
        self._driver_thread: threading.Thread | None = None
        self._owner_tid: int | None = None
        # 唤醒管道：其它线程 -> 所有者线程；也用于打断等待
        self._wake_r, self._wake_w = socket.socketpair()
        self._wake_r.setblocking(False)
        self._wake_w.setblocking(False)
        # fd 等待表：fd -> 事件位、fd -> 分区
        self._fd_actions: dict[int, int] = {}
        self._fd_part: dict[int, Any] = {}
        # 线程创建互斥：多线程同时首次 submit 也只允许建一个 owner 线程
        # （review-poll-core 第 1 条：不能依赖 GIL 保证 check-then-start 原子）
        self._thread_lock = threading.Lock()

    # ================================================================== #
    # 唤醒管道
    # ================================================================== #
    def _wake(self) -> None:
        try:
            self._wake_w.send(b"\x01")
        except OSError:
            pass

    def _drain_wake(self) -> None:
        while True:
            try:
                if not self._wake_r.recv(4096):
                    return
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return

    def _close_wake(self) -> None:
        for sock in (self._wake_r, self._wake_w):
            try:
                sock.close()
            except OSError:
                pass

    # ================================================================== #
    # 专职线程
    # ================================================================== #
    def _ensure_thread(self, name: str) -> None:
        if self._shut:
            raise NbCurlError("Session 已关闭")
        if self._driver_thread is not None:
            return
        # 锁内重新检查：两个线程同时首次提交时只创建一个 owner（GIL 不保证
        # check-then-start 原子，见 review-poll-core 第 1 条）
        with self._thread_lock:
            if self._shut:
                raise NbCurlError("Session 已关闭")
            if self._driver_thread is not None:
                return
            thread = threading.Thread(
                target=self._thread_main, name=name, daemon=True)
            self._driver_thread = thread
        thread.start()

    def _thread_main(self) -> None:
        self._owner_tid = threading.get_ident()
        try:
            while True:
                self._round()
                if self._shut or (self._stopping and not self._has_work()):
                    break
                self._wait()
                if self._shut or (self._stopping and not self._has_work()):
                    break
        except BaseException as exc:  # noqa: BLE001 - 绝不能带着异常退出去而不收尾
            if self._fatal is None:
                self._fatal = exc
            if self._session.debug:
                print("[nb_curl] %s 线程异常退出: %r"
                      % (self._driver_thread.name if self._driver_thread else "驱动", exc))
        finally:
            self._drain_wake()
            self._shutdown_owned()

    def _has_work(self) -> bool:
        with self._lock:
            if self._pending:
                return True
        return any(part.transfers for part in self._parts.values())

    def wait_closed(self, timeout: float = 5.0) -> bool:
        """等所有者线程真的退出；返回是否已退出（供异步 close 异步等待用）。"""
        thread = self._driver_thread
        if thread is None or thread is threading.current_thread():
            return True
        thread.join(timeout)
        return not thread.is_alive()

    # ================================================================== #
    # 等待一次事件
    # ================================================================== #
    def _wait(self) -> None:
        """等一次事件：多路 socket + 唤醒管道，时长取最近一个 libcurl timer。"""
        items: list[tuple[int, int]] = [(self._wake_r.fileno(), NB_CSELECT_IN)]
        items.extend(self._fd_actions.items())
        timeout = self._wait_timeout_ms()
        try:
            ready = lib.poll_sockets(items, timeout)
        except Exception as exc:  # noqa: BLE001 - 系统调用级错误：整个驱动确定失败
            self._fail_driver(NbCurlError(
                "异步驱动等待 socket 事件失败（nb_poll_sockets）：%r" % (exc,)))
            return
        if not ready:
            # 等待超时/兜底上限：让 libcurl 处理一次（早触发无害，它只会重算超时）
            self._fire_due_timers(force=True)
            return
        woke = False
        for fd, revents in ready:
            if fd == self._wake_r.fileno():
                woke = True
                continue
            part = self._fd_part.get(fd)
            if part is None or part.broken:
                continue
            ev = 0
            if revents & NB_CSELECT_IN:
                ev |= NB_CSELECT_IN
            if revents & NB_CSELECT_OUT:
                ev |= NB_CSELECT_OUT
            if revents & NB_CSELECT_ERR:
                ev |= NB_CSELECT_ERR
            if not ev:
                continue
            # 前一个 action 已同步 socket 变更，按最新兴趣过滤本轮事件。
            ev &= self._fd_actions.get(fd, 0) | NB_CSELECT_ERR
            if ev:
                self._socket_action(part, fd, ev)
        if woke:
            self._drain_wake()
        if not self._shut:
            self._fire_due_timers()

    def _wait_timeout_ms(self) -> int:
        """到最近一个 libcurl timer 的毫秒数（绝对 deadline 换算，绝不推迟）。"""
        at = self._next_timer_at()
        if at is None:
            return WAIT_CAP_MS
        delay = int(round((at - time.monotonic()) * 1000.0))
        return max(0, min(delay, WAIT_CAP_MS))

    def _fail_driver(self, exc: BaseException) -> None:
        """驱动级致命错误（例如 poll 系统调用持续失败）：确定失败，绝不静默吞。"""
        if self._fatal is None:
            self._fatal = exc
        if self._session.debug:
            print("[nb_curl] 驱动致命错误: %r" % (exc,))
        self._shutdown_owned()

    # ================================================================== #
    # fd 等待表 / timer
    # ================================================================== #
    def _sync_sockets(self, part: Any) -> None:
        """只传递 libcurl 本轮修改的 socket。"""
        try:
            changes = lib.multi_socket_changes(part.multi)
        except RuntimeError:
            self._break_partition(part, -2)
            return
        for fd, action in changes:
            if action == 4:
                self._apply_socket(fd, 0)
        for fd, action in dict(changes).items():
            ev = _POLL_TO_EV.get(action, 0)
            if ev:
                self._fd_actions[fd] = ev
                self._fd_part[fd] = part
            elif self._fd_part.get(fd) is part:
                self._fd_actions.pop(fd, None)
                self._fd_part.pop(fd, None)
            self._apply_socket(fd, self._fd_actions.get(fd, 0))

    def _forget_sockets(self, part: Any) -> None:
        for fd, owner in list(self._fd_part.items()):
            if owner is part:
                self._fd_part.pop(fd)
                self._fd_actions.pop(fd, None)
                self._apply_socket(fd, 0)

    def _refresh_waits(self) -> None:
        if self._shut:
            return
        now = time.monotonic()
        for part in list(self._parts.values()):
            if part.broken:
                continue
            if lib.multi_active(part.multi) < 0:
                self._break_partition(part, -2)
                continue
            self._sync_timer(part, now)
            self._sync_sockets(part)
        self._apply_waits(now, self._fd_actions)

    def _apply_socket(self, fd: int, ev: int) -> None:
        pass

    def _apply_waits(self, now: float, want: dict[int, int]) -> None:
        pass

    def _next_timer_at(self) -> float | None:
        best: float | None = None
        for part in self._parts.values():
            if part.broken or part.timer_at is None:
                continue
            best = part.timer_at if best is None else min(best, part.timer_at)
        return best

    def _sync_timer(self, part: Any, now: float) -> None:
        """读 libcurl 的**剩余**毫秒并换算成单调绝对到期点。

        native 每次都以"现在"重算剩余量（``curl_multi_timeout``），所以这里可以
        无条件重设 deadline：既不会被无关事件推迟，也不会留下一个已经过去的
        到期点让 loop 每次事件都白触发一次 timer。
        """
        ms = lib.multi_timer(part.multi)
        if ms < 0:
            part.timer_at = None
        elif ms == 0:
            part.timer_at = now
        else:
            part.timer_at = now + ms / 1000.0

    def _fire_due_timers(self, force: bool = False) -> None:
        """触发到期（``force`` 时连未到期的也触发一次，让 libcurl 重算/推进）。"""
        now = time.monotonic()
        for part in list(self._parts.values()):
            if part.broken:
                continue
            at = part.timer_at
            if at is None or not (force or at <= now):
                continue
            rc = lib.multi_fire_timer(part.multi)
            self._sync_timer(part, time.monotonic())
            if rc < 0:
                self._break_partition(part, rc)

    def _socket_action(self, part: Any, fd: int, ev: int) -> None:
        rc = lib.multi_socket_action(part.multi, fd, ev)
        self._sync_timer(part, time.monotonic())
        if rc < 0:
            self._break_partition(part, rc)
        else:
            self._sync_sockets(part)

    def _kick(self, part: Any) -> None:
        """新加入的传输需要一次 kick 才会真正开始（等价于 timer 到期回调）。"""
        rc = lib.multi_fire_timer(part.multi)
        self._sync_timer(part, time.monotonic())
        if rc < 0:
            self._break_partition(part, rc)
        else:
            self._sync_sockets(part)

    # ================================================================== #
    # 子类钩子
    # ================================================================== #
    def _round(self) -> None:
        raise NotImplementedError

    def _break_partition(self, part: Any, rc: int) -> None:
        raise NotImplementedError

    def _shutdown_owned(self) -> None:
        raise NotImplementedError
