"""nb_curl._stream_reactor —— 会话级流式专职 reactor（每 Session 至多 1 个线程）

为什么有这个模块：``stream=True`` 的旧路径是"每条流一个后台线程阻塞在
``easy_perform``"。64 条并发流 = 64 个线程；``aiter_content`` 还要每块一次
``asyncio.to_thread``。本模块把"传输"与"消费"彻底分开：

* 传输归 :class:`StreamReactor`：每会话至多 1 个专职线程，唯一拥有它名下所有
  ``nb_multi``（每连接分区一个）与每条流一个独立 easy 句柄；
* 消费归 :class:`session._StreamBody`：调用线程（用户线程 / 事件循环线程）在
  ``_take()`` 上阻塞，reactor 独立推进，"在事件循环上同步读"不死锁。

等待机制与 :mod:`nb_curl._multi` 的驱动共用 :mod:`nb_curl._stream_core.PollCore`
（唤醒管道 + fd 等待表 + libcurl timer 剩余毫秒现算的绝对到期点 + 1s 兜底），
不造第二套 poll/timer 逻辑。

线程契约（与 native ABI 约定一致）：

* 只有 reactor 线程调用 poll / socket_action / timer / pause / add / remove；
* 其它线程只允许：锁内改标志位（abort/cancel/resume_pending）、写唤醒管道；
* 写回调（跑在 reactor 线程内）只做 O(1) 记账后立刻返回 —— 绝不持锁进 native、
  绝不等消费者；缓冲满时返回 ``CURL_WRITEFUNC_PAUSE`` 且**不入队**（libcurl
  恢复后会重投递这一块，正文不丢不重）；
* unpause 前**先**置 ``paused=False``（``easy_pause(CONT)`` 可能同步重入写回调并
  再次 pause；返回后置 False 会丢掉回调新状态，造成永远不 resume）；
* 所有跨线程交付（头就绪 / 数据 / 异常）一律 ``loop.call_soon_threadsafe``，
  绝不在 reactor 线程上直接 ``Future.set_result``。

中止原因四分（review 第 14 条）：``TASK_CANCEL``（用户任务取消 → CancelledError）、
``SESSION_CLOSED``（会话关闭 → NbCurlError）、``USER_CLOSE``（头就绪后用户主动
close → 读者按 EOF 收场不抛）、``ERROR``（真错误原样抛）。
"""

from __future__ import annotations

import threading
import time
from datetime import timedelta
from typing import Any

from ._native import lib
from ._stream_core import PollCore
from .const import http_version_name
from .exceptions import NbCurlError, RequestError

#: _StreamBody 在 session.py 里（session 导入本模块，故此处不 import session；
#: 基类由 session 在导入时通过 _bind_stream_body 注入）。
_StreamBodyBase: Any = None


def _bind_stream_body(base: Any) -> None:
    """由 :mod:`session` 在导入时调用：注入 ``_StreamBody`` 基类。

    ``ReactorStream`` 的消费接口（wait_ready / iter_chunks / aiter_chunks /
    read_all / abort / close …）全部来自这个基类；_stream_reader 在建流时用
    :func:`make_reactor_stream` 动态生成"基类 + 传输侧"的组合子类
    （绕开模块级循环 import，不改任何公开 API）。
    """
    global _StreamBodyBase
    _StreamBodyBase = base


def make_reactor_stream() -> Any:
    """返回当前的 ``ReactorStream``（已挂上 ``_StreamBody`` 基类的最终形态）。"""
    return ReactorStream

__all__ = ["StreamReactor", "ReactorStream"]

#: 写回调返回这个值 = "这一块没被消费，暂停接收，恢复后重投递"
CURL_WRITEFUNC_PAUSE = 0x10000001
NB_PAUSE_CONT = 0

#: 高/低水位（字节）：迟滞，减少 pause/resume 往返
STREAM_HIGH_WATER = 1024 * 1024
STREAM_LOW_WATER = 512 * 1024


class _Job:
    """一条在飞流在 reactor 侧的全部状态（仅 reactor 线程写这些字段）。"""

    __slots__ = (
        "reader", "prep", "tcp_profile", "handle", "multi", "state",
        "paused", "pause_count", "resume_count", "cancel_requested",
        "code", "error", "status", "finished", "transient",
    )

    def __init__(self, reader: "ReactorStream"):
        self.reader = reader
        self.prep = reader._prep
        self.tcp_profile: Any = None
        self.handle: Any = None
        self.multi: Any = None
        self.state = "NEW"           # NEW / ADDED / FINISHED
        self.paused = False
        self.pause_count = 0
        self.resume_count = 0
        self.cancel_requested = False
        self.code = 0
        self.error: str | None = None
        self.status = 0
        self.finished = False
        # 本次请求专用的 cookie（请求级 cookies / 显式 Cookie 头）：收尾时撤掉
        self.transient: tuple = ()


class ReactorStream:
    """``_StreamBody`` 的传输侧实现：由 :class:`StreamReactor` 驱动。

    实际使用的是 ``session._stream_reader`` 里生成的
    ``class _ReactorStream(ReactorStream, _StreamBody)`` 组合子类：
    消费接口（``wait_ready`` / ``iter_chunks`` / ``aiter_chunks`` /
    ``read_all`` / ``abort`` / ``close`` / ``wait_released``）来自基类，
    本类只提供 reactor 需要的传输侧钩子与启动入口。
    """

    def __init__(self, session: Any, prep: Any, response: Any):
        # 先让 _StreamBody.__init__ 建好锁/缓冲/登记 _streams 等公共状态
        _StreamBodyBase.__init__(self, session, prep, response)
        self._job: _Job | None = None      # reactor 线程在 submit 后建立

    # -- 传输侧钩子（_StreamBody 契约） ------------------------------------ #
    def _on_chunk(self, data: bytes) -> int:
        """写回调（reactor 线程）：O(1) 记账；满水位回 PAUSE 且不入队。"""
        job = self._job
        with self._cond:
            if self._abort:
                return 0
            n = len(data)
            if self._buffered > 0 and self._buffered + n > STREAM_HIGH_WATER:
                if job is not None:
                    job.paused = True
                    job.pause_count += 1
                return CURL_WRITEFUNC_PAUSE
            self._chunks.append(data)
            self._buffered += n
            self._notify_locked()
            return n

    def _on_header(self, line: bytes) -> bool:
        # 基类（_StreamBody）已实现头块解析/1xx 过滤/最终头判定；直接复用。
        return _StreamBodyBase._on_header(self, line)

    def _after_take_locked(self) -> None:
        """消费者取走一块（**调用方已持锁**，见基类契约）：低于低水位就请求恢复。

        resume 只入 **reactor 自己的队列**（``self._session._stream_reactor._resumes``），
        绝不入本 reader 的任何缓冲 —— 消费侧队列 reactor 永远看不到，暂停后就会
        永远无法恢复（10MiB 慢消费者 curl 28 的根因之一）。
        """
        job = self._job
        if job is not None and job.paused and self._buffered <= STREAM_LOW_WATER:
            job.paused = False            # 先清 paused（裁定 2：防同步重入丢状态）
            job.resume_count += 1
            reactor = self._session._stream_reactor
            if reactor is not None:
                reactor._enqueue_resume(job)
                reactor._wake()

    def _cancel_transport(self) -> None:
        """abort() 的传输侧通知：置取消意图 + 唤醒 reactor（绝不碰 native）。"""
        reactor = self._session._stream_reactor
        if reactor is not None:
            reactor._request_cancel(self)

    # -- 启动（调用方线程） ------------------------------------------------- #
    def start(self, tcp_profile: Any) -> None:
        """把这条流交给会话级 reactor（阻塞到响应头就绪或结束）。"""
        reactor = self._session._reactor_for_streams()
        reactor.submit(self, tcp_profile)
        try:
            self.wait_ready()
        except BaseException:
            self.abort()
            raise


class StreamReactor(PollCore):
    """每 Session 至多一个的流式专职 reactor 线程。

    复用 :class:`PollCore` 的等待内核；本类补上：装填（建句柄/装回调/加 multi）、
    完成（drain → remove → 收尾 → 交付）、背压恢复轮次、停机。
    """

    def __init__(self, session: Any):
        super().__init__(session)
        self._by_reader: dict[int, _Job] = {}   # id(reader) -> job
        self._resumes: list[_Job] = []          # 待 resume 的 job（reactor 消费）

    # ------------------------------------------------------------------ #
    # 提交（调用方线程）/ 取消意图
    # ------------------------------------------------------------------ #
    def submit(self, reader: Any, tcp_profile: Any) -> None:
        """登记一条新流（不碰 native）；句柄的创建与配置留给 reactor 线程。

        ``reader._job`` **必须**在这里就绑定：写回调（reactor 线程）和消费者的
        ``_after_take_locked`` 都要靠它找到 job 记账 pause/resume —— 不绑定的话
        写回调永远无法回 PAUSE（缓冲无界）、消费侧也永远无法请求恢复。
        绑定发生在挂进 ``_pending`` 之前，之后任何线程都只读 ``reader._job``。
        """
        job = _Job(reader)
        job.tcp_profile = tcp_profile
        reader._job = job
        with self._lock:
            if self._shut or self._stopping:
                reader._job = None
                raise NbCurlError("Session 已关闭")
            self._pending.append(job)
            self._by_reader[id(reader)] = job
        self._ensure_thread("nb-curl-reactor")
        self._wake()

    def _request_cancel(self, reader: Any) -> None:
        """置"取消这条流"的意图并唤醒（任何线程可调，不碰 native）。"""
        with self._lock:
            job = self._by_reader.get(id(reader))
            if job is not None:
                job.cancel_requested = True
            else:
                job = reader._job
                if job is not None and not job.finished:
                    job.cancel_requested = True
        self._wake()

    def _enqueue_resume(self, job: _Job) -> None:
        """把一条待恢复的 job 放进 reactor 的恢复队列（任何线程可调）。"""
        with self._lock:
            self._resumes.append(job)

    # ------------------------------------------------------------------ #
    # 一轮驱动（reactor 线程）
    # ------------------------------------------------------------------ #
    def _round(self) -> None:
        if self._shut:
            return
        if self._stopping:
            for job in list(self._by_reader.values()):
                self._finish_job(job, cancelled=True)
            if self._shut:
                return
        for _ in range(8):
            self._attach_pending()
            self._fire_due_timers()
            self._drain_completions()
            self._apply_resumes()
            if self._shut or not self._pending:
                break
        self._refresh_waits()

    def _attach_pending(self) -> None:
        with self._lock:
            jobs, self._pending = self._pending, []
        for job in jobs:
            reader = job.reader
            if job.cancel_requested or self._stopping:
                self._finish_job(job, cancelled=True)
                continue
            try:
                self._start_job(job)
            except BaseException as exc:  # noqa: BLE001
                self._fail_job(job, exc)
        # 已在飞、被请求取消的流就地撤销
        for job in list(self._by_reader.values()):
            if job.cancel_requested and job.state == "ADDED":
                self._finish_job(job, cancelled=True)

    def _start_job(self, job: _Job) -> None:
        """建句柄、装回调与配置，加入分区 multi（全部在 reactor 线程）。"""
        session = self._session
        handle = lib.easy_init()
        if not handle:
            raise NbCurlError("easy_init() 失败：native 句柄创建不成功")
        try:
            from .session import _Handle
            hobj = _Handle(handle)
            lib.easy_set_fresh_connect(handle, 1)   # 流用独立连接，不复用池
            session._apply_fingerprint(handle, job.prep.fingerprint)
            session._apply_handle_options(handle, job.prep)
            # transient = 本次请求专用 cookie（请求级 cookies / 显式 Cookie 头）：
            # 收尾时必须撤掉，且不进会话罐 —— 与同步路径同一套语义。
            job.transient = session._sync_cookies(
                handle, job.prep, hobj.pushed_cookies) or ()
            keepalive = lib.install_stream_callbacks(
                handle, job.reader._on_chunk, job.reader._on_header)
            # **必须**在 multi_add 之前准备：方法名与请求体是在 native 的
            # ``easy_prepare_request`` 里才真正落到句柄上的（multi 路径不走
            # ``easy_perform``）。漏掉它，POST 会退化成 GET 且正文丢失 ——
            # 正是 1xx（100-continue）用例里"服务端收到 GET、体长 0"的根因。
            if lib.prepare_request(handle) != 0:
                raise NbCurlError("native 准备请求失败（easy_prepare_request）")
        except BaseException:
            try:
                lib.easy_cleanup(handle)
            except Exception:  # noqa: BLE001
                pass
            raise
        job.handle = hobj
        job.multi = None
        # 回调闭包必须活到传输结束
        job.reader._keepalive = keepalive
        reader = job.reader
        with reader._cond:
            reader._handle = hobj
        try:
            part = self._parts.get(job.prep.key)
            if part is None or part.broken:
                multi = lib.multi_init()
                if not multi:
                    raise NbCurlError("nb_multi_init() 失败")
                part = _StreamPartition(job.prep.key, multi)
                self._parts[part.key] = part
            rc = lib.multi_add(part.multi, handle)
            if rc != 0:
                raise NbCurlError("multi_add 失败（%d）" % rc)
        except BaseException:
            with reader._cond:
                reader._handle = None
            try:
                hobj.close()
            except Exception:  # noqa: BLE001
                pass
            job.handle = None
            raise
        job.multi = part
        part.jobs.add(job)
        part.by_easy[job.handle.ptr] = job
        job.state = "ADDED"
        self._kick(part)

    def _drain_completions(self) -> None:
        for part in list(self._parts.values()):
            if part.broken:
                continue
            while True:
                item = lib.multi_drain(part.multi)
                if item is None:
                    break
                _msg, code, easy = item
                job = part.by_easy.get(easy)
                if job is None:
                    continue
                # 先 drain 读码、再 remove，然后才能读结果/释放（ABI 约定）
                if lib.multi_remove(part.multi, easy) != 0:
                    self._break_partition(part, -2)
                    break
                self._finish_job(job, code=code)
                if part.broken or self._shut:
                    break

    def _apply_resumes(self) -> None:
        """消费积压恢复轮次：unpause 前先清 paused（裁定 2），easy_pause 可同步重入。

        消费侧入队前已把 ``paused=False``，这里再清一次是**兜底**：同步重入的写
        回调可能在两次设置之间又把 paused 置回 True，而 unpause 已经做过了 ——
        那次 True 属于"回调自己没收到数据"，unpause 的语义仍然完成。
        """
        while True:
            with self._lock:
                if not self._resumes:
                    return
                job = self._resumes.pop(0)
            job.paused = False
            handle = job.handle
            if handle is None or job.state != "ADDED" or job.cancel_requested:
                continue
            if job.finished:
                continue
            rc = lib.pause(handle.ptr, NB_PAUSE_CONT)
            if rc != 0:
                self._fail_job(job, RequestError(
                    "easy_pause(CONT) 失败: %s" % lib.strerror(rc)))
            else:
                self._kick(job.multi)

    # ------------------------------------------------------------------ #
    # 收尾（唯一交付点）
    # ------------------------------------------------------------------ #
    def _finish_job(self, job: _Job, *, code: int = 0, cancelled: bool = False,
                    error: BaseException | None = None) -> None:
        """把一条流移出 multi、释放句柄并交付（幂等）。

        交付契约：**任何**出口（完成 / 错误 / 取消 / 会话关闭）都必须置
        ``reader._done`` 并 ``_notify_locked()`` —— 只赋 ``_exc`` 不置 done 会让
        ``_take()`` 永远等下去（review-stream-integration 第 21 条）。
        ``USER_CLOSE``（读者主动中止，写回调已回失败/abort）与 ``TASK_CANCEL``
        都按"读者按 EOF/明确异常收场"交付，不再二次包装。
        """
        if job.finished:
            return
        job.finished = True
        job.state = "FINISHED"
        reader = job.reader
        part = job.multi
        if part is not None and not part.broken and job.handle is not None:
            rc = lib.multi_remove(part.multi, job.handle.ptr)
            if rc != 0:
                error = RequestError(
                    "libcurl multi 内部错误（CURLMcode=%d）：本分区全部流已失败" % rc)
                self._break_partition(part, rc)
            else:
                part.jobs.discard(job)
                part.by_easy.pop(job.handle.ptr, None)
        job.multi = None
        with reader._cond:
            handle, reader._handle = reader._handle, None
            # 完成时把 status/header 早已在头回调里刷进 response；这里只补
            # 错误/取消/正常 code 的交付谓词 —— done 必须无条件置位。
            if error is not None:
                reader._exc = error
                reader._done = True
            elif cancelled:
                reader._code = 0
                reader._done = True
                if job.cancel_requested or reader._abort:
                    # 用户主动 close/abort：读者按 EOF 收场（除非确有 native 错误）
                    if reader._error in (None, "Session 已关闭"):
                        reader._error = None
                else:
                    reader._exc = NbCurlError("Session 已关闭")
            else:
                reader._code = int(code)
                reader._error = lib.strerror(int(code)) if code else None
                reader._done = True
            reader._notify_locked()
        # 与同步/异步非流式走**同一套**收尾（``_collect_result`` + ``_finish``）：
        # 吸收 cookie、撤本次专用 cookie、按 CURLcode 抛异常。少了这一步，流式
        # 响应就不会把 ``Set-Cookie`` 吸收进会话罐（旧版是会吸收的）。
        self._finish_stream_reader(job, reader, code, int(code))
        self._by_reader.pop(id(reader), None)
        # reader._release_handle 由 reactor 释放句柄（避免与 native 抢）
        if handle is not None:
            try:
                handle.close()
            except Exception:  # noqa: BLE001
                pass
        reader._release_event.set()
        reader._release_handle()

    @staticmethod
    def _apply_stream_info(reader: Any, info: Any, cookie_dump: str) -> None:
        """把收尾读数（最终 URL / 协议版本 / 耗时 / 原始 cookie 列表）刷进响应。"""
        resp = reader.response
        if resp is None:
            return
        with reader._cond:
            if info is not None:
                url = getattr(info, "url", None)
                if url:
                    resp.url = url
                version = getattr(info, "http_version", None)
                if version:
                    # getinfo 给的是 CURL_HTTP_VERSION_* 数值，响应对象上是 "1.1"/"2"
                    resp.http_version = http_version_name(int(version))
                elapsed = getattr(info, "total_time", None)
                if elapsed:
                    # Response.elapsed 是 timedelta（构造时由秒数换算）；这里直接
                    # 赋秒数会让它变成 float，调用方 ``.total_seconds()`` 就没了。
                    resp.elapsed = timedelta(seconds=elapsed)
                ip = getattr(info, "primary_ip", None)
                if ip:
                    resp.primary_ip = ip
                redirects = getattr(info, "redirect_count", None)
                if redirects is not None:
                    resp.redirect_count = redirects
            reader._code_dump = cookie_dump or ""
            if cookie_dump:
                # 旧版流式完成后 ``raw_cookie_list`` 为空；候选保留原生导出（只读
                # 字段，不重复投递），测试按 [info] 记录，不强制断言。
                try:
                    resp._raw_cookie_list = cookie_dump
                except Exception:  # noqa: BLE001
                    pass

    def _finish_stream_reader(self, job: _Job, reader: Any, code: int,
                              raw_code: int) -> None:
        """传输真正结束后的收尾读数 + 响应元数据刷新（只在此处做一次）。

        ``_collect_result`` 会 getinfo（最终 URL / 协议版本 / 耗时…）并导出 cookie，
        ``_finish`` 再把 cookie 吸收进会话罐 —— 这两件都是**必须**在句柄释放之前
        完成的。旧版流式同样做了，漏掉就是功能退化（test_stream_metadata 覆盖）。
        """
        handle = job.handle
        prep = job.prep
        session = self._session
        if handle is None or handle.ptr is None:
            return
        try:
            info, cookie_dump = session._collect_result(handle, prep, job.transient)
        except BaseException as exc:  # noqa: BLE001
            with reader._cond:
                reader._exc = exc
                reader._done = True
                reader._notify_locked()
            return
        reader._finish_result = (info, cookie_dump, raw_code)
        # 把 getinfo 的结果刷进响应对象：最终 URL（重定向之后）、协议版本、耗时。
        # 头回调阶段只知道请求的 URL，这些"只有跑完才知道"的字段在这里补齐 ——
        # 旧版流式同样是在收尾时刷的（test_stream_metadata 覆盖）。
        self._apply_stream_info(reader, info, cookie_dump)
        try:
            session._finish(prep, info, cookie_dump, job.transient,
                            raw_code, lib.strerror(raw_code) if raw_code else None)
        except BaseException as exc:  # noqa: BLE001
            # 传输级错误（超时/连接失败…）原样抛给读者，与旧版一致
            with reader._cond:
                reader._exc = exc
                reader._notify_locked()

    def _fail_job(self, job: _Job, exc: BaseException) -> None:
        self._finish_job(job, error=exc)

    def _break_partition(self, part: Any, rc: int) -> None:
        """multi 出错：逐个 remove -> cleanup -> 统一真错误交付。"""
        if part.broken:
            return
        part.broken = True
        self._forget_sockets(part)
        jobs = list(part.jobs)
        part.jobs.clear()
        part.by_easy.clear()
        self._parts.pop(part.key, None)
        err = RequestError(
            "libcurl multi 内部错误（CURLMcode=%d）：本分区全部流已失败" % rc)
        for job in jobs:
            if job.handle is not None:
                try:
                    lib.multi_remove(part.multi, job.handle.ptr)
                except Exception:  # noqa: BLE001
                    pass
        try:
            lib.multi_cleanup(part.multi)
        except Exception:  # noqa: BLE001
            pass
        for job in jobs:
            self._finish_job(job, error=err)

    def _release_handle(self, *args: Any, **kwargs: Any) -> None:  # pragma: no cover
        raise NotImplementedError  # 不使用 _multi 的句柄池语义

    # ------------------------------------------------------------------ #
    # 停机（所有者线程收尾；幂等）
    # ------------------------------------------------------------------ #
    # ------------------------------------------------------------------ #
    # 停机（任何线程可调：只置标志 + 唤醒；所有者线程收尾）
    # ------------------------------------------------------------------ #
    def stop(self, wait: bool = False) -> None:
        """发"停止 + 拆掉全部在飞流"的意图并唤醒（绝不碰 native）。

        ``wait`` 参数仅为与 ``Session._shutdown_streams`` 的调用约定兼容：
        这里**从不等待**（等待由 ``wait_closed``/``_close_streams`` 负责），
        真正的收尾在所有者线程的 ``_shutdown_owned`` 里完成。
        """
        with self._lock:
            if self._stopping or self._shut:
                pass
            else:
                self._stopping = True
        self._wake()
        return None

    def _shutdown_owned(self) -> None:
        if self._shut:
            return
        self._shut = True
        self._stopping = True
        for job in list(self._by_reader.values()):
            self._finish_job(job, cancelled=True)
        with self._lock:
            pend, self._pending = self._pending, []
        for job in pend:
            self._finish_job(job, cancelled=True)
        for part in list(self._parts.values()):
            if not part.broken:
                for job in list(part.jobs):
                    if job.handle is not None:
                        try:
                            lib.multi_remove(part.multi, job.handle.ptr)
                        except Exception:  # noqa: BLE001
                            pass
                try:
                    lib.multi_cleanup(part.multi)
                except Exception:  # noqa: BLE001
                    pass
        self._parts.clear()
        self._close_wake()


class _StreamPartition:
    """一个连接分区：一个 ``nb_multi`` + 挂在上面的流 job。

    ``transfers`` 是 ``jobs`` 的只读视图别名：PollCore._has_work 按
    ``part.transfers`` 统一问"还有没有在飞"（review 要求 part 接口统一，
    不允许 PollCore 知道两种字段名）。
    """

    __slots__ = ("key", "multi", "jobs", "by_easy", "broken", "timer_at")

    def __init__(self, key: Any, multi: Any):
        self.key = key
        self.multi = multi
        self.jobs: set = set()
        self.by_easy: dict = {}
        self.broken = False
        self.timer_at: float | None = None

    @property
    def transfers(self) -> Any:
        """在飞集合（= jobs 的只读视图；len() 与成员判断语义一致）。"""
        return self.jobs
