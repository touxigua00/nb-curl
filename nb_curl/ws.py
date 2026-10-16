"""nb_curl.ws —— WebSocket 客户端（基于 libcurl 的 curl_ws_*）

连接由 ``Session.ws_connect(url, ...)`` 建立：内部对 handle 设
``CURLOPT_CONNECT_ONLY=2`` 后 ``easy_perform`` 完成 ws 握手（HTTP/1.1 101 协议升级），
之后用 ``curl_ws_send`` / ``curl_ws_recv`` 收发帧。

设计要点：

* **独立 handle，不走连接池**：ws 是长连接独占，与请求-响应模型不同；
  ``close()`` 时直接 ``easy_cleanup``。
* **recv 负责控制帧**：收到 PING 立刻回同载荷 PONG；收到 PONG 丢弃；
  收到 CLOSE 置"对端已关闭"并返回 ``None``（不在这里释放 handle，
  释放统一由 :meth:`WebSocket.close` 完成，避免状态位复用导致句柄泄漏）。
* **帧分片重组**：大帧会被 curl 分多次返回，用 ``bytesleft`` 判断帧是否读完，
  再用帧内 ``offset`` 校验续片首尾相接（错位 = 丢/重数据，直接报错而不是静默拼错）。
* **阻塞 recv + 超时**：``curl_ws_recv`` 无数据时返回 ``CURLE_AGAIN(81)``，
  Python 侧轮询 sleep。不是真异步——如需高并发 ws，未来可基于 multi 接口重写。
* **发送不丢数据**：``curl_ws_send`` 可能只吃下一部分（桥接层返回 ``-3``）
  或返回 ``CURLE_AGAIN``，两者都按 libcurl 文档"带剩余数据重试"处理。
* **自动 PONG**：libcurl 默认会自己回 PONG，但它把 PONG 排进内部 pending，
  只有"成功收到一个数据帧"或"下一次 curl_ws_send"时才会 flush；
  因此 ``Session.ws_connect`` 在握手前通过 :func:`configure_ws_handshake` 关掉
  自动 PONG（``CURLWS_NOAUTOPONG``），由本模块的 ``recv`` 回 PONG（已集成）。
  用户若绕开 ``ws_connect`` 自建 ws 句柄，请自行调用该 helper，否则退化为：
  recv 仍收得到数据帧（客户端有发送动作时 PONG 会被顺带 flush），
  但"服务端 PING 后静等客户端 PONG"这一步不成立。
"""
from __future__ import annotations

import time

from .exceptions import NbCurlError, RequestError, Timeout, curl_error_detail
from .options import (
    CURLWS_BINARY,
    CURLWS_CLOSE,
    CURLWS_CONT,
    CURLWS_NOAUTOPONG,
    CURLWS_OFFSET,
    CURLWS_PING,
    CURLWS_PONG,
    CURLWS_TEXT,
    CURLE_AGAIN,
    CurlOpt,
)

__all__ = ["WebSocket", "configure_ws_handshake", "ws_handshake_options",
           "CURLWS_TEXT", "CURLWS_BINARY", "CURLWS_CLOSE",
           "CURLWS_PING", "CURLWS_PONG", "CURLWS_CONT", "CURLWS_OFFSET",
           "CURLWS_NOAUTOPONG"]


# CURLOPT_CONNECT_ONLY = 141（long 类）。ws 握手需要设为 2。
_CURLOPT_CONNECT_ONLY = 141

#: ws_recv 单次取数据的缓冲区大小；大帧靠多次调用 + bytesleft 拼回来。
_RECV_CAP = 65536

#: 发送遇 CURLE_AGAIN 时轮询间隔（秒）。
_SEND_POLL = 0.005

#: close 握手等待对端 CLOSE 的上限（秒）。有界，不做固定 sleep 兜底。
_CLOSE_WAIT = 0.5

#: 桥接层自定义：ws_send 只吃下一部分（native/nb_curl_bridge.c 的 -3）。
_WS_PARTIAL = -3

# 已经下发过 ws 握手指令的 handle（按指针身份记账）。见 configure_ws_handshake。
_APPLIED: set[int] = set()
_APPLIED_MAX = 1024


# ---------------------------------------------------------------------- #
# 握手期选项：关掉 libcurl 的自动 PONG，把 PONG 交给 ws.recv
# ---------------------------------------------------------------------- #
def _handle_key(handle) -> int:
    """把 native handle 映射成稳定的整数键（int / ctypes / cffi 指针都能吃）。

    不能用 ``int()``：cffi 的 ``void *`` 与 ctypes 指针都不支持它。
    ``hash()`` 对三者都返回基于地址的稳定值，且 cffi 指针可哈希。
    """
    return hash(handle)


def ws_handshake_options() -> dict:
    """返回 ws 握手**前**必须下发的 curl_options 片段。

    目前只有一项：``CURLOPT_WS_OPTIONS = CURLWS_NOAUTOPONG``。
    调用方把它合进本次 ``ws_connect`` 的 ``curl_options``（用户显式给的值优先），
    或者用 :func:`configure_ws_handshake` 直接下发。返回的 dict 不做任何缓存。
    """
    return {CurlOpt.WS_OPTIONS: CURLWS_NOAUTOPONG}


def configure_ws_handshake(handle, lib) -> None:
    """在 ``easy_perform`` 之前，把 ws 握手指令下发到 handle。

    代码::

        # Session.ws_connect 内部（最小集成点，一行）
        lib.set_option_long(ptr, CurlOpt.CONNECT_ONLY, 2)
        ws.configure_ws_handshake(ptr, lib)      # <- 新增

    要点：

    * 必须在握手前调用：``ws_no_auto_pong`` 要在 ws 连接建立时就是对的；
      握手后再设只影响后续帧，对已经建立的连接不可靠。
    * 不关自动 PONG 的后果：libcurl 自己吃掉 PING，生成的 PONG 只排在内部 pending 里，
      只有"下一次 curl_ws_send"或"成功交付一个数据帧"才会被 flush ——
      只轮询 ``curl_ws_recv`` 的应用会一直收不到东西。
    * 关掉之后 PONG 由 :meth:`WebSocket.recv` 负责发；自动 PONG 与手动 PONG
      二选一，不能都开着（都开会让对端收到两个 PONG）。
    * 同一 handle 重复调用安全（按指针去重）。句柄被 cleanup 后指针可能被复用，
      所以只按"已下发"记账、不尝试撤销；重新握手请新建 handle。
    """
    if handle is None:
        return
    key = _handle_key(handle)
    if key in _APPLIED:
        return
    code = lib.set_option_long(handle, CurlOpt.WS_OPTIONS, CURLWS_NOAUTOPONG)
    if code != 0:
        raise RequestError(code=code, message=curl_error_detail(
            code, "设置 WS_OPTIONS=%d（CURLWS_NOAUTOPONG）失败: %s"
            % (CURLWS_NOAUTOPONG, lib.strerror(code))))
    if len(_APPLIED) >= _APPLIED_MAX:
        _APPLIED.clear()          # 简单有界：满了一键清空，避免长跑进程无限增长
    _APPLIED.add(key)


def forget_ws_options(handle) -> None:
    """撤销 :func:`configure_ws_handshake` 对某个 handle 的记账（handle 已释放时调用）。"""
    if handle is None:
        return
    _APPLIED.discard(_handle_key(handle))


class WebSocket:
    """同步 WebSocket 客户端。由 :meth:`Session.ws_connect` 创建，不要直接构造。"""

    def __init__(self, session, handle_ptr, lib):
        self._session = session
        self._ptr = handle_ptr
        self._lib = lib
        # 两个状态位分开：对端已 CLOSE != native handle 已释放。
        # 复用同一个位会让"对端先关"的连接永远走不到 easy_cleanup（句柄泄漏）。
        self._peer_closed = False
        self._released = False
        # 当前正在累积的多分片帧（CONT 帧续接）
        self._frame_buf: bytearray | None = None
        self._frame_kind: int = 0  # TEXT / BINARY
        self._frame_off: int = 0   # self._frame_buf 在整帧内的起始偏移

    # -- 内部 ----------------------------------------------------------- #
    def _err(self, code: int, what: str) -> RequestError:
        return RequestError(code=code, message=curl_error_detail(
            code, "WebSocket %s: %s" % (what, self._lib.strerror(code))))

    def _send_raw(self, data: bytes, flags: int) -> None:
        """发一整帧；按 libcurl 的语义处理部分发送与 ``CURLE_AGAIN``，不丢/不重数据。

        桥接层把"部分发送"折叠成 ``-3``、把 ``CURLE_AGAIN`` 原样传回（不返回已发送
        字节数）。两者都表示"这一帧还没送完，libcurl 已把没收下的那段留在自己缓冲里"，
        所以这里**原样重试同一整帧**直到 ``code == 0``：`curl_ws_send` 的契约只拒绝
        "比上次更小的 buflen"（`lib/ws.c:1418-1436`），重试同一载荷正是它期望的用法
        （curl_ws_send(3) 的示例循环也是这个形状，只是它自己推进 offset）。
        """
        if self._released:
            raise NbCurlError("WebSocket 已关闭")
        while True:
            code = self._lib.ws_send(self._ptr, data, flags)
            if code == 0:
                return
            if code in (_WS_PARTIAL, CURLE_AGAIN):
                time.sleep(_SEND_POLL)
                continue
            raise self._err(code, "发送失败")

    def _control_reply(self, data: bytes, flags: int) -> RequestError | None:
        """回一个控制帧；失败不抛异常，把异常返回给调用方决定。"""
        try:
            self._send_raw(data, flags)
        except (RequestError, NbCurlError) as exc:
            return exc if isinstance(exc, RequestError) else None
        return None

    def _drain_until_close(self, deadline: float) -> bool:
        """读到对端 CLOSE 返回 True；超时/连接已断返回 False。

        只用于 close() 收尾：既保证 CLOSE 帧已被对端读走，也顺带排空接收队列。
        """
        while time.monotonic() < deadline:
            code, _data, flags, _off, _left = self._lib.ws_recv(self._ptr, _RECV_CAP)
            if code == CURLE_AGAIN:
                time.sleep(_SEND_POLL)
                continue
            if code != 0:
                return False          # 连接已经坏了/断了，不用再等
            if flags & CURLWS_CLOSE:
                return True
        return False

    # -- 发送 ----------------------------------------------------------- #
    def send(self, data, *, binary: bool | None = None) -> None:
        """发送一帧。

        :param data: ``str`` 当文本帧、``bytes`` 当二进制帧。
        :param binary: 显式指定 True=二进制 / False=文本；不传则按 data 类型推断
            （str→文本，bytes→二进制）。
        """
        if binary is None:
            binary = isinstance(data, (bytes, bytearray))
        payload = data if isinstance(data, (bytes, bytearray)) else str(data).encode("utf-8")
        self._send_raw(bytes(payload), CURLWS_BINARY if binary else CURLWS_TEXT)

    def send_text(self, text: str) -> None:
        self._send_raw(text.encode("utf-8"), CURLWS_TEXT)

    # 别名（对标 curl_cffi 的 WebSocket.send_str）
    send_str = send_text

    def send_bytes(self, data: bytes) -> None:
        self._send_raw(bytes(data), CURLWS_BINARY)

    def ping(self, data: bytes = b"") -> None:
        self._send_raw(bytes(data), CURLWS_PING)

    # -- 接收 ----------------------------------------------------------- #
    def recv(self, timeout: float | None = None):
        """阻塞接收一个完整数据帧。

        :param timeout: 秒；超时抛 :class:`Timeout`。``None`` 表示无限等待。
        :return: ``str``（文本帧）或 ``bytes``（二进制帧）。
            连接已关闭（收到 CLOSE 帧，或对端直接断开）时返回 ``None``。
            文本帧 UTF-8 解码失败时回退返回 ``bytes``。
        """
        if self._peer_closed or self._released:
            return None
        deadline = time.monotonic() + timeout if timeout else None

        while True:
            code, data, flags, offset, left = self._lib.ws_recv(self._ptr, _RECV_CAP)

            if code == CURLE_AGAIN:
                if deadline is not None and time.monotonic() >= deadline:
                    raise Timeout("WebSocket recv 超时", code)
                time.sleep(_SEND_POLL)
                continue
            if code != 0:
                # 对端直接断开（没有 CLOSE 帧）也算连接结束；其余错误照抛，不吞。
                if code == CURLE_GOT_NOTHING:
                    self._peer_closed = True
                    return None
                raise self._err(code, "接收失败")

            kind = flags & ~CURLWS_OFFSET

            # 控制帧：就地处理，不交给应用层
            if kind & CURLWS_PING:
                # 关掉自动 PONG 后这里是唯一通路；发送失败不吞，报清楚
                err = self._control_reply(data, CURLWS_PONG)
                if err is not None:
                    raise err
                continue
            if kind & CURLWS_PONG:
                continue
            if kind & CURLWS_CLOSE:
                self._peer_closed = True
                return None

            # 数据帧（可能的层次：ws 消息分片 / 单帧内的传输分片）
            #
            # curl 的 offset 是**每次调用内部切片**的偏移：一次调用装不下时，下一次
            # 调用的 offset 会接着上一次走（65536, 131072…）；而 ws 消息的下一个
            # 分片（CONT）又是从 0 重新开始。所以"新分片开始"的判据不是 buffer 长度，
            # 而是 offset==0：它既覆盖"整帧读完后的新消息"，也覆盖"消息内新分片"。
            if kind & (CURLWS_TEXT | CURLWS_BINARY):
                next_kind = kind & (CURLWS_TEXT | CURLWS_BINARY)
                if next_kind != self._frame_kind:
                    self._frame_buf = None       # 新消息：丢弃上一帧的残留缓冲
                    self._frame_off = 0
                self._frame_kind = next_kind
            elif kind & CURLWS_CONT:
                if self._frame_kind == 0:
                    raise NbCurlError(
                        "WebSocket 帧序列损坏：收到 CONT 续片但没有起始帧")
            else:
                continue

            if offset == 0 and self._frame_buf is not None:
                self._frame_buf = None           # 上一分片的载荷已用完，重新累积
            if self._frame_buf is None:
                self._frame_buf = bytearray()
                self._frame_off = offset

            # 片与片必须严格首尾相接：错位就意味着丢数据/重复数据，明确报错
            if offset != self._frame_off + len(self._frame_buf):
                raise NbCurlError(
                    "WebSocket 帧分片错位：期望 offset=%d，实际收到 %d"
                    % (self._frame_off + len(self._frame_buf), offset))
            self._frame_buf.extend(data)

            if left == 0:
                payload = bytes(self._frame_buf)
                binary = bool(self._frame_kind & CURLWS_BINARY)
                self._frame_buf = None
                self._frame_kind = 0
                self._frame_off = 0
                if binary:
                    return payload
                try:
                    return payload.decode("utf-8")
                except UnicodeDecodeError:
                    return payload

            # left > 0：继续收同一帧的下一片

    # -- 生命周期 ------------------------------------------------------- #
    def close(self) -> None:
        """发送 CLOSE 帧、有界等待对端 CLOSE，然后释放 handle。可重复调用（幂等）。

        不在这里做固定 sleep：等的是对端真的回了 CLOSE（或连接结束/超时），
        这样既能把 CLOSE 交给对端读走，也顺手排空接收队列。
        """
        if self._released:
            return
        ptr = self._ptr
        if ptr:
            if not self._peer_closed:
                self._control_reply(b"", CURLWS_CLOSE)
                self._drain_until_close(time.monotonic() + _CLOSE_WAIT)
            self._lib.easy_cleanup(ptr)
            forget_ws_options(ptr)
        self._ptr = None
        self._released = True

    @property
    def closed(self) -> bool:
        """连接是否已不可用（对端已 CLOSE 或本地已释放）。"""
        return self._released or self._peer_closed

    def __enter__(self) -> "WebSocket":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self):  # pragma: no cover
        try:
            self.close()
        except Exception:  # noqa: BLE001
            pass

    def __repr__(self) -> str:
        return "<WebSocket peer_closed=%s released=%s>" % (
            self._peer_closed, self._released)
