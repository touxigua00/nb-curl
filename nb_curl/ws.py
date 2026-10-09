"""nb_curl.ws —— WebSocket 客户端（基于 libcurl 的 curl_ws_*）

连接由 ``Session.ws_connect(url, ...)`` 建立：内部对 handle 设
``CURLOPT_CONNECT_ONLY=2`` 后 ``easy_perform`` 完成 ws 握手（HTTP/1.1 101 协议升级），
之后用 ``curl_ws_send`` / ``curl_ws_recv`` 收发帧。

设计要点：

* **独立 handle，不走连接池**：ws 是长连接独占，与请求-响应模型不同；
  ``close()`` 时直接 ``easy_cleanup``。
* **recv 自动处理控制帧**：收到 PING 自动回 PONG（与浏览器一致，curl 默认已自动处理，
  这里是双保险），收到 CLOSE 标记关闭，收到 PONG 透传给应用（默认丢弃）。
* **帧分片重组**：大帧会被 curl 分多次返回，用 ``bytesleft`` 判断帧是否读完，
  累积完整帧再返回。
* **阻塞 recv + 超时**：``curl_ws_recv`` 无数据时返回 ``CURLE_AGAIN(81)``，
  Python 侧轮询 sleep。不是真异步——如需高并发 ws，未来可基于 multi 接口重写。
"""
from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

from .exceptions import NbCurlError, RequestError, Timeout, curl_error_detail
from .options import (
    CURLWS_BINARY,
    CURLWS_CLOSE,
    CURLWS_CONT,
    CURLWS_PING,
    CURLWS_PONG,
    CURLWS_TEXT,
    CURLE_AGAIN,
)

__all__ = ["WebSocket", "CURLWS_TEXT", "CURLWS_BINARY", "CURLWS_CLOSE",
           "CURLWS_PING", "CURLWS_PONG"]


# CURLOPT_CONNECT_ONLY = 141（long 类）。ws 握手需要设为 2。
_CURLOPT_CONNECT_ONLY = 141


class WebSocket:
    """同步 WebSocket 客户端。由 :meth:`Session.ws_connect` 创建，不要直接构造。"""

    def __init__(self, session, handle_ptr, lib):
        self._session = session
        self._ptr = handle_ptr
        self._lib = lib
        self._closed = False
        # 当前正在累积的多分片帧（CONT 帧续接）
        self._frame_buf: bytearray | None = None
        self._frame_kind: int = 0  # TEXT / BINARY

    # -- 内部 ----------------------------------------------------------- #
    def _send_raw(self, data: bytes, flags: int) -> None:
        if self._closed:
            raise NbCurlError("WebSocket 已关闭")
        # curl_ws_send 一次性写整帧；部分发送（-3）时按整帧重发（libcurl 内部缓冲）
        # —— 实测小帧不会部分发送，这里直接调一次。
        code = self._lib.ws_send(self._ptr, data, flags)
        if code != 0 and code != -3:
            raise RequestError(
                curl_error_detail(
                    code, "WebSocket 发送失败: %s" % self._lib.strerror(code)),
                code)

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
            连接已关闭（收到 CLOSE 帧）时返回 ``None``。
            文本帧 UTF-8 解码失败时回退返回 ``bytes``。
        """
        if self._closed:
            return None
        deadline = time.monotonic() + timeout if timeout else None
        _recv_cap = 65536

        while True:
            # 先 drain 当前正在累积的帧（curl 仍可能继续给同一帧的分片）
            code, data, flags, _off, left = self._lib.ws_recv(self._ptr, _recv_cap)

            if code == CURLE_AGAIN:
                if deadline is not None and time.monotonic() >= deadline:
                    raise Timeout("WebSocket recv 超时", code)
                time.sleep(0.005)
                continue
            if code != 0:
                raise RequestError(
                    curl_error_detail(
                        code, "WebSocket 接收失败: %s" % self._lib.strerror(code)),
                    code)

            # 控制帧：自动处理，不交给应用层
            if flags & CURLWS_PING:
                # 双保险回 PONG（curl 默认已自动处理）
                try:
                    self._send_raw(data, CURLWS_PONG)
                except RequestError:
                    pass
                continue
            if flags & CURLWS_PONG:
                continue
            if flags & CURLWS_CLOSE:
                self._closed = True
                return None

            # 数据帧（可能分片：CONT 续接前一个 TEXT/BINARY）
            if flags & (CURLWS_TEXT | CURLWS_BINARY):
                self._frame_buf = bytearray(data)
                self._frame_kind = flags & (CURLWS_TEXT | CURLWS_BINARY)
            elif flags & CURLWS_CONT:
                if self._frame_buf is None:
                    # 没有起始帧就收到 CONT，丢弃（不该发生）
                    continue
                self._frame_buf.extend(data)
            else:
                continue

            if left == 0:
                payload = bytes(self._frame_buf)
                kind = self._frame_kind
                self._frame_buf = None
                self._frame_kind = 0
                if kind & CURLWS_BINARY:
                    return payload
                try:
                    return payload.decode("utf-8")
                except UnicodeDecodeError:
                    return payload

            # left > 0：继续收同一帧的下一片

    # -- 生命周期 ------------------------------------------------------- #
    def close(self) -> None:
        """发送 CLOSE 帧并关闭连接。可重复调用（幂等）。"""
        if self._closed:
            return
        try:
            self._send_raw(b"", CURLWS_CLOSE)
        except RequestError:
            pass
        if self._ptr:
            self._lib.easy_cleanup(self._ptr)
        self._ptr = None
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed

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
        return "<WebSocket closed=%s>" % self._closed
