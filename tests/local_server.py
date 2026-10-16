"""本地回归测试服务 —— 纯 stdlib、动态端口、结束即清理。

测试自洽：不 import 本目录之外的任何东西（被测实现只由用户在 ``PYTHONPATH`` /
``--package-path`` 里显式指定，测试自己不插路径）。

本服务提供下面这些端点，用来把"背压""取消""错误之后可继续"从口头断言
变成可观测事实：响应重复头、1xx 中间响应、中途断流、RST、服务端写入字节计数。

端点一览（``srv.url(path)``）：:

    GET/POST/... /echo                      回显方法/路径/头(含重复)/体的 sha256
    /binary/<n>                             含 NUL/高位/CRLF 的确定性二进制体
    /chunked/<n>                            同一份体走 Transfer-Encoding: chunked
    /dup-headers                            重复响应头 X-Dup + 两条 Set-Cookie
    /redirect/<n>                           302 链，最后一跳 /echo
    /redirect-loop                          自指向 302（用来触发 TooManyRedirects）
    /cookies/set?k=v&...                    302 -> /cookies，并 Set-Cookie
    /cookies                                回显收到的 Cookie 头
    /gzip, /gzip-binary/<n>                 Content-Encoding: gzip
    /delay/<sec>                            睡够再回（超时用例）
    /status/<code>                          指定状态码
    /drip/<chunks>/<size>?interval=<sec>    分块慢发（真增量 / 背压用例）
    /expect100                              POST 先回 1xx 再回 200
    /close-mid-body/<declared>/<actual>     声明长度大于实际写入，然后关连接
    /reset                                  SO_LINGER(1,0) 硬断（RST）
    /admin/stats, /admin/reset              计数器（同进程也可直接读 srv.stats）

所有响应都带 ``Content-Length``，``protocol_version = HTTP/1.1``，因此
连接默认保持复用 —— 连接复用/池行为也在被测范围内。
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

__all__ = ["LocalServer", "Stats", "PATTERN", "pattern_bytes", "sha256_hex"]

#: 故意包含 NUL、CRLF、0xff/0xfe 高位字节 —— "响应体被 \\0 截断" 这类 bug 的照妖镜
PATTERN = b"\x00\x01\x02\xff\xfe\r\n\x00ABC"
_JSON_CT = "application/json"
_OCTET = "application/octet-stream"


def pattern_bytes(n: int) -> bytes:
    """确定性二进制体：``n`` 字节，内容由 :data:`PATTERN` 平铺后截断。"""
    if n <= 0:
        return b""
    return (PATTERN * (n // len(PATTERN) + 1))[:n]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


# --------------------------------------------------------------------------- #
# 计数器
# --------------------------------------------------------------------------- #
class Stats:
    """线程安全的服务端计数器。

    背压用例依赖 ``path_bytes``：客户端"拿走了多少"在客户端侧不可观测，
    但"服务端写出去多少"可以 —— 两者一比就知道客户端有没有把整个响应体
    无界地吞进内存。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.started = time.time()
        self.requests = 0
        self.connections = 0
        self.active_connections = 0
        self.bytes_out = 0
        self.errors = 0
        self.aborted = 0
        self.path_requests: dict = {}
        self.path_bytes: dict = {}

    # -- 记账 ---------------------------------------------------------- #
    def note_connection(self, opened: bool) -> None:
        with self._lock:
            self.connections += 1
            self.active_connections += 1 if opened else -1

    def note_request(self, path: str) -> None:
        with self._lock:
            self.requests += 1
            self.path_requests[path] = self.path_requests.get(path, 0) + 1

    def note_bytes(self, path: str, n: int) -> None:
        with self._lock:
            self.bytes_out += n
            self.path_bytes[path] = self.path_bytes.get(path, 0) + n

    def note_error(self) -> None:
        with self._lock:
            self.errors += 1

    def note_aborted(self) -> None:
        with self._lock:
            self.aborted += 1

    def bytes_under(self, prefix: str) -> int:
        with self._lock:
            return sum(v for k, v in self.path_bytes.items() if k.startswith(prefix))

    def requests_under(self, prefix: str) -> int:
        with self._lock:
            return sum(v for k, v in self.path_requests.items() if k.startswith(prefix))

    def reset(self) -> None:
        with self._lock:
            self.requests = 0
            self.connections = 0
            self.bytes_out = 0
            self.errors = 0
            self.aborted = 0
            self.path_requests = {}
            self.path_bytes = {}

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "pid": os.getpid(),
                "wall_s": round(time.time() - self.started, 6),
                "requests": self.requests,
                "connections": self.connections,
                "active_connections": self.active_connections,
                "bytes_out": self.bytes_out,
                "errors": self.errors,
                "aborted": self.aborted,
                "path_requests": dict(self.path_requests),
                "path_bytes": dict(self.path_bytes),
                "process_cpu_s": time.process_time(),
            }


# --------------------------------------------------------------------------- #
# 处理器
# --------------------------------------------------------------------------- #
class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nb-curl-testsrv/1.0"

    # -- 噪音控制 ---------------------------------------------------------- #
    def log_message(self, *args) -> None:  # noqa: D102 - 关掉默认 stderr 日志
        pass

    def log_error(self, *args) -> None:  # noqa: D102
        pass

    @property
    def stats(self) -> Stats:
        return self.server.stats  # type: ignore[attr-defined]

    def setup(self) -> None:
        super().setup()
        # 注意：path 要等 parse_request() 才存在，setup() 阶段只能给个占位
        self._route = getattr(self, "path", "")
        self.stats.note_connection(True)

    def finish(self) -> None:
        self.stats.note_connection(False)
        super().finish()

    # -- 读 ---------------------------------------------------------------- #
    def _read_body(self) -> bytes:
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            return self._read_chunked()
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        return self.rfile.read(n) if n > 0 else b""

    def _read_chunked(self) -> bytes:
        out = bytearray()
        while True:
            line = self.rfile.readline(65536)
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                size = int(line.split(b";", 1)[0], 16)
            except ValueError:
                break
            if size == 0:
                while True:                     # 吃掉 trailer
                    tail = self.rfile.readline(65536)
                    if tail in (b"\r\n", b"\n", b""):
                        break
                break
            out += self.rfile.read(size)
            self.rfile.read(2)                  # 块尾 CRLF
        return bytes(out)

    # -- 写 ---------------------------------------------------------------- #
    def _send(self, code: int, payload: bytes, ctype: str = _JSON_CT,
              extra=None, extra_multi=None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        for k, v in (extra_multi or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD" and payload:
            self.wfile.write(payload)
            self.stats.note_bytes(self._route, len(payload))

    def _json(self, code: int, obj, extra=None, extra_multi=None) -> None:
        self._send(code, _json_bytes(obj), _JSON_CT, extra, extra_multi)

    # -- 路由 -------------------------------------------------------------- #
    def _dispatch(self) -> None:
        parts = urlsplit(self.path)
        path = parts.path
        self._route = path
        q = parse_qs(parts.query, keep_blank_values=True)
        self.stats.note_request(path)
        try:
            self._route_dispatch(path, q)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # 客户端提前断开（close/取消/背压用例的预期行为），不算服务端故障
            self.stats.note_aborted()
            self.close_connection = True

    def _route_dispatch(self, path: str, q: dict) -> None:
        if path == "/echo":
            return self._r_echo()
        if path == "/dup-headers":
            return self._r_dup_headers()
        if path == "/redirect-loop":
            return self._r_redirect("/redirect-loop")
        if path == "/cookies/set":
            return self._r_cookies_set(q)
        if path == "/cookies":
            return self._r_cookies()
        if path == "/gzip":
            return self._r_gzip()
        if path == "/expect100":
            return self._r_expect100()
        if path == "/reset":
            return self._r_reset()
        if path == "/admin/stats":
            return self._json(200, self.stats.snapshot())
        if path == "/admin/reset":
            self.stats.reset()
            return self._json(200, {"ok": True})
        if path.startswith("/drip/"):
            chunks_s, _, size_s = path[len("/drip/"):].partition("/")
            interval = _float(q.get("interval", ["0.3"])[0])
            return self._r_drip(_int(chunks_s), _int(size_s), interval)
        if path.startswith("/close-mid-body/"):
            declared_s, _, actual_s = path[len("/close-mid-body/"):].partition("/")
            return self._r_close_mid_body(_int(declared_s), _int(actual_s))

        base, _, arg = path.rpartition("/")
        if base == "/binary":
            return self._send(200, pattern_bytes(_int(arg)), _OCTET)
        if base == "/chunked":
            return self._r_chunked(_int(arg))
        if base == "/gzip-binary":
            return self._r_gzip_binary(_int(arg))
        if base == "/redirect":
            return self._r_redirect("/echo" if _int(arg) <= 1 else "/redirect/%d" % (_int(arg) - 1))
        if base == "/delay":
            time.sleep(max(0.0, _float(arg)))
            return self._json(200, {"slept": _float(arg)})
        if base == "/status":
            return self._json(_int(arg), {"status": "forced", "code": _int(arg)})
        return self._json(404, {"error": "not found", "path": path})

    # -- 各端点 ------------------------------------------------------------ #
    def _r_echo(self) -> None:
        body = self._read_body()
        out = {
            "method": self.command,
            "path": self.path,
            "query": {k: v[0] for k, v in parse_qs(urlsplit(self.path).query,
                                                  keep_blank_values=True).items()},
            "query_list": parse_qs(urlsplit(self.path).query, keep_blank_values=True),
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "header_list": [[k.lower(), v] for k, v in self.headers.items()],
            "cookie": self.headers.get("Cookie") or "",
            "body_len": len(body),
            "body_sha256": sha256_hex(body),
            "body_text": body.decode("utf-8", "replace"),
        }
        if len(body) <= 65536:
            out["body_b64"] = base64.b64encode(body).decode("ascii")
        self._json(200, out)

    def _r_dup_headers(self) -> None:
        self._json(
            200,
            {"ok": True, "note": "duplicate response headers"},
            extra_multi=[("X-Dup", "a"), ("X-Dup", "b"),
                         ("Set-Cookie", "sid=1; Path=/"),
                         ("Set-Cookie", "other=2; Path=/")],
        )

    def _r_redirect(self, target: str) -> None:
        self._json(302, {"redirect": target}, extra={"Location": target})

    def _r_cookies_set(self, q: dict) -> None:
        multi = [("Set-Cookie", "%s=%s; Path=/" % (k, v[0])) for k, v in q.items()]
        self._json(302, {"ok": True}, extra={"Location": "/cookies"}, extra_multi=multi)

    def _r_cookies(self) -> None:
        jar = {}
        for pair in (self.headers.get("Cookie") or "").split(";"):
            pair = pair.strip()
            if pair:
                k, _, v = pair.partition("=")
                jar[k] = v
        self._json(200, {"cookies": jar, "raw": self.headers.get("Cookie") or ""})

    def _r_gzip(self) -> None:
        raw = _json_bytes({"gz": "ok", "text": "压缩测试"})
        self._send(200, gzip.compress(raw), _JSON_CT, extra={"Content-Encoding": "gzip"})

    def _r_gzip_binary(self, n: int) -> None:
        self._send(200, gzip.compress(pattern_bytes(n)), _OCTET,
                   extra={"Content-Encoding": "gzip"})

    def _r_chunked(self, n: int) -> None:
        """同一份确定性二进制体，走 chunked 传输编码。"""
        payload = pattern_bytes(n)
        self.send_response(200)
        self.send_header("Content-Type", _OCTET)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        if self.command == "HEAD":
            return
        step = 1024
        for i in range(0, max(len(payload), 1), step):
            piece = payload[i:i + step]
            if not piece:
                break
            self.wfile.write(b"%x\r\n" % len(piece) + piece + b"\r\n")
            self.stats.note_bytes(self._route, len(piece))
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def _r_drip(self, chunks: int, size: int, interval: float) -> None:
        """分多次、带间隔地发同一份体：真增量与背压的最小可观测模型。"""
        chunks = max(1, chunks)
        size = max(1, size)
        total = chunks * size
        payload = pattern_bytes(size)
        self.send_response(200)
        self.send_header("Content-Type", _OCTET)
        self.send_header("Content-Length", str(total))
        self.end_headers()
        if self.command == "HEAD":
            return
        for _ in range(chunks):
            self.wfile.write(payload)
            self.wfile.flush()
            self.stats.note_bytes(self._route, len(payload))
            if interval > 0:
                time.sleep(interval)

    def _r_expect100(self) -> None:
        """先回一个 1xx 中间响应，再回最终响应。

        libcurl 对请求体较大的 POST 会自带 ``Expect: 100-continue``；
        这里无条件先发 100，再读体 —— 无论客户端有没有带 Expect，
        "中间响应块不能打乱最终响应解析"这条都必须成立。
        """
        self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        self.wfile.flush()
        body = self._read_body()
        self._json(200, {"body_len": len(body), "body_sha256": sha256_hex(body),
                         "interim": True})

    def _r_close_mid_body(self, declared: int, actual: int) -> None:
        """声明 Content-Length 大于实际写入，然后关闭连接（短体错误）。"""
        body = pattern_bytes(min(actual, declared))
        self.send_response(200)
        self.send_header("Content-Type", _OCTET)
        self.send_header("Content-Length", str(max(declared, len(body) + 1)))
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)
            self.wfile.flush()
            self.stats.note_bytes(self._route, len(body))
        self.close_connection = True
        try:
            self.connection.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def _r_reset(self) -> None:
        """SO_LINGER(1,0) + close -> RST：模拟对端硬断。"""
        self.stats.note_aborted()
        try:
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                       struct.pack("ii", 1, 0))
        except OSError:
            pass
        self.close_connection = True
        try:
            self.connection.close()
        except OSError:
            pass

    # 所有方法都进同一个路由
    do_GET = _dispatch
    do_POST = _dispatch
    do_PUT = _dispatch
    do_PATCH = _dispatch
    do_DELETE = _dispatch
    do_OPTIONS = _dispatch
    do_HEAD = _dispatch


def _int(text: str, default: int = 0) -> int:
    try:
        return int(text)
    except (TypeError, ValueError):
        return default


def _float(text: str, default: float = 0.0) -> float:
    try:
        return float(text)
    except (TypeError, ValueError):
        return default


class _Server(ThreadingHTTPServer):
    request_queue_size = 128
    daemon_threads = True
    allow_reuse_address = True
    stats: Stats = None  # type: ignore[assignment]

    def handle_error(self, request, client_address) -> None:
        exc = sys.exc_info()[1]
        self.stats.note_error()
        if isinstance(exc, (BrokenPipeError, ConnectionResetError,
                            ConnectionAbortedError, socket.timeout, OSError)):
            return                          # 客户端提前断开是用例的一部分，不当噪音
        traceback.print_exc()


# --------------------------------------------------------------------------- #
# 上下文管理器
# --------------------------------------------------------------------------- #
class LocalServer:
    """在后台线程里跑一个 HTTP/1.1 keepalive 服务；端口默认动态绑定（0）。"""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.stats = Stats()
        self._srv = _Server((host, port), _Handler)
        self._srv.stats = self.stats
        self.host, self.port = self._srv.server_address[:2]
        self._thread = threading.Thread(target=self._srv.serve_forever,
                                        name="nb-testsrv", daemon=True)
        self._started = False
        self._stopped = False

    # -- 生命周期 ---------------------------------------------------------- #
    def start(self) -> "LocalServer":
        if not self._started:
            self._thread.start()
            self._started = True
        return self

    def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        try:
            self._srv.shutdown()
        finally:
            self._srv.server_close()
            if self._started:
                self._thread.join(timeout=5.0)

    # -- 辅助 -------------------------------------------------------------- #
    def url(self, path: str = "/") -> str:
        return "http://%s:%d%s" % (self.host, self.port, path)

    def stats_snapshot(self) -> dict:
        return self.stats.snapshot()

    def __enter__(self) -> "LocalServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
