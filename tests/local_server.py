"""本地测试服务器 —— 让功能测试不依赖外部站点

为什么要本地起服务：
* httpbin.org / httpbingo.org / postman-echo.com 在本环境会拦截 curl-impersonate
  的 TLS 指纹，返回 405 或直接断连，无法作为可靠基准；
* 本地服务能精确断言"客户端到底发了什么"（方法、头、二进制体），
  这是验证 GET 被误发成 POST、响应体被 \\0 截断这类 bug 的唯一可靠手段。

用法::

    with LocalServer() as srv:
        r = nb_curl.get(srv.url("/echo"))
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__all__ = ["LocalServer"]


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nb_curl-test/1.0"

    # 关掉默认的 stderr 日志，保持测试输出干净
    def log_message(self, *args):  # noqa: D102
        pass

    # -- 工具 ---------------------------------------------------------- #
    def _read_body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n > 0 else b""

    def _send(self, code: int, payload: bytes, ctype: str = "application/json",
              extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _json(self, code: int, obj, extra: dict | None = None) -> None:
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json", extra)

    # -- 路由 ---------------------------------------------------------- #
    def _echo(self) -> None:
        body = self._read_body()
        self._json(200, {
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body.decode("utf-8", "replace"),
            "body_len": len(body),
        })

    def _dispatch(self) -> None:
        path = self.path.split("?", 1)[0]

        if path == "/echo":
            self._echo()
            return

        if path.startswith("/redirect/"):
            n = int(path.rsplit("/", 1)[1])
            target = "/echo" if n <= 1 else "/redirect/%d" % (n - 1)
            self._json(302, {"redirect": target}, {"Location": target})
            return

        if path == "/cookies/set":
            # 设置 cookie 后 302 到 /cookies
            qs = self.path.split("?", 1)[1] if "?" in self.path else ""
            cookies = []
            for pair in qs.split("&"):
                if not pair:
                    continue
                k, _, v = pair.partition("=")
                cookies.append("%s=%s; Path=/" % (k, v))
            self._json(302, {"ok": True}, {"Location": "/cookies",
                                           "Set-Cookie": "\n".join(cookies)})
            return

        if path == "/cookies":
            jar = {}
            raw = self.headers.get("Cookie") or ""
            for pair in raw.split(";"):
                pair = pair.strip()
                if pair:
                    k, _, v = pair.partition("=")
                    jar[k] = v
            self._json(200, {"cookies": jar})
            return

        if path.startswith("/status/"):
            self._json(int(path.rsplit("/", 1)[1]), {"status": "forced"})
            return

        if path.startswith("/delay/"):
            time.sleep(float(path.rsplit("/", 1)[1]))
            self._json(200, {"slept": True})
            return

        if path.startswith("/binary/"):
            # 故意包含 \0、\r\n、高位字节 —— 用于验证二进制不截断
            n = int(path.rsplit("/", 1)[1])
            pattern = b"\x00\x01\x02\xff\xfe\r\n\x00ABC"
            data = (pattern * (n // len(pattern) + 1))[:n]
            self._send(200, data, "application/octet-stream")
            return

        if path == "/gzip":
            import gzip

            raw = json.dumps({"gz": "ok", "text": "压缩测试"}).encode("utf-8")
            self._send(200, gzip.compress(raw), "application/json",
                       {"Content-Encoding": "gzip"})
            return

        self._json(404, {"error": "not found", "path": path})

    do_GET = _dispatch
    do_POST = _dispatch
    do_PUT = _dispatch
    do_PATCH = _dispatch
    do_DELETE = _dispatch
    do_OPTIONS = _dispatch
    do_HEAD = _dispatch


class LocalServer:
    """上下文管理器：在后台线程跑一个回显用 HTTP 服务。"""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self._srv = ThreadingHTTPServer((host, port), _Handler)
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self.host, self.port = self._srv.server_address[:2]

    def start(self) -> "LocalServer":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()

    def url(self, path: str = "/") -> str:
        return "http://%s:%d%s" % (self.host, self.port, path)

    def __enter__(self) -> "LocalServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
