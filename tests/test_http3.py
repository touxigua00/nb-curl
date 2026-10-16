"""HTTP/3 普通功能回归（独立套件）：本地 aioquic H3 UDP 服务端 + nb_curl 强制 HTTP3_ONLY。

只做普通 localhost 功能：不碰第三方站点、不做性能/压测、不做指纹或反检测。要点：服务端绑
``127.0.0.1`` + UDP 端口 0（内核分配）、ALPN
只给 ``h3``（协商不到就关连接并计数）；证书复用 ``protocol_fixtures.CertBundle``（临时 CA +
SAN ``localhost``/``127.0.0.1`` 的叶子证书），另用无亲缘的"错误 CA"做负向对照；客户端
``http_version="3only"``（``const.resolve_http_version`` → 31 = ``CURL_HTTP_VERSION_3ONLY``）不许
静默降级，断言 ``resp.http_version == "3"``；响应体是二进制且含 NUL，逐字节比对。URL 用
``127.0.0.1`` 而非 ``localhost``：只绑了 IPv4 UDP，避免先解析到 ``::1``，而叶子证书的
``iPAddress`` SAN 仍让主机名校验真实生效。

缺 ``aioquic``（或客户端 native 未含 ``nghttp3``）→ 记 **blocked** 并退出 3：不装依赖、不把跳过
当通过。用法::

    python tests/test_http3.py --package-path . --backend cffi

退出码：0 = 全部通过；1 = 有失败；2 = 实现选择/导入失败；3 = blocked（缺依赖/未编译 H3）。
"""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import importlib
import json
import os
import sys
import threading
import time
import traceback
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:   # 只为 import 同目录的 protocol_fixtures（不是被测实现路径）
    sys.path.insert(0, str(_HERE))
import protocol_fixtures as fx  # noqa: E402

HOST = fx.HOST
HTTP_VERSION_ARG = "3only"                  # const.resolve_http_version("3only") == 31
HTTP3_ONLY_CODE = 31                        # const.CURL_HTTP_VERSION_3ONLY
UNSUPPORTED_PROTOCOL, NOT_BUILT_IN = 1, 4   # 客户端没编译 H3 时 curl 报的错误码
CERT_VERIFY_FAILED = 60                     # CURLE_PEER_FAILED_VERIFICATION
H3_WORKERS = 8
PROXY_ENV_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
# 二进制响应体：首/中/尾都有 NUL，再跟全部 256 个字节值——任何"当文本处理"
# （截断、去 NUL、编码转换）的实现都会在这里露馅。
H3_BODY = b"\x00h3\x00binary\xff\xfe\r\n" + bytes(range(256)) + b"\x00end\x00"
EXIT_OK, EXIT_FAIL, EXIT_SETUP, EXIT_BLOCKED = 0, 1, 2, 3


def unit_tests() -> int:
    """离线单元测试：不需要网络/依赖/被测实现，失败返回 1。"""
    ok = True
    s = Suite()
    s.case("u")
    s.check("先失败", False, "x"); s.check("后通过", True)
    if not (s._cur["status"] == "fail" and s.failed == 1 and s.passed == 1):
        print("[UNIT FAIL] Suite.check 失败粘滞被覆盖"); ok = False
    s2 = Suite(); s2.case("v"); s2.check("全过", True)
    if s2._cur["status"] != "pass":
        print("[UNIT FAIL] 全过应为 pass"); ok = False
    print("[UNIT] %s" % ("全部通过" if ok else "有失败"))
    return EXIT_OK if ok else EXIT_FAIL


def aioquic_report() -> dict:
    """aioquic 可用性：不装依赖，不可用就如实 blocked。"""
    need = "本地 HTTP/3（QUIC/UDP）服务端"
    try:
        import aioquic
        from aioquic.h3.connection import H3_ALPN
        return {"ok": True, "used": True, "needed_for": need, "alpn": list(H3_ALPN),
                "version": getattr(aioquic, "__version__", None), "error": None}
    except BaseException as exc:  # noqa: BLE001
        return {"ok": False, "used": True, "needed_for": need, "alpn": None, "version": None,
                "error": "%s: %s" % (type(exc).__name__, exc)}


class Suite:
    """极小结果记录：case/check/block + 通过失败计数（不是通用测试框架）。"""

    def __init__(self) -> None:
        self.cases, self.blocked, self.passed, self.failed, self._cur = [], [], 0, 0, None

    def case(self, name: str) -> None:
        self._cur = {"case": name, "checks": [], "seconds": 0.0, "status": "pass"}
        self.cases.append(self._cur)

    def check(self, name: str, ok, detail: str = "") -> bool:
        ok = bool(ok)
        self._cur["checks"].append({"name": name, "ok": ok, "detail": str(detail)[:300]})
        if not ok:                       # 失败粘滞：一旦 fail 不被后续 pass 覆盖
            self._cur["status"] = "fail"
        self.passed, self.failed = self.passed + ok, self.failed + (not ok)
        print("      [%s] %s%s" % ("PASS" if ok else "FAIL", name, "" if ok else "   " + str(detail)[:160]))
        return ok

    def data(self, **kw) -> None:
        """把结构化数据（如并发逐轮结果）挂到当前用例，进 JSON 报告。"""
        self._cur.setdefault("data", {}).update(kw)

    def block(self, scope: str, reason: str, cases: list | None = None) -> None:
        self.blocked.append({"scope": scope, "reason": reason, "cases": list(cases or [])})
        print("      [BLOCKED] %s —— %s" % (scope, reason))


def _safe(fn):
    try:
        return fn()
    except BaseException as exc:  # noqa: BLE001
        return "<error: %r>" % (exc,)


def select_implementation(paths: list):
    """按显式给出的目录选 nb_curl（不传就用当前 sys.path）；返回 (module, info)。"""
    info = {"requested_paths": [str(p) for p in paths], "resolved": None, "error": None,
            "matched_package_path": None, "version": None, "backend": None,
            "backend_info": None, "native_version": None}
    dirs = [Path(p).expanduser() for p in paths]
    if [str(d) for d in dirs if not d.is_dir()]:
        info["error"] = "package-path 不存在或不是目录: %s" % [str(d) for d in dirs if not d.is_dir()]
        return None, info
    for d in reversed(dirs):
        sys.path.insert(0, str(d))
    try:
        mod = importlib.import_module("nb_curl")
        mod_file = Path(getattr(mod, "__file__", "") or "<unknown>").resolve()
    except BaseException as exc:  # noqa: BLE001
        info["error"] = "import nb_curl 失败: %r" % (exc,)
        return None, info
    info.update({"resolved": str(mod_file), "version": getattr(mod, "__version__", None),
                 "backend": _safe(getattr(mod, "backend_name", lambda: None)),
                 "backend_info": _safe(getattr(mod, "backend_info", lambda: None)),
                 "native_version": _safe(getattr(mod, "native_version", lambda: None))})
    hit = []
    for d in dirs:
        try:
            if os.path.commonpath([str(mod_file), str(d)]) == str(d):
                hit.append(str(d))
        except ValueError:      # 不同盘符没有公共前缀
            pass
    if dirs and not hit:
        info["error"] = "import 到的 nb_curl 不在指定 package-path 内：%s" % mod_file
        return None, info
    info["matched_package_path"] = hit[0] if hit else None
    return mod, info


def server_event_loop():
    """夹具服务端用的事件循环 —— **Windows 上必须用 SelectorEventLoop**。

    默认的 ``ProactorEventLoop`` 在 UDP 上有个致命缺陷（CPython 3.11
    ``Lib/asyncio/proactor_events.py`` 的 ``_ProactorDatagramTransport._loop_reading``）：
    挂起的 ``recvfrom`` 若以 ``WSAECONNRESET`` 完成，asyncio 只调用
    ``protocol.error_received(exc)``，**不再重新挂 recvfrom** —— 这个 UDP 服务端从此
    一个包都收不到，而且没有任何异常、日志或回调。selector 版（``_read_ready``）在同样的
    错误分支里只调 ``error_received``，fd 仍在 selector 上，后续数据照收。

    触发链：客户端发完 QUIC CONNECTION_CLOSE 就正常关掉自己的 UDP socket（QUIC 允许，
    服务器本该容忍），夹具服务端随后还有一个包要发给它 → ICMP 端口不可达 → 服务端 socket
    收到 WSAECONNRESET → 夹具整体变聋 → 同一批里剩下的请求全部卡到超时
    （表现为 h3.concurrent_8 偶发 7/8 或 0/8）。

    最小复现（不需要 nb_curl）：起一个 asyncio UDP 服务端，让客户端 A 收一个包后关掉 A，
    服务端再往 A 发一个包；随后让客户端 B 发包 —— ProactorEventLoop 下收不到 B 的包，
    SelectorEventLoop 下收得到。
    """
    if sys.platform == "win32":
        return asyncio.SelectorEventLoop()
    return asyncio.new_event_loop()


def protocol_class(server: "H3Server"):
    """协议类工厂：aioquic 只在真要跑时 import，缺依赖也能 --help。"""
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import HeadersReceived
    from aioquic.quic.events import ProtocolNegotiated

    class H3Protocol(QuicConnectionProtocol):
        _http = None
        _cid = None

        @property
        def cid(self):                 # 连接短标识（不收集敏感内容，只用于对账时间线）
            if self._cid is None:
                self._cid = "c%04x" % (hash(self._quic.host_cid) & 0xFFFF)
            return self._cid

        def quic_event_received(self, event) -> None:
            if isinstance(event, ProtocolNegotiated):
                server.note("connections", 1)
                server.note("alpn", event.alpn_protocol)
                server.event(self.cid, "handshake alpn=%s" % event.alpn_protocol)
                if event.alpn_protocol != "h3":
                    server.note("errors", "ALPN=%r（服务端只提供 h3）" % (event.alpn_protocol,))
                    return self.close()
                self._http = H3Connection(self._quic, enable_webtransport=False)
            if self._http is not None:
                for ev in self._http.handle_event(event):
                    # 只服务带 END_STREAM 的 HEADERS（本套件全是 GET）；aioquic 1.3.0 的
                    # H3Connection 没有 send_flow_control_credit，别写"看着能用"的死代码。
                    if isinstance(ev, HeadersReceived):
                        server.note("requests", {k.decode("latin-1"): v.decode("latin-1") for k, v in ev.headers})
                        server.note("reqs_per_conn", self.cid)
                        server.event(self.cid, "request :path=%s" %
                                     dict((k.decode("latin-1"), v.decode("latin-1"))
                                          for k, v in ev.headers).get(":path"))
                        if ev.stream_ended:
                            self.reply(ev.stream_id)

        def connection_lost(self, exc) -> None:      # 记 termination 时刻，区分握手失败与中途断开
            try:
                server.event(self.cid, "close")
            finally:
                super().connection_lost(exc)

        def reply(self, stream_id: int) -> None:     # 二进制含 NUL 的响应体
            body = server.body
            self._http.send_headers(stream_id, [
                (b":status", b"200"), (b"content-type", b"application/octet-stream"),
                (b"content-length", str(len(body)).encode()), (b"x-nb-curl-h3", b"1")])
            self._http.send_data(stream_id, body, end_stream=True)
            self.transmit()
            server.note("responses", 1)
            server.event(self.cid, "response")

    return H3Protocol


class H3Server:
    """本地 aioquic HTTP/3 服务端：UDP / 127.0.0.1 / 动态端口 / ALPN 只给 h3。

    接受循环跑在独立线程的独立事件循环里（同步的 nb_curl 用例不用自己管 asyncio）。
    """

    def __init__(self, certfile, keyfile, body: bytes = H3_BODY, host: str = HOST) -> None:
        self.certfile, self.keyfile, self.body, self.host = str(certfile), str(keyfile), body, host
        self.port = None
        self.stats = {"connections": 0, "responses": 0, "alpn": [], "requests": [], "errors": [],
                      "reqs_per_conn": [],          # 每条连接各服务了几个请求 → 连接复用的服务端证据
                      "timeline": []}     # 每连接 handshake/request/response/close 相对时刻（秒，非敏感）
        self._lock = threading.Lock()
        self._stop, self._ready = threading.Event(), threading.Event()
        self._loop = self._thread = self._server = None

    def note(self, key, value) -> None:            # 协议回调线程内调用
        with self._lock:
            if isinstance(self.stats[key], int):
                self.stats[key] += int(value)
            else:
                self.stats[key].append(value)

    def event(self, cid, what: str) -> None:       # 时间线：相对服务端 epoch 的秒，只记时刻与类型
        with self._lock:
            self.stats["timeline"].append({"conn": cid, "t": round(time.monotonic() - self._t0, 4),
                                           "event": what})

    def snapshot(self) -> dict:
        with self._lock:
            return {k: (v if isinstance(v, int) else list(v)) for k, v in self.stats.items()}

    def url(self, path: str = "/h3") -> str:
        return "https://%s:%d%s" % (HOST, self.port, path)

    def start(self) -> "H3Server":
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        if not self._ready.wait(20) or self.port is None:
            raise RuntimeError("aioquic H3 服务端未就绪：%s" % (self.snapshot()["errors"],))
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None

    def _run(self) -> None:
        loop = server_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._serve())
        except BaseException as exc:  # noqa: BLE001
            self.note("errors", "%s: %s" % (type(exc).__name__, exc))
        finally:
            self._ready.set()      # 启动失败也要让 start() 醒过来，别挂 20s
            loop.close()

    async def _serve(self) -> None:
        from aioquic.asyncio import serve
        from aioquic.h3.connection import H3_ALPN
        from aioquic.quic.configuration import QuicConfiguration

        cfg = QuicConfiguration(is_client=False, alpn_protocols=list(H3_ALPN))
        cfg.load_cert_chain(self.certfile, self.keyfile)
        self._t0 = time.monotonic()
        self._server = await serve(self.host, 0, configuration=cfg, create_protocol=protocol_class(self))
        self.port = int(self._server._transport.get_extra_info("sockname")[1])   # 无公开取端口 API
        self._ready.set()
        await self._loop.run_in_executor(None, self._stop.wait)
        self._server.close()
        await asyncio.sleep(0.1)


class Ctx:
    """用例上下文：被测模块 + 夹具 + 参数（没有隐式全局状态）。"""

    def __init__(self, mod, suite: Suite, args, info: dict, const) -> None:
        self.mod, self.suite, self.args, self.info, self.const = mod, suite, args, info, const
        self.bundle = self.server = None
        self.h3_abort = False

    def get_h3(self, url: str, **kw):
        """强制 HTTP3_ONLY 发一次 GET，返回 ``(ok, resp, err)``。

        客户端 native 没编译 H3（CURLE_UNSUPPORTED_PROTOCOL / CURLE_NOT_BUILT_IN）时记 blocked
        并置 ``h3_abort``，避免把"环境不具备"报成"协议失败"。
        """
        try:
            with self.mod.Session(http_version=HTTP_VERSION_ARG, timeout=25, connect_timeout=10, **kw) as s:
                return True, s.get(url), None
        except BaseException as exc:  # noqa: BLE001
            if getattr(exc, "code", None) in (UNSUPPORTED_PROTOCOL, NOT_BUILT_IN):
                if not self.h3_abort:
                    self.suite.block("h3.client_unsupported", "客户端未编译 H3：%s" % exc)
                self.h3_abort = True
            return False, None, exc


# --------------------------------------------------------------------------- #
# 用例（每条 check 都是硬断言）
# --------------------------------------------------------------------------- #
def case_impl(c: Ctx) -> None:
    req = (c.args.backend or "").strip().lower()
    print("      [info] 实现=%s 版本=%s 后端=%s" % (c.info["resolved"], c.info["version"], c.info["backend"]))
    c.suite.check("实现选择无错误（未偷偷加载别处的 nb_curl）", not c.info["error"], str(c.info["error"]))
    if c.args.package_path:
        c.suite.check("nb_curl 落在显式指定的 --package-path 内", bool(c.info["matched_package_path"]))
    if req in ("cffi", "ctypes"):
        c.suite.check("请求的 --backend 被满足（不静默回退）", c.info["backend"] == req, "实际 %r" % c.info["backend"])
    c.suite.check("公开 API 存在：Session / RequestError", hasattr(c.mod, "Session") and hasattr(c.mod, "RequestError"))


def case_const(c: Ctx) -> None:
    k = c.const
    c.suite.check("const.CURL_HTTP_VERSION_3ONLY == 31", k.CURL_HTTP_VERSION_3ONLY == 31, "got=%r" % k.CURL_HTTP_VERSION_3ONLY)
    c.suite.check("resolve_http_version('3only') == 31（本套件的强制值）",
                  k.resolve_http_version(HTTP_VERSION_ARG) == HTTP3_ONLY_CODE, "got=%r" % k.resolve_http_version(HTTP_VERSION_ARG))
    c.suite.check("resolve_http_version('3') == 30 且有别于 3ONLY（允许降级，故不用）",
                  k.resolve_http_version("3") == 30 != HTTP3_ONLY_CODE, "got=%r" % k.resolve_http_version("3"))
    c.suite.check("http_version_name(31) == '3'（resp.http_version 的口径）",
                  k.http_version_name(HTTP3_ONLY_CODE) == "3", "got=%r" % k.http_version_name(HTTP3_ONLY_CODE))


def case_local_binary(c: Ctx) -> None:
    if c.h3_abort:
        return
    ok, resp, err = c.get_h3(c.server.url(), ca_path=str(c.bundle.ca_path))
    if not c.suite.check("强制 HTTP3_ONLY + verify=True/本地 CA 下请求成功", ok, repr(err)[:200]):
        return
    c.suite.check("状态码 200", resp.status_code == 200, "status=%r" % resp.status_code)
    c.suite.check("响应体逐字节等于二进制载荷（含 NUL，共 %d 字节）" % len(H3_BODY), resp.content == H3_BODY,
                  "len=%d head=%r" % (len(resp.content), resp.content[:64]))
    c.suite.check("resp.http_version == '3'（真走了 HTTP/3，没降级到 h2/h1）", resp.http_version == "3",
                  "http_version=%r" % resp.http_version)
    c.suite.check("响应头 content-type 为 application/octet-stream", "octet-stream" in resp.content_type,
                  "content_type=%r" % resp.content_type)
    snap = c.server.snapshot()
    c.suite.check("服务端 QUIC ALPN 协商为 h3（无 h2/h1 降级）",
                  bool(snap["alpn"]) and set(snap["alpn"]) == {"h3"}, "alpn=%r" % snap["alpn"])
    c.suite.check("服务端记录到 1 条请求且路径为 /h3", [r.get(":path") for r in snap["requests"]] == ["/h3"],
                  "requests=%r" % [r.get(":path") for r in snap["requests"]])


def case_wrong_ca(c: Ctx) -> None:
    if c.h3_abort:
        return
    before = c.server.snapshot()["responses"]
    ok, resp, err = c.get_h3(c.server.url(), ca_path=str(c.bundle.rogue_ca_path))
    c.suite.check("错误 CA 下必须被拒绝（不返回 200）", (not ok) and resp is None, repr(err)[:200])
    c.suite.check("拒绝原因是证书校验失败（curl code 60）", getattr(err, "code", None) == CERT_VERIFY_FAILED,
                  "code=%r" % getattr(err, "code", None))
    c.suite.check("被拒期间服务端没有新增任何响应", c.server.snapshot()["responses"] == before,
                  "before=%d after=%d" % (before, c.server.snapshot()["responses"]))


def case_concurrent(c: Ctx) -> None:
    if c.h3_abort:
        return
    url, before = c.server.url(), c.server.snapshot()
    with concurrent.futures.ThreadPoolExecutor(max_workers=H3_WORKERS) as ex:
        results = list(ex.map(lambda _i: c.get_h3(url, ca_path=str(c.bundle.ca_path)), range(H3_WORKERS)))
    oks = [r[1] for r in results if r[0]]
    c.suite.check("%d 个并发请求全部成功" % H3_WORKERS, len(oks) == H3_WORKERS,
                  "errors=%r" % [repr(r[2])[:80] for r in results if not r[0]])
    c.suite.check("并发响应体全部逐字节一致（含 NUL）",
                  len(oks) == H3_WORKERS and all(r.content == H3_BODY for r in oks),
                  "lens=%r" % [len(r.content) for r in oks])
    c.suite.check("并发响应的 http_version 全部为 '3'",
                  len(oks) == H3_WORKERS and all(r.http_version == "3" for r in oks),
                  "versions=%r" % sorted({r.http_version for r in oks}))
    snap = c.server.snapshot()
    c.suite.check("服务端新增响应数 >= %d" % H3_WORKERS, snap["responses"] - before["responses"] >= H3_WORKERS,
                  "delta=%d" % (snap["responses"] - before["responses"]))
    c.suite.check("服务端观测到的 ALPN 全是 h3（无 h2/h1 降级）",
                  bool(snap["alpn"]) and set(snap["alpn"]) == {"h3"}, "alpn=%r" % snap["alpn"])
    c.suite.check("服务端未记录协议/ALPN 错误", not snap["errors"], "errors=%r" % snap["errors"])


def case_reuse(c: Ctx) -> None:
    """同 Session 连续两个请求：硬断言服务端只见到 1 条连接（连接复用）。"""
    if c.h3_abort:
        return
    before = c.server.snapshot()
    ok1 = ok2 = False
    r1 = r2 = None
    err1 = err2 = None
    try:
        with c.mod.Session(http_version=HTTP_VERSION_ARG, timeout=25, connect_timeout=10) as s:
            ok1, r1, err1 = True, s.get(c.server.url(), ca_path=str(c.bundle.ca_path)), None
            ok2, r2, err2 = True, s.get(c.server.url("/h3?second=1"), ca_path=str(c.bundle.ca_path)), None
    except BaseException as exc:  # noqa: BLE001
        if not ok1:
            ok1, err1 = False, exc
        else:
            ok2, err2 = False, exc
    c.suite.check("第 1 个请求成功", bool(ok1), repr(err1)[:200])
    if not ok1:
        return
    c.suite.check("第 2 个请求成功（同 Session 复用连接）", bool(ok2), repr(err2)[:200])
    if not ok2:
        return
    c.suite.check("两个响应体均逐字节一致", r1.content == H3_BODY and r2.content == H3_BODY,
                  "lens=%r" % [len(r.content) for r in (r1, r2)])
    snap = c.server.snapshot()
    delta_conns = snap["connections"] - before["connections"]
    delta_reqs = len(snap["requests"]) - len(before["requests"])
    per_conn = sorted(snap["reqs_per_conn"][len(before["reqs_per_conn"]):])
    c.suite.check("连接复用：2 个请求只新增 1 条 QUIC 连接", delta_conns == 1,
                  "conns_delta=%d requests_delta=%d" % (delta_conns, delta_reqs))
    c.suite.check("该连接服务端顺序服务了 2 个请求",
                  delta_reqs == 2 and len(per_conn) == 2 and len(set(per_conn)) == 1,
                  "per_conn=%r delta_reqs=%d" % (per_conn, delta_reqs))


CASES = [("impl.select", (), case_impl),
         ("h3.const_http3_only", (), case_const),
         ("h3.local_verify_binary", ("aioquic", "cryptography"), case_local_binary),
         ("h3.wrong_ca_rejected", ("aioquic", "cryptography"), case_wrong_ca),
         ("h3.session_reuse", ("aioquic", "cryptography"), case_reuse),
         ("h3.concurrent_8", ("aioquic", "cryptography"), case_concurrent)]


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="nb_curl HTTP/3 普通功能回归（本地 aioquic；不碰第三方、不装依赖）")
    p.add_argument("--package-path", action="append", default=[], metavar="DIR",
                   help="nb_curl 所在目录（可多次给）。不传则用当前 sys.path/PYTHONPATH。")
    p.add_argument("--backend", default="", choices=["", "auto", "cffi", "ctypes"],
                   help="强制 NB_CURL_BACKEND（导入前生效）；不匹配即视为 setup 失败")
    p.add_argument("--aioquic-path", action="append", default=[], metavar="DIR",
                   help="额外的 aioquic 搜索目录（如 build/tools/h3libs），导入前插入 sys.path")
    p.add_argument("--json", default="", metavar="PATH",
                   help="JSON 报告路径（默认写到 <仓库根>/reports/http3-<backend>-<时间>.json）")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    for raw in reversed(args.aioquic_path):
        d = Path(raw).expanduser()
        if not d.is_dir():
            print("[SETUP FAIL] --aioquic-path 不存在或不是目录: %s" % d)
            return EXIT_SETUP
        if str(d) not in sys.path:
            sys.path.insert(0, str(d))
    for key in list(os.environ):
        if key.lower() in PROXY_ENV_VARS:
            os.environ.pop(key, None)
    if args.backend:
        os.environ["NB_CURL_BACKEND"] = args.backend
    print("=" * 78)
    print("nb_curl HTTP/3 普通功能回归（本地 aioquic H3 UDP / 强制 HTTP3_ONLY）")
    print("=" * 78)
    mod, info = select_implementation(args.package_path)
    if mod is None:
        print("[SETUP FAIL] %s" % info["error"])
        print("提示：用 --package-path <目录> 指定实现；本套件不会自动插入其它路径。")
        return EXIT_SETUP
    req = (args.backend or "").strip().lower()
    if req in ("cffi", "ctypes") and info["backend"] != req:
        print("[SETUP FAIL] 请求 backend=%r，实际 %r（拒绝静默回退）" % (req, info["backend"]))
        return EXIT_SETUP
    const = importlib.import_module(mod.__name__ + ".const")
    print("  实现      : %s\n  版本/后端 : %s / %s\n  curl 版本 : %s"
          % (info["resolved"], info["version"], info["backend"], info["native_version"]))

    deps = {"aioquic": aioquic_report(), "cryptography": fx.deps_report()["cryptography"]}
    for name, d in deps.items():
        print("  依赖 %-12s: %s" % (name, "可用 version=%s" % d["version"] if d["ok"]
                                    else "不可用 —— %s" % d["error"]))
    suite = Suite()
    ctx = Ctx(mod, suite, args, info, const)
    for name, needs, _fn in CASES:
        missing = [n for n in needs if not deps[n]["ok"]]
        if missing:
            suite.block(name, "缺依赖：%s" % ", ".join("%s(%s)" % (n, deps[n]["error"]) for n in missing), [name])
    # 客户端 native 未编译 nghttp3 时 H3 必然不可用：同样记 blocked，不报成协议失败
    client_h3 = "nghttp3" in (str(info["native_version"]) + str(info["backend_info"]))
    if not client_h3:
        suite.block("client.h3_build",
                    "客户端 native 未含 nghttp3（本构建无 H3），不发 H3 请求：%s" % (info["native_version"],))
    server = None
    try:
        if deps["aioquic"]["ok"] and deps["cryptography"]["ok"] and client_h3:
            ctx.bundle = fx.CertBundle.create()
            server = ctx.server = H3Server(ctx.bundle.cert_path, ctx.bundle.key_path).start()
            print("  夹具      : H3/UDP %s:%d ALPN=%s body=%d 字节"
                  % (HOST, server.port, deps["aioquic"]["alpn"], len(H3_BODY)))
        print("-" * 78)
        for name, needs, fn in CASES:
            if any(not deps[n]["ok"] for n in needs) or (needs and not client_h3):
                continue        # 缺依赖的组已记 blocked，这里不执行也不伪造结果
            print("\n== %s ==" % name)
            suite.case(name)
            t0 = time.perf_counter()
            try:
                fn(ctx)
            except BaseException as exc:  # noqa: BLE001
                suite.check("用例自身未抛异常", False, "%s: %s" % (type(exc).__name__, exc))
                traceback.print_exc()
            suite._cur["seconds"] = round(time.perf_counter() - t0, 3)
    finally:
        if server is not None:
            try:
                server.stop()
            except Exception:  # noqa: BLE001
                traceback.print_exc()
        if ctx.bundle is not None:
            ctx.bundle.cleanup()

    print("\n" + "=" * 78)
    print("结果：%d 条断言，通过 %d，失败 %d，blocked %d"
          % (suite.passed + suite.failed, suite.passed, suite.failed, len(suite.blocked)))
    for case in suite.cases:
        for ck in case["checks"]:
            if not ck["ok"]:
                print("  [FAIL] %s / %s   %s" % (case["case"], ck["name"], ck["detail"][:140]))
    for b in suite.blocked:
        print("  [BLOCKED] %s —— %s" % (b["scope"], b["reason"]))
    out = Path(args.json) if args.json else (_HERE.parent / "reports" / (
        "http3-%s-%s.json" % (info["backend"] or "unknown", time.strftime("%Y%m%d-%H%M%S"))))
    payload = {"suite": "nb_curl-http3-local", "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "platform": sys.platform, "python": sys.version, "executable": sys.executable,
               "cwd": os.getcwd(), "requested_package_paths": info["requested_paths"],
               "requested_backend": args.backend or None, "aioquic_paths": args.aioquic_path,
               "implementation": info, "dependencies": deps, "client_h3_built": client_h3,
               "http_version_arg": HTTP_VERSION_ARG, "http_version_code": HTTP3_ONLY_CODE,
               "response_body": {"length": len(H3_BODY), "nul_count": H3_BODY.count(b"\x00"),
                                 "tail_hex": H3_BODY[-8:].hex()},
               "pki": ctx.bundle.describe() if ctx.bundle else None,
               "server": server.snapshot() if server is not None else None,
               "counts": {"checks": suite.passed + suite.failed, "passed": suite.passed,
                          "failed": suite.failed, "blocked": len(suite.blocked)},
               "cases": suite.cases, "blocked": suite.blocked,
               "honesty_notes": [
                   "只覆盖本地 127.0.0.1 的 HTTP/3 普通功能：本地 CA 校验、错误 CA 负向、二进制含 "
                   "NUL 响应体、8 并发、resp.http_version=3 与服务端 ALPN=h3。",
                   "h3.concurrent_8 只验功能正确性不是性能；超时按失败报告并保留逐请求真实结果与服务端 timeline，不加 timeout、不重跑洗白。",
                   "h3.session_reuse 硬断言同 Session 两请求只新增 1 条连接（服务端计数为证）。",
                   "服务端 timeline 只记 handshake/request/response/close 时刻与连接短标识，不读取头字段值或载荷。",
                   "不做性能/压测、不做指纹或反检测、不访问任何第三方站点。",
                   "blocked = 缺 aioquic 或客户端未编译 nghttp3：未执行也不计通过，退出码 3。"]}
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        print("JSON 报告：%s" % out.resolve())
    except OSError as exc:
        print("[WARN] JSON 报告写入失败：%r" % (exc,))
    print("=" * 78)
    if suite.failed:
        return EXIT_FAIL
    if suite.blocked:
        return EXIT_BLOCKED
    return EXIT_OK


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(unit_tests())
    sys.exit(main())
