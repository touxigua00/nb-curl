"""协议回归（独立套件）：本地 TLS 校验 / 错误 CA / 真实 HTTP/2 协商 / WebSocket 基本收发。

与 ``run_local_regression.py`` 分开、互不 import：本套件只管**协议层真实协商**，
不做请求语义、生命周期或性能回归。

硬性约束：

* **只打自建本地服务**，socket 一律绑 ``127.0.0.1`` + 端口 0；不碰任何第三方站点，
  不做指纹/反检测断言，线上压测更不在此列。
* **证书是现场生成的**（本地 CA + SAN ``localhost``/``127.0.0.1``），走客户端
  ``verify=True`` + ``ca_path=<本地 CA>`` 的真实校验路径；另备一个无亲缘的"错误 CA"
  做负向对照，再用一个 SAN 不匹配的叶子证书验证主机名校验没有被跳过。
* **缺依赖 = 明确 blocked + 非零退出**，不静默 skip 后当作通过。
* **H3 只登记未覆盖**：没有可用的本地 H3 服务端就不假装测过。
* 实现由 ``--package-path`` / ``--backend`` 显式选择；本套件只把自己所在目录加进
  ``sys.path``（为了 import 同级的 ``protocol_fixtures``），不会写入其它路径；
  导入后核对 ``nb_curl.__file__`` 确实落在指定目录内。

用法（在仓库根目录执行）::

    python tests/test_protocols.py --package-path . --backend cffi
    python tests/test_protocols.py --package-path . --backend ctypes
    python tests/test_protocols.py --list
    python tests/test_protocols.py --only tls,ws --json out.json

退出码：0 = 全部通过（H3 未覆盖不算通过，只在报告里单列）；1 = 有失败；
2 = 实现选择/导入失败（含 ``--backend`` 未被满足）；3 = 因缺依赖而 blocked。
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import importlib
import json
import os
import sys
import threading
import time
import traceback
from pathlib import Path

_HERE = Path(__file__).resolve().parent
# 只为 import 同目录的 protocol_fixtures —— 这是本套件自己的目录，不是被测实现路径
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import protocol_fixtures as fx  # noqa: E402

HOST = fx.HOST
PROXY_ENV_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
WS_TEXT = "ws 文本 · 你好"
WS_BINARY = b"\x00\x01\xff\xfe\r\nAB\x00"
WS_PING = b"hi-probe"
H2_WORKERS = 8
H2_PER_WORKER = 3
HTTP2_STREAMS_SEQUENTIAL = 3

EXIT_OK, EXIT_FAIL, EXIT_SETUP, EXIT_BLOCKED = 0, 1, 2, 3


# --------------------------------------------------------------------------- #
# 极小结果记录（不是通用测试框架：只有 case/check/note + blocked/uncovered）
# --------------------------------------------------------------------------- #
class Suite:
    def __init__(self) -> None:
        self.cases: list = []
        self.blocked: list = []
        self.uncovered: list = []
        self.passed = 0
        self.failed = 0
        self._cur: dict | None = None

    @contextlib.contextmanager
    def case(self, name: str, group: str | None = None):
        entry = {"case": name, "group": group or name, "checks": [], "seconds": 0.0,
                 "status": "pass"}
        self.cases.append(entry)
        prev, self._cur = self._cur, entry
        t0 = time.perf_counter()
        try:
            yield entry
        except BaseException as exc:  # noqa: BLE001
            self.check("用例自身未抛异常", False, "%s: %s" % (type(exc).__name__, exc))
            traceback.print_exc()
        finally:
            entry["seconds"] = round(time.perf_counter() - t0, 3)
            if any(not c["ok"] for c in entry["checks"]):
                entry["status"] = "fail"
            self._cur = prev

    def check(self, name: str, ok, detail: str = "") -> bool:
        ok = bool(ok)
        entry = {"name": name, "ok": ok, "detail": str(detail)[:400]}
        if self._cur is not None:
            self._cur["checks"].append(entry)
        if ok:
            self.passed += 1
            print("      [PASS] %s" % name)
        else:
            self.failed += 1
            print("      [FAIL] %s   %s" % (name, entry["detail"]))
        return ok

    def note(self, text: str) -> None:
        print("      [info] %s" % text)

    def mark_blocked(self, scope: str, reason: str, cases: list | None = None) -> None:
        # 名字刻意不叫 blocked()：实例属性 self.blocked 是列表，会遮蔽同名方法
        # （原名导致 "TypeError: 'list' object is not callable"，套件在写 JSON 前就崩）
        self.blocked.append({"scope": scope, "reason": reason, "cases": list(cases or [])})
        print("      [BLOCKED] %s —— %s" % (scope, reason))

    def mark_uncovered(self, protocol: str, reason: str, **extra) -> None:
        # 同理不叫 uncovered()：self.uncovered 是列表；该方法在主流程里**必定**被调用，
        # 原来每次运行都会在 payload 写入前抛异常 → 从未产出任何 JSON 报告
        self.uncovered.append(dict({"protocol": protocol, "status": "not-covered",
                                    "reason": reason}, **extra))
        print("      [NOT-COVERED] %s —— %s" % (protocol, reason))


def expect_rejected(s: Suite, name: str, fn, expect_code: int = 60):
    """断言 fn() 被拒绝（抛异常），并单独核对 curl 错误码。返回异常对象或 None。"""
    t0 = time.perf_counter()
    try:
        fn()
    except BaseException as exc:  # noqa: BLE001
        detail = "%s: %s (%.2fs)" % (type(exc).__name__, str(exc)[:160],
                                     time.perf_counter() - t0)
        s.check(name, True, detail)
        got = getattr(exc, "code", None)
        s.check(name + " / curl 错误码", got == expect_code,
                "code=%r 期望=%r（拒绝已发生，这里是错误码归因）" % (got, expect_code))
        return exc
    s.check(name, False, "没有抛异常 —— 该被拒绝的场景被放过了")
    return None


def wait_for(pred, timeout: float = 3.0, interval: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(interval)
    return bool(pred())


def recv_frame(ws, timeout: float = 5.0):
    """收一帧，返回 ``(ok, value)``；异常转成可读结果，别把用例炸成 traceback。"""
    try:
        return True, ws.recv(timeout)
    except BaseException as exc:  # noqa: BLE001
        return False, "%s: %s" % (type(exc).__name__, exc)


def scrub_proxy_env() -> list:
    """清掉代理环境变量，返回**只含变量名**的清单。

    刻意不记录取值：代理 URL 常带 ``user:password@host``，报告要能被安全归档，
    所以这里只留变量名（明确不写 ``key=value``）。
    """
    removed = []
    for key in list(os.environ):
        if key.lower() in PROXY_ENV_VARS:
            os.environ.pop(key, None)
            removed.append(key)
    return removed


def _is_within(child: Path, parent: Path) -> bool:
    try:
        return os.path.commonpath([str(child), str(parent)]) == str(parent)
    except ValueError:
        return False


def select_implementation(package_paths: list, module: str = "nb_curl"):
    """按显式给出的目录选实现；不传就用当前 sys.path。返回 (module, info)。"""
    info = {"requested_paths": [str(p) for p in package_paths], "resolved": None,
            "error": None, "matched_package_path": None}
    resolved_paths = []
    for raw in reversed(package_paths):
        path = Path(raw).expanduser()
        try:
            path = path.resolve()
        except OSError:
            pass
        if not path.is_dir():
            info["error"] = "package-path 不存在或不是目录: %s" % path
            return None, info
        resolved_paths.append(path)
        sys.path.insert(0, str(path))
    try:
        mod = importlib.import_module(module)
    except BaseException as exc:  # noqa: BLE001
        info["error"] = "import %s 失败: %r" % (module, exc)
        return None, info
    resolved = Path(getattr(mod, "__file__", "") or "<unknown>")
    try:
        resolved = resolved.resolve()
    except OSError:
        pass
    info["resolved"] = str(resolved)
    if resolved_paths:
        inside = [str(p) for p in resolved_paths if _is_within(resolved, p)]
        if not inside:
            info["error"] = ("import 到的 %s 不在指定 package-path 内：%s"
                             % (module, resolved))
            return None, info
        info["matched_package_path"] = inside[0]
    return mod, info


def implementation_info(mod) -> dict:
    def safe(fn):
        try:
            return fn()
        except BaseException as exc:  # noqa: BLE001
            return "<error: %r>" % (exc,)

    return {
        "module": getattr(mod, "__name__", "?"),
        "file": str(Path(getattr(mod, "__file__", "") or "").resolve()),
        "version": getattr(mod, "__version__", None),
        "backend": safe(getattr(mod, "backend_name", lambda: None)),
        "backend_info": safe(getattr(mod, "backend_info", lambda: None)),
        "native_version": safe(getattr(mod, "native_version", lambda: None)),
    }


# --------------------------------------------------------------------------- #
# 用例
# --------------------------------------------------------------------------- #
def case_impl(c: "Ctx") -> None:
    with c.suite.case("impl.select", "impl"):
        info = implementation_info(c.mod)
        c.suite.note("实现=%s 版本=%s 后端=%s" % (info["file"], info["version"], info["backend"]))
        c.suite.note("模块信息=%s" % (info["backend_info"],))
        c.suite.check("实现选择无错误（未偷偷加载别处的 nb_curl）",
                      not c.imp.get("error"), str(c.imp.get("error")))
        if c.args.package_path:
            c.suite.check("nb_curl 落在显式指定的 package-path 内",
                          bool(c.imp.get("matched_package_path")),
                          "resolved=%s" % c.imp.get("resolved"))
        requested_backend = (c.args.backend or "").strip().lower()
        if requested_backend in ("cffi", "ctypes"):
            c.suite.check("请求的 backend 被满足（不静默回退）",
                          info["backend"] == requested_backend,
                          "请求 %r 实际 %r" % (requested_backend, info["backend"]))
        elif requested_backend == "auto":
            # auto 是"优先 cffi、失败回退 ctypes"的偏好，不是具体后端名：
            # backend_name() 必然解析成 cffi/ctypes，拿它跟字面量 "auto" 比相等没有意义
            c.suite.note("--backend auto 解析为 %r（auto 只作偏好，不与字面量做相等断言）"
                         % (info["backend"],))
            c.suite.check("auto 解析出的后端是已知实现之一（cffi/ctypes）",
                          info["backend"] in ("cffi", "ctypes"),
                          "解析结果=%r" % (info["backend"],))
        for name in ("Session", "Response", "RequestError", "NbCurlError"):
            c.suite.check("公开 API 存在：%s" % name, hasattr(c.mod, name))


def case_deps(c: "Ctx") -> None:
    with c.suite.case("env.deps", "env"):
        for name, info in c.deps.items():
            if not info["used"]:
                c.suite.note("依赖 %s 未使用：%s（版本=%s）"
                             % (name, info["needed_for"], info["version"]))
            elif info["ok"]:
                c.suite.check("依赖可用：%s" % name, True, "版本=%s" % info["version"])
            else:
                # 缺依赖的用例已在主流程登记 blocked，这里只如实记录，不算通过
                c.suite.note("依赖不可用：%s（%s）%s" % (name, info["needed_for"], info["error"]))
        if c.bundle is not None:
            c.suite.note("PKI 目录=%s CA sha256=%s"
                         % (c.bundle.dir, c.bundle.info["ca_sha256"][:16]))


def case_tls_local_ca(c: "Ctx") -> None:
    with c.suite.case("tls.local_ca_verify", "tls"):
        srv = c.h1
        before = srv.requests
        with c.mod.Session(verify=True, ca_path=str(c.bundle.ca_path),
                           timeout=15, connect_timeout=5) as s:
            r = s.get(srv.url("/echo?case=local-ca"))
            c.suite.check("HTTPS 200（本地 CA 校验通过）", r.status_code == 200,
                          "status=%s" % r.status_code)
            c.suite.check("返回 HTTP/1.1（未升级也未降级）", r.http_version == "1.1",
                          "http_version=%r" % r.http_version)
            body = r.json()
            c.suite.check("服务端见到的路径正确", body.get("path") == "/echo?case=local-ca",
                          repr(body)[:200])
            # IP SAN 用 127.0.0.1 直连来覆盖。客户端**没有** hostname= 这个参数
            # （两个实现都会经 check_options 抛 TypeError），所以主机名只能写进 URL；
            # 之前写成 s.get(url, hostname=HOST) 是工具自身 bug，不是客户端 bug。
            r2 = s.get(srv.url("/echo?case=ip-san", hostname=HOST))
            c.suite.check("IP SAN 127.0.0.1 也可校验通过", r2.status_code == 200,
                          "status=%s" % r2.status_code)
        c.suite.check("服务端共收到 2 个请求", srv.requests - before == 2,
                      "requests=+%d" % (srv.requests - before))
        ok_ver = bool(srv.tls_seen) and all(v in ("TLSv1.2", "TLSv1.3") for v in srv.tls_seen)
        c.suite.check("服务端 TLS 版本 >= 1.2", ok_ver, "tls=%r" % (srv.tls_seen,))
        c.suite.note("服务端观测：连接=%d ALPN=%r TLS=%r cipher=%r"
                     % (srv.connections, srv.alpn_seen, srv.tls_seen, srv.ciphers))


def case_tls_wrong_ca(c: "Ctx") -> None:
    with c.suite.case("tls.wrong_ca_rejected", "tls"):
        srv = c.h1
        before = srv.requests
        with c.mod.Session(verify=True, ca_path=str(c.bundle.rogue_ca_path),
                           timeout=15, connect_timeout=5) as s:
            expect_rejected(c.suite, "错误 CA 下 verify=True 被拒绝",
                            lambda: s.get(srv.url("/echo")))
        rejected_delta = srv.requests - before
        with c.mod.Session(verify=False, timeout=15, connect_timeout=5) as s:
            r = s.get(srv.url("/echo?case=no-verify-control"))
            c.suite.check("同一 URL verify=False 成功（证明拒绝只来自证书校验，不是连不上）",
                          r.status_code == 200, "status=%s" % r.status_code)
        c.suite.note("校验失败期间服务端新增请求数=%d（期望 0：拒绝发生在 HTTP 之前）"
                     % rejected_delta)


def case_tls_hostname(c: "Ctx") -> None:
    with c.suite.case("tls.hostname_mismatch_rejected", "tls"):
        srv = c.h1_badname
        with c.mod.Session(verify=True, ca_path=str(c.bundle.ca_path),
                           timeout=15, connect_timeout=5) as s:
            expect_rejected(c.suite, "受信 CA 但 SAN 不匹配（只含 wrong.example）被拒绝",
                            lambda: s.get(srv.url("/echo")))
        with c.mod.Session(verify=False, timeout=15, connect_timeout=5) as s:
            r = s.get(srv.url("/echo?case=no-verify-control"))
            c.suite.check("verify=False 时同一证书可连（确认失败是主机名校验而非网络）",
                          r.status_code == 200, "status=%s" % r.status_code)


def _h2_get(s, url):
    r = s.get(url, timeout=25)
    body = r.json()
    return r.status_code, r.http_version, body.get("path"), r.headers.get("x-local-h2")


def case_h2_negotiation(c: "Ctx") -> None:
    with c.suite.case("http2.real_negotiation", "http2"):
        srv = c.h2
        conns_before, streams_before = srv.connection_count(), srv.streams
        with c.mod.Session(http_version="2", verify=True, ca_path=str(c.bundle.ca_path),
                           timeout=25, connect_timeout=5) as s:
            for i in range(HTTP2_STREAMS_SEQUENTIAL):
                path = "/seq/%d" % i
                status, ver, got_path, marker = _h2_get(s, srv.url(path))
                c.suite.check("HTTP/2 请求 %d 状态 200" % i, status == 200, "status=%s" % status)
                c.suite.check("HTTP/2 请求 %d 实际协议为 h2" % i, ver == "2",
                              "response.http_version=%r" % ver)
                c.suite.check("HTTP/2 请求 %d 响应体对得上" % i, got_path == path,
                              "path=%r" % got_path)
                c.suite.check("HTTP/2 请求 %d 带本地服务标记头" % i, marker == "1",
                              "x-local-h2=%r" % marker)
        c.suite.check("服务端 ALPN 真实协商为 h2（无降级）",
                      bool(srv.connections) and all(x["alpn"] == "h2" for x in srv.connections),
                      "alpn=%r" % [x["alpn"] for x in srv.connections])
        c.suite.check("3 个串行请求只用了 1 条连接（连接保持/复用）",
                      srv.connection_count() - conns_before == 1,
                      "新增连接=%d" % (srv.connection_count() - conns_before))
        c.suite.check("服务端计到 3 个 stream", srv.streams - streams_before
                      == HTTP2_STREAMS_SEQUENTIAL, "新增 stream=%d" % (srv.streams - streams_before))
        c.suite.check("没有连接因 ALPN 不匹配被拒，也没有 h2 协议层错误",
                      not srv.refusals and not srv.errors,
                      "refusals=%r errors=%r" % (srv.refusals, srv.errors))


def case_h2_concurrent(c: "Ctx") -> None:
    total = H2_WORKERS * H2_PER_WORKER
    with c.suite.case("http2.concurrent_streams", "http2"):
        srv = c.h2
        conns_before, streams_before = srv.connection_count(), srv.streams
        results: list = [None] * total
        errors: list = []

        def one(s, idx: int):
            try:
                results[idx] = _h2_get(s, srv.url("/c/%d" % idx))
            except BaseException as exc:  # noqa: BLE001
                errors.append("stream %d: %s: %s" % (idx, type(exc).__name__, exc))

        with c.mod.Session(http_version="2", verify=True, ca_path=str(c.bundle.ca_path),
                           timeout=25, connect_timeout=5) as s:
            with concurrent.futures.ThreadPoolExecutor(max_workers=H2_WORKERS) as pool:
                list(pool.map(lambda idx: one(s, idx), range(total)))

        c.suite.check("并发请求没有异常", not errors, "; ".join(errors[:3]))
        c.suite.check("全部 %d 个响应都是 200" % total,
                      all(r is not None and r[0] == 200 for r in results),
                      "%r" % [r[0] if r else None for r in results][:12])
        c.suite.check("全部响应 response.http_version 都是 2",
                      all(r is not None and r[1] == "2" for r in results),
                      "%r" % [r[1] if r else None for r in results][:12])
        c.suite.check("每个 stream 拿到自己的响应（路径一一对应）",
                      all(r is not None and r[2] == "/c/%d" % i for i, r in enumerate(results)),
                      "mismatch=%r" % [i for i, r in enumerate(results)
                                       if r is None or r[2] != "/c/%d" % i][:8])
        c.suite.check("服务端 stream 计数 == 并发请求数",
                      srv.streams - streams_before == total,
                      "新增 stream=%d 期望=%d" % (srv.streams - streams_before, total))
        c.suite.check("并发期间无 ALPN 拒绝/协议错误",
                      not srv.refusals and not srv.errors,
                      "refusals=%r errors=%r" % (srv.refusals, srv.errors))
        c.suite.note("并发观测：新增连接=%d，单连接最多 stream=%d（客户端是否复用由实现决定，"
                     "这里是观测值不是通过条件）"
                     % (srv.connection_count() - conns_before, srv.max_streams_one_connection()))


def case_ws_basic(c: "Ctx") -> None:
    with c.suite.case("ws.basic_frames", "ws"):
        srv = c.ws
        closes_before = len(srv.snapshot()["closes"])
        with c.mod.Session(timeout=10) as s:
            ws = s.ws_connect(srv.url("/echo"))
            try:
                hs = srv.snapshot()["handshakes"][-1]
                c.suite.check("握手请求行为 101 升级", hs["upgrade"].lower() == "websocket",
                              "upgrade=%r" % hs["upgrade"])
                c.suite.check("握手带 Connection: Upgrade", "upgrade" in hs["connection"].lower(),
                              "connection=%r" % hs["connection"])
                c.suite.check("握手 Sec-WebSocket-Version: 13", hs["version"] == "13",
                              "version=%r" % hs["version"])
                c.suite.check("握手 Sec-WebSocket-Key 为 16 字节 base64",
                              len(hs["key"]) == 24, "key=%r len=%d" % (hs["key"], len(hs["key"])))

                ws.send_text(WS_TEXT)
                ok, got = recv_frame(ws)
                c.suite.check("小文本帧往返一致", ok and got == WS_TEXT, "got=%r" % (got,))
                ws.send_bytes(WS_BINARY)
                ok, got = recv_frame(ws)
                c.suite.check("二进制帧往返一致（含 NUL/高位/CRLF）",
                              ok and isinstance(got, bytes) and got == WS_BINARY,
                              "got=%r" % (got,))
                ws.send_text("")
                got = None
                try:
                    ok, got = recv_frame(ws)
                    detail = "got=%r" % (got,)
                except BaseException as exc:  # noqa: BLE001
                    ok, detail = False, "发送空帧抛异常: %s: %s" % (type(exc).__name__, exc)
                c.suite.check("空文本帧往返一致（空帧也要按帧交付）", ok and got == "", detail)

                ws.ping(WS_PING)
                ws.send_text("after-ping")
                ok, got = recv_frame(ws)
                c.suite.check("发 PING 后连接仍可用（服务端应已收到 PING 并回 PONG）",
                              ok and got == "after-ping", "got=%r" % (got,))
                ok = wait_for(lambda: WS_PING in srv.snapshot()["pings"])
                c.suite.check("服务端记录到客户端 PING 载荷", ok,
                              "pings=%r" % (srv.snapshot()["pings"],))

                ws.send_text(fx.WS_CMD_PING)
                ok, got = recv_frame(ws, 6.0)
                c.suite.check("服务端主动 PING 后，客户端自动回 PONG 并拿到后续数据帧",
                              ok and got == fx.WS_PONG_OK, "got=%r" % (got,))
                ok = wait_for(lambda: fx.WS_PING_PROBE in srv.snapshot()["pongs"])
                c.suite.check("服务端记录到客户端回给我们的 PONG 载荷", ok,
                              "pongs=%r" % (srv.snapshot()["pongs"],))

                ws.close()
                c.suite.check("客户端 close() 后 closed=True", bool(ws.closed), "")
                ok = wait_for(lambda: len(srv.snapshot()["closes"]) > closes_before)
                c.suite.check("服务端记录到客户端 CLOSE 帧", ok,
                              "closes=%r" % (srv.snapshot()["closes"],))
            finally:
                try:
                    ws.close()
                except Exception:  # noqa: BLE001
                    pass
        snap = srv.snapshot()
        c.suite.check("服务端未记录到协议违规（掩码/UTF-8/opcode）", not snap["errors"],
                      "errors=%r" % (snap["errors"],))
        c.suite.check("服务端记录到 1 条 WS 连接", snap["connections"] == 1,
                      "connections=%d" % snap["connections"])


def case_ws_server_close(c: "Ctx") -> None:
    with c.suite.case("ws.server_initiated_close", "ws"):
        srv = c.ws
        server_closes_before = srv.snapshot()["server_closes"]
        with c.mod.Session(timeout=10) as s:
            ws = s.ws_connect(srv.url("/echo"))
            try:
                ws.send_text(fx.WS_CMD_CLOSE)
                ok, got = recv_frame(ws, 6.0)
                c.suite.check("收到服务端 CLOSE 时 recv 返回 None", ok and got is None,
                              "ok=%s got=%r" % (ok, got))
                c.suite.check("收到 CLOSE 后 closed=True", bool(ws.closed), "")
            finally:
                try:
                    ws.close()
                except Exception:  # noqa: BLE001
                    pass
        snap = srv.snapshot()
        c.suite.check("服务端确实主动发过 CLOSE",
                      snap["server_closes"] - server_closes_before >= 1,
                      "server_closes=+%d" % (snap["server_closes"] - server_closes_before))
        c.suite.note("服务端观测：客户端回帧 closes=%r（收到 CLOSE 即置 closed 的实现不会回 CLOSE，"
                     "这里只登记事实）" % (snap["closes"],))


def case_ws_tls(c: "Ctx") -> None:
    with c.suite.case("ws.tls_verify", "ws"):
        srv = c.ws_tls
        with c.mod.Session(timeout=10) as s:
            ws = s.ws_connect(srv.url("/echo"), verify=True, ca_path=str(c.bundle.ca_path))
            try:
                ws.send_text(WS_TEXT)
                ok, got = recv_frame(ws)
                c.suite.check("wss + 本地 CA 校验通过且文本帧往返一致",
                              ok and got == WS_TEXT, "got=%r" % (got,))
            finally:
                try:
                    ws.close()
                except Exception:  # noqa: BLE001
                    pass
        with c.mod.Session(timeout=10) as s:
            expect_rejected(c.suite, "wss 在错误 CA 下握手被拒绝",
                            lambda: s.ws_connect(srv.url("/echo"), verify=True,
                                                 ca_path=str(c.bundle.rogue_ca_path)))


def _h2_cookie_fields(s, url, body_out: dict | None = None, **options):
    """发一个 h2 请求，返回 (状态码, 服务端收到的 header 原样列表)。"""
    r = s.get(url, timeout=25, **options)
    body = r.json()
    if body_out is not None:
        body_out.update(body)
    return r.status_code, [tuple(pair) for pair in body["header_fields"]]


def case_h2_cookie_header(c: "Ctx") -> None:
    """h2 上 Cookie 必须**一条** header 字段，且值/位置原样。

    回归背景：curl-impersonate 的每个预设都开着 split_cookies，HTTP/2 下 libcurl
    会把 ``Cookie: a=1; b=2`` 拆成两条 ``cookie`` 头（``lib/http.c`` 的
    http_cookies split 分支）。按 RFC 9113 §8.2.3 接收方应该用 "; " 拼回去，但现实里
    一堆服务端/中间件按"同名头覆盖"处理，于是整串登录态只剩最后一条。"给了一条、
    线上变六条"也不是用户给什么就发什么。
    """
    ck = ("uin=o0123456789; p_uin=o0123456789; p_uid=u0123456789; "
          "SESSION_TRACE_ID=1646sdsd1fgsd1fg5; a=5555; s=5555")
    with c.suite.case("http2.cookie_header", "http2"):
        srv = c.h2
        with c.mod.Session(http_version="2", verify=True, ca_path=str(c.bundle.ca_path),
                           timeout=25, connect_timeout=5) as s:
            status, fields = _h2_cookie_fields(
                s, srv.url("/ck/1"),
                headers={"x-a": "1", "Cookie": ck, "x-z": "2"})
            names = [k for k, _ in fields]
            cookie_values = [v for k, v in fields if k == "cookie"]
            c.suite.check("显式 Cookie 头在 h2 上只有一条", len(cookie_values) == 1,
                          "cookie 字段=%r" % (cookie_values,))
            c.suite.check("显式 Cookie 头的值逐字节原样",
                          cookie_values == [ck], "%r" % (cookie_values,))
            c.suite.check("Cookie 的位置跟着 headers= 走",
                          [k for k in names if k in ("x-a", "cookie", "x-z")]
                          == ["x-a", "cookie", "x-z"],
                          "顺序=%r" % (names,))

            status, fields = _h2_cookie_fields(
                s, srv.url("/ck/2"), headers={"x-a": "1"}, cookies={
                    "uin": "o0123456789", "a": "5555"})
            cookie_values = [v for k, v in fields if k == "cookie"]
            c.suite.check("请求级 cookies 在 h2 上也只有一条", len(cookie_values) == 1,
                          "%r" % (cookie_values,))
            c.suite.check("请求级 cookies 的值按 dict 顺序原样",
                          cookie_values == ["uin=o0123456789; a=5555"],
                          "%r" % (cookie_values,))

            # 引擎那一路（会话罐自己没有显式 cookie 时）同样只发一条
            s.cookies["jarA"] = "1"
            s.cookies["jarB"] = "2"
            status, fields = _h2_cookie_fields(s, srv.url("/ck/3"))
            cookie_values = [v for k, v in fields if k == "cookie"]
            c.suite.check("会话罐 cookie 在 h2 上只有一条", len(cookie_values) == 1,
                          "%r" % (cookie_values,))
            c.suite.check("会话罐 cookie 两条都在同一条头里",
                          bool(cookie_values)
                          and "jarA=1" in cookie_values[0]
                          and "jarB=2" in cookie_values[0],
                          "%r" % (cookie_values,))
            s.cookies.clear()

            # 显式开关只作用于**引擎那一路**（会话罐）：显式 Cookie 头永远是原样的
            # 一条行，拆不拆不由 libcurl 的 cookie 代码决定，所以也不受影响。
            s.cookies.clear()
            s.cookies["a"] = "1"
            s.cookies["b"] = "2"
            status, fields = _h2_cookie_fields(s, srv.url("/ck/4"),
                                               diy_fp={"split_cookies": True})
            cookie_values = [v for k, v in fields if k == "cookie"]
            # 实测 Chrome 155：h2 上 cookie 仍然只有**一条**头（本地 h2 服务端抓到
            # `['a=1; b=2']`）。旧版 Chrome 拆行，现在不拆；diy_fp 这个开关对这条头
            # 已经没有任何作用（保留字段只为 ABI 兼容）。
            c.suite.check("split_cookies 开关不影响 Cookie 头（h2 也只发一条）",
                          cookie_values == ["a=1; b=2"], "%r" % (cookie_values,))

            status, fields = _h2_cookie_fields(s, srv.url("/ck/5"))
            cookie_values = [v for k, v in fields if k == "cookie"]
            c.suite.check("默认（不拆）时引擎 cookie 合成一条",
                          len(cookie_values) == 1
                          and "a=1" in cookie_values[0]
                          and "b=2" in cookie_values[0], "%r" % (cookie_values,))
            s.cookies.clear()


def case_h2_frames(c: "Ctx") -> None:
    """``diy_fp={"http2_frames": ...}``：SETTINGS / WINDOW_UPDATE / 伪头顺序真的落到帧上。

    断言全部基于服务端收到的**原始字节**（``protocol_fixtures.H2Server`` 记录的
    SETTINGS 条目（保序）、WINDOW_UPDATE 增量、伪头顺序），不看响应体猜。
    这三样就是 Akamai HTTP/2 指纹的全部内容。
    """
    srv = c.h2
    conn_opts = dict(verify=True, ca_path=str(c.bundle.ca_path),
                     timeout=25, connect_timeout=5)

    def run(**opts):
        before = srv.connection_count()
        with c.mod.Session(**conn_opts, **opts) as s:
            r = s.get(srv.url("/frames"), timeout=25)
            ok = r.status_code == 200 and r.http_version == "2"
        for _ in range(80):                      # 等这条连接的帧落地
            if srv.connection_count() > before and srv.last_settings():
                break
            time.sleep(0.05)
        return ok, srv.last_settings(), srv.last_window_updates(), srv.last_pseudo_order

    with c.suite.case("http2.frames_custom", "http2"):
        # 1) 预设原样：Chrome 155 的 SETTINGS 内容与顺序
        ok, settings, win, order = run(impersonate="chrome155")
        c.suite.check("预设：请求成功且走 h2", ok)
        c.suite.check("预设：SETTINGS 条目与顺序 = Chrome", settings == [
            (1, 65536), (2, 0), (4, 6291456), (6, 262144)], "%r" % (settings,))
        c.suite.check("预设：连接级 WINDOW_UPDATE = 15663105",
                      win == [(0, 15663105)], "%r" % (win,))
        c.suite.check("预设：伪头顺序 masp", order == "masp", repr(order))

        # 2) 字典写法：名称 -> 值，顺序即发出顺序
        ok, settings, win, order = run(impersonate="chrome155", diy_fp={"http2_frames": {
            "settings": {"HEADER_TABLE_SIZE": 16384, "ENABLE_PUSH": 1,
                         "INITIAL_WINDOW_SIZE": 2097152},
            "window_updates": {"0": 10420225},
            "order": "m,p,a,s",
        }})
        c.suite.check("字典：请求成功且走 h2", ok)
        c.suite.check("字典：SETTINGS 按字典写入顺序发出",
                      settings == [(1, 16384), (2, 1), (4, 2097152)], "%r" % (settings,))
        c.suite.check("字典：window_updates={'0': ...} 生效",
                      win == [(0, 10420225)], "%r" % (win,))
        c.suite.check("字典：伪头顺序 m,p,a,s", order == "mpas", repr(order))

        # 3) 字符串写法：SETTINGS|WINDOW_UPDATE|PRIORITY|ORDER
        ok, settings, win, order = run(impersonate="chrome155", diy_fp={
            "http2_frames":
                "1:65536;2:0;3:1000;4:6291456;6:262144|12517377|0|m,a,s,p"})
        c.suite.check("字符串：请求成功且走 h2", ok)
        c.suite.check("字符串：SETTINGS 生效",
                      settings == [(1, 65536), (2, 0), (3, 1000),
                                   (4, 6291456), (6, 262144)], "%r" % (settings,))
        c.suite.check("字符串：WINDOW_UPDATE 生效",
                      win == [(0, 12517377)], "%r" % (win,))
        c.suite.check("字符串：伪头顺序 masp", order == "masp", repr(order))

        # 4) 非法写法要直接报错，不能静默忽略
        for name, bad in (
                ("段数不对", "1:65536|15663105|m,a,s,p"),
                ("未知 settings 名", {"settings": {"NOPE": 1},
                                      "window_updates": 1, "order": "masp"}),
                ("非连接级 window_updates", {"settings": "1:65536",
                                             "window_updates": {"3": 5},
                                             "order": "masp"}),
                ("缺 order", {"settings": "1:65536", "window_updates": 1}),
        ):
            try:
                with c.mod.Session(**conn_opts, impersonate="chrome155",
                                   diy_fp={"http2_frames": bad}) as s:
                    s.get(srv.url("/frames"), timeout=25)
                got = "no error"
            except Exception as exc:  # noqa: BLE001
                got = type(exc).__name__
            c.suite.check("非法写法报错：%s" % name, got == "FingerprintError", got)


CASES = [
    ("impl.select", None, case_impl),
    ("env.deps", None, case_deps),
    ("tls.local_ca_verify", "cryptography", case_tls_local_ca),
    ("tls.wrong_ca_rejected", "cryptography", case_tls_wrong_ca),
    ("tls.hostname_mismatch_rejected", "cryptography", case_tls_hostname),
    ("http2.real_negotiation", "h2", case_h2_negotiation),
    ("http2.concurrent_streams", "h2", case_h2_concurrent),
    ("http2.cookie_header", "h2", case_h2_cookie_header),
    ("http2.frames_custom", "h2", case_h2_frames),
    ("ws.basic_frames", None, case_ws_basic),
    ("ws.server_initiated_close", None, case_ws_server_close),
    ("ws.tls_verify", "cryptography", case_ws_tls),
]


class Ctx:
    """用例上下文：被测模块 + 夹具 + 参数（没有任何隐式全局状态）。"""

    def __init__(self, mod, suite: Suite, args, imp: dict, deps: dict) -> None:
        self.mod = mod
        self.suite = suite
        self.args = args
        self.imp = imp
        self.deps = deps
        self.bundle = None
        self.h1 = None
        self.h1_badname = None
        self.h2 = None
        self.ws = None
        self.ws_tls = None


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="nb_curl 协议回归（本地 TLS/HTTP2/WebSocket；不做 H3、不碰第三方）")
    p.add_argument("--package-path", action="append", default=[], metavar="DIR",
                   help="nb_curl 所在目录（可多次给）。不传则用当前 sys.path/PYTHONPATH。")
    p.add_argument("--module", default="nb_curl", help="包名（默认 nb_curl）")
    p.add_argument("--backend", default="", choices=["", "auto", "cffi", "ctypes"],
                   help="强制 NB_CURL_BACKEND（导入前生效）；不匹配即视为 setup 失败")
    p.add_argument("--only", default="", metavar="SUBSTR[,SUBSTR]",
                   help="只跑用例名包含任一子串的用例")
    p.add_argument("--list", action="store_true", help="列出用例后退出")
    p.add_argument("--json", default="", metavar="PATH",
                   help="JSON 报告路径（默认写到 <仓库根>/reports/protocol-<backend>-<时间>.json）")
    p.add_argument("--overall-timeout", type=float, default=600.0,
                   help="套件总时长上限（秒，默认 600；到点强制退出码 3）")
    p.add_argument("--utf8-output", action="store_true",
                   help="把 stdout/stderr 切成 UTF-8（管道采集日志时用）")
    return p.parse_args(argv)


def _watchdog(seconds: float):
    if seconds <= 0:
        return None
    timer = threading.Timer(seconds, lambda: os._exit(EXIT_BLOCKED))
    timer.daemon = True
    timer.start()
    return timer


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.utf8_output:
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding="utf-8", errors="backslashreplace")
            except (AttributeError, ValueError):
                pass
    if args.list:
        for name, need, _fn in CASES:
            print("%-34s 依赖=%s" % (name, need or "-"))
        return EXIT_OK

    scrubbed = scrub_proxy_env()
    if args.backend:
        os.environ["NB_CURL_BACKEND"] = args.backend

    print("=" * 78)
    print("nb_curl 协议回归（本地 TLS / 错误 CA / 真实 HTTP2 / WebSocket）")
    print("=" * 78)
    mod, imp = select_implementation(args.package_path, args.module)
    if mod is None:
        print("[SETUP FAIL] %s" % imp.get("error"))
        print("提示：用 --package-path <目录> 指定实现；本套件不会自动插入其它路径。")
        return EXIT_SETUP
    impl = implementation_info(mod)
    requested_backend = (args.backend or "").strip().lower()
    if requested_backend in ("cffi", "ctypes") and impl["backend"] != requested_backend:
        print("[SETUP FAIL] 请求 backend=%r，实际 %r（拒绝静默回退）"
              % (requested_backend, impl["backend"]))
        return EXIT_SETUP
    if requested_backend == "auto" and impl["backend"] not in ("cffi", "ctypes"):
        print("[SETUP FAIL] --backend auto 解析出未知后端 %r" % (impl["backend"],))
        return EXIT_SETUP
    print("  实现      : %s" % impl["file"])
    print("  版本/后端 : %s / %s" % (impl["version"], impl["backend"]))
    print("  模块信息  : %s" % (impl["backend_info"],))
    if scrubbed:
        print("  已清理代理环境变量: %s" % scrubbed)

    deps = fx.deps_report()
    suite = Suite()
    ctx = Ctx(mod, suite, args, imp, deps)
    started: list = []
    descriptors: dict = {}
    released: dict = {}
    selected = [c for c in CASES
                if not args.only or any(n.strip() and n.strip() in c[0]
                                        for n in args.only.split(","))]
    if not selected:
        print("[SETUP FAIL] --only %r 没有匹配到任何用例" % args.only)
        return EXIT_SETUP
    for name, need, _ in selected:
        if need and not deps[need]["ok"]:
            suite.mark_blocked(name, "依赖 %s 不可用：%s" % (need, deps[need]["error"]), [name])

    timer = _watchdog(args.overall_timeout)
    try:
        try:
            if deps["cryptography"]["ok"]:
                ctx.bundle = fx.CertBundle.create()
            else:
                print("[BLOCKED] 无本地 PKI（cryptography 缺失），TLS/H2/WS-TLS 全部无法运行")
            if ctx.bundle is not None:
                ctx.h1 = fx.TLSHttpServer(ctx.bundle.cert_path, ctx.bundle.key_path).start()
                ctx.h1_badname = fx.TLSHttpServer(ctx.bundle.badname_cert_path,
                                                  ctx.bundle.badname_key_path).start()
                ctx.ws_tls = fx.WebSocketServer(ctx.bundle.cert_path,
                                                ctx.bundle.key_path).start()
                started += [ctx.h1, ctx.h1_badname, ctx.ws_tls]
                if deps["h2"]["ok"]:
                    ctx.h2 = fx.H2Server(ctx.bundle.cert_path, ctx.bundle.key_path).start()
                    started.append(ctx.h2)
            ctx.ws = fx.WebSocketServer().start()
            started.append(ctx.ws)

            print("  夹具      : h1=%s h2=%s ws=%s ws_tls=%s"
                  % (getattr(ctx.h1, "port", None), getattr(ctx.h2, "port", None),
                     ctx.ws.port, getattr(ctx.ws_tls, "port", None)))
            print("-" * 78)
            for name, need, fn in selected:
                if need and not deps[need]["ok"]:
                    continue
                print("\n== %s ==" % name)
                fn(ctx)

            # H3：本机没有可用 H3 服务端 —— 只登记未覆盖，绝不假冒
            suite.mark_uncovered(
                "http3",
                "无可用本地 H3 服务端（ngtcp2/nghttp3 只提供客户端/库，缺服务端），"
                "本套件不发起 H3 请求，也不把降级到 h2/h1 当作通过",
                client_curl=str(impl["backend_info"]),
                client_h3_built="nghttp3" in str(impl["backend_info"]),
            )
            for label, srv in (("tls_h1", ctx.h1), ("tls_h1_badname", ctx.h1_badname),
                               ("h2", ctx.h2), ("ws", ctx.ws), ("ws_tls", ctx.ws_tls)):
                if srv is not None:
                    descriptors[label] = srv.describe()
        finally:
            for srv in reversed(started):
                try:
                    srv.stop()
                except Exception:  # noqa: BLE001
                    traceback.print_exc()
            for label, srv in (("tls_h1", ctx.h1), ("tls_h1_badname", ctx.h1_badname),
                               ("h2", ctx.h2), ("ws", ctx.ws), ("ws_tls", ctx.ws_tls)):
                if srv is not None:
                    released[label] = not fx.port_open(HOST, srv.port)
            if ctx.bundle is not None:
                ctx.bundle.cleanup()
    finally:
        if timer is not None:
            timer.cancel()

    # 夹具清理也要有结论（不只写在文档里）
    with suite.case("fixtures.cleanup", "fixtures"):
        for label, ok in released.items():
            suite.check("夹具 %s 监听端口已释放" % label, ok, "端口仍可连")

    print("\n" + "=" * 78)
    total = suite.passed + suite.failed
    print("结果：%d 条断言，通过 %d，失败 %d，blocked %d，未覆盖 %d"
          % (total, suite.passed, suite.failed, len(suite.blocked), len(suite.uncovered)))
    for case in suite.cases:
        for ck in case["checks"]:
            if not ck["ok"]:
                print("  [FAIL] %s / %s   %s" % (case["case"], ck["name"], ck["detail"][:140]))
    for b in suite.blocked:
        print("  [BLOCKED] %s —— %s" % (b["scope"], b["reason"]))
    for u in suite.uncovered:
        print("  [NOT-COVERED] %s —— %s" % (u["protocol"], u["reason"]))
    slow = sorted(suite.cases, key=lambda c: -c["seconds"])[:5]
    print("最慢用例：%s" % ", ".join("%s(%.2fs)" % (c["case"], c["seconds"]) for c in slow))

    out = Path(args.json) if args.json else (
        _HERE.parent / "reports" / ("protocol-%s-%s.json" % (
            impl["backend"] or "unknown", time.strftime("%Y%m%d-%H%M%S"))))
    payload = {
        "suite": "nb_curl-protocol-regression",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "platform": sys.platform,
        "python": sys.version,
        "executable": sys.executable,
        "cwd": os.getcwd(),
        "requested_package_paths": imp["requested_paths"],
        "requested_backend": args.backend or None,
        "implementation": impl,
        "import_info": imp,
        "proxy_env_scrubbed": scrubbed,
        "dependencies": deps,
        "pki": ctx.bundle.describe() if ctx.bundle else None,
        "servers": descriptors,
        "ports_released": released,
        "counts": {"checks": total, "passed": suite.passed, "failed": suite.failed,
                   "blocked": len(suite.blocked), "uncovered": len(suite.uncovered)},
        "cases": suite.cases,
        "blocked": suite.blocked,
        "uncovered": suite.uncovered,
        "observations": {
            "h2_connections": getattr(ctx.h2, "connection_count", lambda: None)() if ctx.h2 else None,
            "h2_max_streams_one_connection": (
                ctx.h2.max_streams_one_connection() if ctx.h2 else None),
            "ws_server": ctx.ws.snapshot() if ctx.ws else None,
        },
        "honesty_notes": [
            "只覆盖本地 TLS 校验/错误 CA/主机名不匹配、真实 ALPN h2 协商与并发 stream、"
            "WebSocket text/binary/ping/pong/close；没有跑 H3、性能或反检测。",
            "H3 记为 not-covered，不因协议降级或未测试而算通过。",
            "blocked 表示缺依赖导致该组用例未执行，退出码非零，不计入通过。",
        ],
    }
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str),
                       encoding="utf-8")
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
    sys.exit(main())
