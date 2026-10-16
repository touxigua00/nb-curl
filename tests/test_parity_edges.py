"""nb_curl 平价边界套件（对应 public-api-parity-audit.md P1-2/P1-3/P0-3 的普通功能面）。

独立于 run_local_regression.py / test_protocols.py，互不 import；复用同目录
``local_server``（/close-mid-body 等既有端点，只读不改），另起一个自有线程服务
提供 /echo-hdr、/latin1、/deflate 三个补充端点。

覆盖点（均只打 127.0.0.1 动态端口，不外联）：
* auth basic 生效 + 复用会话下一请求无 Authorization 残留（P1-2 句柄复位）
* 请求级 timeout 覆盖后，复用默认值恢复（P1-2 timeout 复位）
* resolve 把自定义 localhost 别名解析到 127.0.0.1（不外网）
* curl_options 一个明确普通选项（USERAGENT，配 allow_dangerous）
* latin1 / utf8 响应 encoding 解析 + 显式改 encoding（P1-3）
* deflate 响应解压（若客户端广告了 deflate）
* 声明 Content-Length > 实际写入 → 必须报错且保留已读部分，不得静默成功（P0-3）

用法与退出码同 test_protocols.py：--package-path / --backend / --json / --list；
0=全过 1=有失败 2=setup 失败 3=watchdog。
"""

from __future__ import annotations

import argparse
import base64
import importlib
import json
import os
import sys
import threading
import time
import traceback
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from local_server import LocalServer  # noqa: E402  只复用，不修改

PROXY_ENV_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
LATIN1_BODY = b"caf\xe9\xfe"          # latin-1: "caféþ"
EXIT_OK, EXIT_FAIL, EXIT_SETUP, EXIT_WATCHDOG = 0, 1, 2, 3


# --------------------------------------------------------------------------- #
# 补充端点（自有线程服务；与 local_server 互不干扰）
# --------------------------------------------------------------------------- #
class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _dispatch(self):
        # query 必须显式解析：直接 split 掉 query 会让 `?slow=1` 这类参数失效，
        # 从而把"没有延迟"误当成"超时残留"。这里：
        #   /delay?ms=N   服务端阻塞 N 毫秒后回 200（N 上限 10000，防滥用）
        #   /echo-hdr?slow=1 等价 /delay?ms=1500（同一语义的另一种写法）
        parsed = urlsplit(self.path)
        path = parsed.path
        q = parse_qs(parsed.query)

        # /delay 与 ?slow=1 显式分支，命中即结束（_send 自带 return 后的直通路径）
        if path == "/delay" or "slow" in q:
            try:
                delay_ms = int(q.get("ms", ["0"])[0]) if path == "/delay" else 1500
            except ValueError:
                self._send(400, b'{"error":"bad query"}', "application/json")
                return
            delay_ms = max(0, min(delay_ms, 10000))
            t0 = time.perf_counter()
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)
            elapsed = time.perf_counter() - t0
            self._send(200,
                       json.dumps({"delayed_ms": delay_ms,
                                   "server_elapsed_ms": round(elapsed * 1000, 1)}).encode(),
                       "application/json")
            return

        if path == "/echo-hdr":
            body = json.dumps({"headers": {k.lower(): v for k, v in self.headers.items()}
                               }).encode("utf-8")
            self._send(200, body, "application/json")
        elif path == "/latin1":
            self._send(200, LATIN1_BODY, "text/plain; charset=iso-8859-1")
        elif path == "/deflate":
            self._send(200, zlib.compress(b'{"deflate":"ok","n":1}'),
                       "application/json", extra={"Content-Encoding": "deflate"})
        else:
            self._send(404, b'{"error":"not found"}', "application/json")

    def _send(self, code, payload, ctype, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Server-Path", self.path)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = _dispatch


def _hdr_server() -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, name="parity-edges-srv",
                     daemon=True).start()
    return srv


# --------------------------------------------------------------------------- #
# 极小框架
# --------------------------------------------------------------------------- #
class Suite:
    def __init__(self):
        self.cases, self._cur = [], None
        self.passed = self.failed = 0

    def check(self, name, ok, detail=""):
        ok = bool(ok)
        if self._cur is not None:
            self._cur["checks"].append({"name": name, "ok": ok, "detail": str(detail)[:400]})
        print("      [%s] %s %s" % ("PASS" if ok else "FAIL", name, detail if not ok else ""))
        self.passed, self.failed = self.passed + ok, self.failed + (not ok)
        return ok

    def eq(self, name, got, want):
        return self.check(name, got == want, "got=%r want=%r" % (got, want))

    def raises(self, name, exc_types, fn, code=None):
        try:
            fn()
        except exc_types as exc:
            got = getattr(exc, "code", None)
            if code is not None:
                return self.check(name, got == code, "抛了 %s code=%r 期望=%r"
                                  % (type(exc).__name__, got, code))
            return self.check(name, True, "%s: %s" % (type(exc).__name__, str(exc)[:120]))
        except BaseException as exc:
            return self.check(name, False, "非预期异常 %r" % (exc,))
        return self.check(name, False, "没有抛异常")

    def case(self, name):
        self._cur = {"case": name, "checks": []}
        print("\n== %s ==" % name)

    def end(self):
        self.cases.append(self._cur)
        self._cur = None


# --------------------------------------------------------------------------- #
# 用例
# --------------------------------------------------------------------------- #
def case_auth(mod, t: Suite, urls):
    """auth basic 生效；复用同一会话下一请求无残留。"""
    with mod.Session() as s:
        r = s.get(urls["echo"], auth=("user", "password"), timeout=10)
        want = "Basic " + base64.b64encode(b"user:password").decode()
        t.eq("auth= 元组发出 Basic 头", r.json()["headers"].get("authorization"), want)
        r2 = s.get(urls["echo"], timeout=10)
        t.eq("复用会话下一请求无 Authorization 残留",
             r2.json()["headers"].get("authorization"), None)
        r3 = s.get(urls["echo"], auth="alice:secret", timeout=10)
        want3 = "Basic " + base64.b64encode(b"alice:secret").decode()
        t.eq("auth= 字符串形式生效", r3.json()["headers"].get("authorization"), want3)
        r4 = s.get(urls["echo"], timeout=10)
        t.eq("字符串 auth 后同样无残留", r4.json()["headers"].get("authorization"), None)


def case_timeout_restore(mod, t: Suite, urls):
    """请求级 timeout 覆盖后，下一次不带 timeout 的请求必须回到会话默认。

    前提：`/echo-hdr?slow=1` 必须有**真实延迟**（query 不能被丢掉、服务端要真
    sleep），否则 "timeout 残留 10s" 这种结论会建立在"其实没有延迟"的假象上。
    本用例据此分三步判定：

    1. 先独立验证服务端 /delay?ms=1500 真实耗时 >= 1s（排除假延迟）；
    2. Session(timeout=0.5) 首请求 timeout=10 打无延迟端点，验证覆盖生效；
    3. 下一请求不带 timeout 打 slow 端点：按客户端实测耗时判定——
       耗时 < 0.9s 说明 0.5s 生效（即使异常对象 code 非 28 也算复位），
       耗时 >= 2s 说明残留 10s（10s 内能正常返回）。
    """
    base = urls["echo"].rsplit("/", 1)[0]

    def _client_elapsed(fn):
        t0 = time.perf_counter()
        outcome = ("ok", None)
        try:
            fn()
        except BaseException as exc:
            outcome = (type(exc).__name__, exc)
        return time.perf_counter() - t0, outcome

    # 1) 服务端延迟独立验证（不经被测客户端，用同步 socket 直连）
    import http.client
    host, port = urls["echo"].split("//")[1].split("/")[0].split(":")
    t0 = time.perf_counter()
    conn = http.client.HTTPConnection(host, int(port), timeout=10)
    conn.request("GET", "/delay?ms=1500")
    resp = conn.getresponse()
    body = json.loads(resp.read())
    raw_elapsed = time.perf_counter() - t0
    conn.close()
    t.check("服务端 /delay?ms=1500 真实延迟 >=1s（预检，非被测客户端）",
            raw_elapsed >= 1.0 and body.get("delayed_ms") == 1500,
            "client_wall=%.3fs server_report=%r" % (raw_elapsed, body))

    # 2) 请求级 timeout=10 覆盖会话默认 0.5
    with mod.Session(timeout=0.5) as s:
        r = s.get(urls["echo"], timeout=10)
        t.eq("请求级 timeout=10 覆盖（无延迟端点正常返回）", r.status_code, 200)

        # 3) 客户端侧验证延迟真实：timeout=10 下 slow 请求实测 >=0.9s
        elapsed_full, (kind_full, exc_full) = _client_elapsed(
            lambda: s.get(base + "/delay?ms=1500", timeout=10))
        t.check("timeout=10 下 slow 请求实测 >=0.9s（客户端侧确认延迟真实）",
                elapsed_full >= 0.9 and kind_full == "ok",
                "elapsed=%.3fs kind=%s" % (elapsed_full, kind_full))

        # 4) 下一请求不带 timeout：客户端实测耗时决定结论
        elapsed, (kind, exc) = _client_elapsed(
            lambda: s.get(base + "/delay?ms=1500", timeout=None))
        t.check("slow 请求未挂死在服务端 1.5s 延迟上（<=2.0s 即非 10s 残留）",
                elapsed <= 2.0, "elapsed=%.3fs kind=%s" % (elapsed, kind))
        default_ok = elapsed < 0.9  # 0.5s 默认超时生效
        residue = elapsed >= 2.0    # 10s 残留：能扛过 1.5s 服务端延迟
        if default_ok:
            t.check("不带 timeout 回到会话默认 0.5s（实测 %0.3fs，非残留）" % elapsed, True)
        elif residue:
            t.check("不带 timeout 残留 timeout=10（实测 %0.3fs，扛过 1.5s 延迟）" % elapsed,
                    False)
        else:
            t.raises("不带 timeout 时超时（code=28），且耗时与 0.5s 默认一致",
                     (getattr(mod, "Timeout", ()), getattr(mod, "RequestError", ())),
                     lambda: (_ for _ in ()).throw(exc) if exc else (_ for _ in ()),
                     code=28)


def case_resolve(mod, t: Suite, urls):
    """resolve 把自定义 localhost 别名钉到 127.0.0.1，全程不外网。"""
    host, port = "nbtest.alias.local", urls["echo"].split(":")[-1].split("/")[0]
    key = "%s:%s" % (host, port)
    url = "http://%s:%s/echo-hdr" % (host, port)
    r = mod.get(url, resolve={key: "127.0.0.1"}, timeout=10)
    t.eq("resolve 别名命中本地服务", r.status_code, 200)
    t.eq("服务端见到的 Host 是别名", r.json()["headers"].get("host"), key)
    t.raises("resolve 未命中时别名不可解析（证明没走真实 DNS/外网）",
             (getattr(mod, "RequestError", ()), getattr(mod, "NbCurlError", ())),
             lambda: mod.get(url, timeout=5), code=6)


def case_curl_options(mod, t: Suite, urls):
    """一个明确的普通选项：USERAGENT 直通到请求头。"""
    co = {"CurlOpt.USERAGENT": None}
    try:
        from nb_curl.options import CurlOpt
        co = {CurlOpt.USERAGENT: "parity-edges/1.0"}
    except Exception:
        co = {10018: "parity-edges/1.0"}
    with mod.Session(allow_dangerous_options=True) as s:
        r = s.get(urls["echo"], curl_options=co, timeout=10)
        t.eq("curl_options 设置的 User-Agent 送达",
             r.json()["headers"].get("user-agent"), "parity-edges/1.0")
        r2 = s.get(urls["echo"], timeout=10)
        t.check("下一请求 User-Agent 回到实现默认（无残留）",
                r2.json()["headers"].get("user-agent") != "parity-edges/1.0",
                repr(r2.json()["headers"].get("user-agent")))


def case_encoding(mod, t: Suite, urls):
    """latin1 响应按 charset 解码；显式改 encoding 后 text/json 跟着变。"""
    r = mod.get(urls["latin1"], timeout=10)
    t.eq("encoding 取自 charset=iso-8859-1", r.encoding, "iso-8859-1")
    t.eq("latin1 体解码正确", r.text, "caféþ")
    t.eq("content 字节未动", r.content, LATIN1_BODY)
    r.encoding = "utf-8"
    t.check("显式改 utf-8 后 text 出现替换符而非崩溃", "\ufffd" in r.text, repr(r.text))
    r.encoding = "latin-1"
    t.eq("再改回 latin-1 恢复正确", r.text, "caféþ")
    r2 = mod.get(urls["echo"] + "?plain=1", timeout=10)
    t.eq("无 charset 时默认 utf-8", r2.encoding, "utf-8")


def case_deflate(mod, t: Suite, urls):
    """deflate 解压（服务端无条件发 deflate，客户端解不开就如实记失败）。"""
    r = mod.get(urls["deflate"], timeout=10)
    t.eq("deflate 自动解压且 JSON 正确", r.json().get("deflate"), "ok")
    t.eq("deflate 长度解压后还原", len(r.content), len(b'{"deflate":"ok","n":1}'))


def case_partial_body(mod, t: Suite, srv):
    """声明 CL > 实际写入：必须报错（code=18 PARTIAL_FILE），不得静默完整成功。"""
    t.raises("非流式短体报错", (getattr(mod, "RequestError", ()), getattr(mod, "NbCurlError", ())),
             lambda: mod.get(srv.url("/close-mid-body/2048/512"), timeout=10), code=18)
    # 流式：已读部分要保留，读完已有数据后再抛
    r = mod.get(srv.url("/close-mid-body/2048/512"), timeout=10, stream=True)
    got, err = bytearray(), None
    try:
        for chunk in r.iter_content(256):
            got += chunk
    except BaseException as exc:
        err = exc
    t.check("流式先交付已读的 512 字节", len(got) == 512, "got=%d" % len(got))
    t.check("读完已有数据后抛错（非静默成功）",
            err is not None and "Timeout" not in type(err).__name__,
            "err=%r" % (err,))


def case_header_order(mod, t: Suite, srv):
    """diy_fp 的 header_order：收列表、且 host 永远排最前。

    背景：C 层语义是"名单里的头按序排到最前，其余保持原相对顺序追加在后"，
    所以名单里没写 host 时它会被塞到"其余"那组（末尾）。这里锁两件事：
    列表写法能收；host 无论写没写、写在第几位，都在第一个。
    """
    hdrs = {"X-Zeta": "1", "X-Alpha": "2", "User-Agent": "order-probe"}
    r = mod.get(srv.url("/echo"), timeout=10, headers=dict(hdrs),
                diy_fp={"header_order": ["x-zeta", "user-agent", "x-alpha"]})
    seen = [k for k, _ in r.json()["header_list"]]
    t.eq("列表写法：host 第一个", seen[:1], ["host"])
    t.eq("列表写法：名单按给定顺序", seen[:4],
         ["host", "x-zeta", "user-agent", "x-alpha"])

    r2 = mod.get(srv.url("/echo"), timeout=10, headers=dict(hdrs),
                 diy_fp={"header_order": "x-alpha,host,x-zeta"})
    seen2 = [k for k, _ in r2.json()["header_list"]]
    t.eq("字符串写法：host 仍被提到最前", seen2[:3], ["host", "x-alpha", "x-zeta"])

    r3 = mod.get(srv.url("/echo"), timeout=10, impersonate="chrome155",
                 headers={"X-Zeta": "1"},
                 diy_fp={"header_order": ["x-zeta", "accept-language"]})
    seen3 = [k for k, _ in r3.json()["header_list"]]
    t.eq("预设 + 自定义顺序：host 第一个", seen3[:1], ["host"])
    t.eq("预设 + 自定义顺序：名单紧随其后", seen3[:3],
         ["host", "x-zeta", "accept-language"])
    t.check("预设 + 自定义顺序：预设的头没丢",
            "sec-ch-ua" in seen3 and "user-agent" in seen3, repr(seen3))

    t.raises("空名单报错", (getattr(mod, "FingerprintError", ()),),
             lambda: mod.get(srv.url("/echo"), timeout=10,
                             diy_fp={"header_order": []}))
    t.raises("非法类型报错", (getattr(mod, "FingerprintError", ()),),
             lambda: mod.get(srv.url("/echo"), timeout=10,
                             diy_fp={"header_order": 123}))


CASES = [("auth.basic.no_residue", case_auth),
         ("timeout.override_restore", case_timeout_restore),
         ("resolve.local_alias", case_resolve),
         ("curl_options.useragent", case_curl_options),
         ("encoding.latin1_utf8", case_encoding),
         ("compression.deflate", case_deflate),
         ("header_order.list_and_host_first", case_header_order),
         ("partial.body.error_keeps_read", case_partial_body)]

# 需要拿到 LocalServer 实例（而不是 urls 字典）的用例
_SRV_CASES = {case_partial_body, case_header_order}


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
def parse_args(argv=None):
    p = argparse.ArgumentParser(description="nb_curl 平价边界套件（本地、动态端口）")
    p.add_argument("--package-path", action="append", default=[], metavar="DIR")
    p.add_argument("--module", default="nb_curl")
    p.add_argument("--backend", default="", choices=["", "auto", "cffi", "ctypes"],
                   help="导入前设置 NB_CURL_BACKEND；请求的后端不被满足即 setup 失败")
    p.add_argument("--only", default="", metavar="SUBSTR[,SUBSTR]")
    p.add_argument("--list", action="store_true")
    p.add_argument("--json", default="", metavar="PATH")
    p.add_argument("--overall-timeout", type=float, default=180.0)
    p.add_argument("--utf8-output", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.utf8_output:
        for s_ in (sys.stdout, sys.stderr):
            try:
                s_.reconfigure(encoding="utf-8", errors="backslashreplace")
            except (AttributeError, ValueError):
                pass
    if args.list:
        for name, _ in CASES:
            print(name)
        return EXIT_OK
    for key in list(os.environ):
        if key.lower() in PROXY_ENV_VARS:
            os.environ.pop(key, None)

    if args.backend:
        os.environ["NB_CURL_BACKEND"] = args.backend
    for raw in reversed(args.package_path):
        sys.path.insert(0, str(Path(raw).resolve()))
    try:
        mod = importlib.import_module(args.module)
    except BaseException as exc:
        print("[SETUP FAIL] import 失败: %r" % (exc,))
        return EXIT_SETUP
    impl_file = str(Path(getattr(mod, "__file__", "?")).resolve())
    backend = getattr(mod, "backend_name", lambda: "?")()
    print("=" * 72)
    print("nb_curl 平价边界套件  实现=%s 后端=%s 版本=%r" %
          (impl_file, backend, getattr(mod, "__version__", None)))
    if args.backend in ("cffi", "ctypes") and backend != args.backend:
        print("[SETUP FAIL] 请求 backend=%r 实际 %r（拒绝静默回退）" % (args.backend, backend))
        return EXIT_SETUP

    timer = threading.Timer(args.overall_timeout, lambda: os._exit(EXIT_WATCHDOG))
    timer.daemon = True
    timer.start()

    hdr = _hdr_server()
    srv = LocalServer().start()
    urls = {"echo": "http://127.0.0.1:%d/echo-hdr" % hdr.server_address[1],
            "latin1": "http://127.0.0.1:%d/latin1" % hdr.server_address[1],
            "deflate": "http://127.0.0.1:%d/deflate" % hdr.server_address[1],
            "delay": "http://127.0.0.1:%d/delay" % hdr.server_address[1]}
    t = Suite()
    try:
        for name, fn in CASES:
            if args.only and not any(x.strip() and x.strip() in name
                                     for x in args.only.split(",")):
                continue
            t.case(name)
            try:
                fn(mod, t, srv) if fn in _SRV_CASES else fn(mod, t, urls)
            except BaseException as exc:
                t.check("用例自身未抛异常", False, "%s: %s" % (type(exc).__name__, exc))
                traceback.print_exc()
            t.end()
    finally:
        srv.stop()
        hdr.shutdown()
        hdr.server_close()
        timer.cancel()

    print("\n" + "=" * 72)
    print("结果：%d 条断言，通过 %d，失败 %d" % (t.passed + t.failed, t.passed, t.failed))
    for c in t.cases:
        for ck in c["checks"]:
            if not ck["ok"]:
                print("  [FAIL] %s / %s  %s" % (c["case"], ck["name"], ck["detail"]))
    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({
            "suite": "nb_curl-parity-edges",
            "implementation": impl_file, "backend": backend,
            "passed": t.passed, "failed": t.failed, "cases": t.cases,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        print("JSON 报告：%s" % out.resolve())
    return EXIT_OK if t.failed == 0 else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
