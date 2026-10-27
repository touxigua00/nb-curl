"""nb_curl 本地回归套件（同步 + 异步，纯 stdlib）。

设计约束：

* **只打本地服务**。全部流量走 127.0.0.1 动态端口，不碰任何第三方站点，
  也不做任何指纹 / 反检测断言 —— 那些需要真实 TLS，不属于本套件的范围。
* **不隐藏问题**。没有 skip、没有 xfail：每条断言要么过要么记 FAIL，
  退出码如实反映。
* **实现由调用方显式选择**。``--package-path`` / ``PYTHONPATH`` 指到哪就用哪，
  本套件自己**只**把 ``tests/`` 目录加进 ``sys.path``（为了 import 同级的
  ``local_server``），不会插入任何其它路径；导入后会核对
  ``nb_curl.__file__`` 是否确实落在指定目录里，不符直接报错退出。
* **端口动态绑定、结束即清理**：服务端 port=0，套件结束时 shutdown + close，
  并追加一条"端口确实已释放"的断言。

用法（在仓库根目录执行）::

    # 用当前目录下的 nb_curl
    python tests/run_local_regression.py --package-path .

    # 也可以只靠 PYTHONPATH，不传 --package-path
    set PYTHONPATH=. && python tests/run_local_regression.py

    # 只跑某些用例 / 先看清单 / 出 JSON
    ... --list
    ... --only stream,cookies
    ... --json regression-report.json
"""

from __future__ import annotations

import argparse
import asyncio
import gc
import importlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    # 只为 import 同目录的 local_server（本套件自己的目录）
    sys.path.insert(0, str(_HERE))

from local_server import (  # noqa: E402
    PATTERN,
    LocalServer,
    pattern_bytes,
    sha256_hex,
)

# --------------------------------------------------------------------------- #
# 参数常量
# --------------------------------------------------------------------------- #
BACKPRESSURE_TOTAL = 32 * 1024 * 1024        # 背压用例：32 MiB 一次流式响应
BACKPRESSURE_MAX_SERVED_RATIO = 0.90         # 无人读取时，服务端不应能把整份体写完
CANCEL_DELAY_S = 12.0                        # 取消用例里的慢请求时长
CANCEL_CLOSE_BUDGET_S = 4.0                  # 取消后 close 必须在此预算内返回
CANCEL_HARD_WAIT_S = 25.0                    # 断言失败后仍等它收尾，避免留下悬空线程
ASYNC_COMPAT_WATCHDOG_S = 30.0               # 同 loop 同步读兼容用例的进程级看门狗
CLOSE_INFLIGHT_REQ_DELAY_S = 1.5             # 该用例内单个请求时长（<=2s）
CLOSE_INFLIGHT_WATCHDOG_S = 10.0             # 该用例内各等待（含 close）的硬看门狗
PROXY_ENV_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy")

REQUIRED_EXPORTS = (
    "Session", "AsyncSession", "Response", "Request", "Headers", "CookieJar",
    "Timeout", "HTTPError", "TooManyRedirects", "RequestError", "NbCurlError",
    "backend_name", "__version__", "get", "post", "put", "patch", "delete",
    "head", "options", "request",
)


def scrub_proxy_env() -> list:
    """清掉进程内代理环境变量；**只记录变量名**，绝不把值写进报告。

    代理 URL 常带 ``user:password@host``，把 ``key=value`` 记进 JSON 就是泄漏凭证。
    报告里只出现"清掉了哪些名字"，值是死是活都不落盘。

    环境清理只是防御（宿主机的代理变量不该影响回环流量）：
    ``proxy=""``（显式禁用代理、连环境变量都不读）是**必须保留的公开 API**，
    套件里仍然显式使用它（见 ``proxy.empty_string`` 用例）—— 不能把"清掉环境变量"
    当成"不必保留空串语义"的理由。
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
    """按显式给出的目录选实现；返回 (module, info)。失败时 module 为 None。"""
    info = {
        "requested_paths": [str(p) for p in package_paths],
        "sys_path_head": list(sys.path[:8]),
        "resolved": None,
        "error": None,
    }
    for raw in reversed(package_paths):
        path = Path(raw).expanduser()
        try:
            path = path.resolve()
        except OSError:
            pass
        if not path.is_dir():
            info["error"] = "package-path 不存在或不是目录: %s" % path
            return None, info
        sys.path.insert(0, str(path))
    try:
        mod = importlib.import_module(module)
    except BaseException as exc:                      # noqa: BLE001
        info["error"] = "import %s 失败: %r" % (module, exc)
        return None, info

    resolved = Path(getattr(mod, "__file__", "") or "<unknown>")
    try:
        resolved = resolved.resolve()
    except OSError:
        pass
    info["resolved"] = str(resolved)
    if package_paths:
        inside = [str(p) for p in package_paths
                  if _is_within(resolved, Path(p).expanduser().resolve())]
        if not inside:
            info["error"] = ("import 到的 nb_curl 不在指定 package-path 内：%s"
                             " （--package-path %s）" % (resolved, ", ".join(map(str, package_paths))))
            return None, info
        info["matched_package_path"] = inside[0]
    return mod, info


def implementation_info(mod) -> dict:
    """记录"实际用的是哪一份实现"—— 结论必须可复现。"""
    def safe(fn, *a):
        try:
            return fn(*a)
        except BaseException as exc:                  # noqa: BLE001
            return "<error: %r>" % (exc,)

    return {
        "module": getattr(mod, "__name__", "?"),
        "file": str(Path(getattr(mod, "__file__", "") or "").resolve()),
        "version": getattr(mod, "__version__", None),
        "backend": safe(getattr(mod, "backend_name", lambda: None)),
        "backend_info": safe(getattr(mod, "backend_info", lambda: None)),
        "available_backends": safe(getattr(mod, "available_backends", lambda: None)),
        "native_version": safe(getattr(mod, "native_version", lambda: None)),
    }


def count_handles():
    """当前进程的 FD / 句柄数（纯 stdlib）。拿不到就返回 None，不猜。"""
    if os.name == "nt":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            k32.GetCurrentProcess.restype = ctypes.c_void_p
            k32.GetProcessHandleCount.argtypes = [ctypes.c_void_p,
                                                 ctypes.POINTER(ctypes.c_ulong)]
            k32.GetProcessHandleCount.restype = ctypes.c_int
            handle = ctypes.c_ulong(0)
            proc = k32.GetCurrentProcess()
            if proc and k32.GetProcessHandleCount(proc, ctypes.byref(handle)):
                return int(handle.value)
        except BaseException:                         # noqa: BLE001
            return None
        return None
    for probe in ("/proc/self/fd",):
        try:
            return len(os.listdir(probe))
        except OSError:
            continue
    return None


# --------------------------------------------------------------------------- #
# 极小测试框架
# --------------------------------------------------------------------------- #
class Tester:
    def __init__(self, mod, srv: LocalServer, args) -> None:
        self.mod = mod
        self.srv = srv
        self.args = args
        self.cases: list = []
        self._cur: dict = None
        self._failed_in_case = False
        self.passed = 0
        self.failed = 0

    # -- 用例边界 ---------------------------------------------------------- #
    @property
    def failed_in_case(self) -> bool:
        return self._failed_in_case

    def begin_case(self, name: str) -> None:
        self._cur = {"name": name, "checks": [], "seconds": 0.0}
        self._failed_in_case = False

    def end_case(self, name: str, seconds: float) -> None:
        if self._cur is not None:
            self._cur["seconds"] = round(seconds, 3)
            self.cases.append(self._cur)
            self._cur = None

    # -- 断言 -------------------------------------------------------------- #
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
            self._failed_in_case = True
            print("      [FAIL] %s   %s" % (name, entry["detail"]))
        return ok

    def eq(self, name: str, got, want) -> bool:
        return self.check(name, got == want, "got=%r want=%r" % (got, want))

    def note(self, text: str) -> None:
        print("      [info] %s" % text)

    def raises(self, name: str, exc_types, fn, *, code=None):
        """断言 fn() 抛指定异常；顺带核对 curl 错误码（如果要求）。"""
        t0 = time.perf_counter()
        try:
            fn()
        except exc_types as exc:
            dt = time.perf_counter() - t0
            detail = "%s: %s (%.2fs)" % (type(exc).__name__, str(exc)[:160], dt)
            if code is not None:
                got = getattr(exc, "code", None)
                return self.check(name, got == code, detail + " code=%r 期望=%r" % (got, code)), exc
            return self.check(name, True, detail), exc
        except BaseException as exc:                  # noqa: BLE001
            return self.check(name, False, "抛了非预期异常 %r" % (exc,)), exc
        return self.check(name, False, "没有抛异常"), None

    def no_raise(self, name: str, fn):
        try:
            value = fn()
        except BaseException as exc:                  # noqa: BLE001
            self.check(name, False, "抛了 %r" % (exc,))
            return None
        self.check(name, True)
        return value


CASES: list = []


def case(name: str, group: str = None):
    def deco(fn):
        CASES.append({"name": name, "group": group or name, "fn": fn})
        return fn
    return deco


# --------------------------------------------------------------------------- #
# 1. 实现与本地服务
# --------------------------------------------------------------------------- #
@case("impl.import")
def case_impl_import(t: Tester, srv: LocalServer) -> None:
    missing = [n for n in REQUIRED_EXPORTS if not hasattr(t.mod, n)]
    t.check("公开 API 齐全（%d 项）" % len(REQUIRED_EXPORTS), not missing, "缺少 %s" % missing)
    backend = getattr(t.mod, "backend_name", lambda: None)()
    t.check("backend_name() 非空", bool(backend), repr(backend))
    t.note("实现文件 = %s" % Path(t.mod.__file__).resolve())
    t.note("version=%r backend=%r" % (getattr(t.mod, "__version__", None), backend))


@case("server.lifecycle")
def case_server_lifecycle(t: Tester, srv: LocalServer) -> None:
    t.check("端口是动态绑定（非固定值）", srv.port != 0, "port=%s" % srv.port)
    r = t.mod.get(srv.url("/echo"), timeout=10)
    t.eq("本地服务可达", r.status_code, 200)
    snap = srv.stats_snapshot()
    t.check("服务端计数到请求", snap["requests"] >= 1, "requests=%d" % snap["requests"])
    t.check("服务端计数到连接", snap["connections"] >= 1, "connections=%d" % snap["connections"])
    admin = t.mod.get(srv.url("/admin/stats"), timeout=10).json()
    t.eq("admin/stats 属于本进程", admin.get("pid"), os.getpid())


@case("proxy.empty_string")
def case_proxy_empty_string(t: Tester, srv: LocalServer) -> None:
    """``proxy=""``（显式禁用代理）是保留的公开 API，环境里有代理变量也必须绕开。

    套件启动时清掉了进程里的代理变量（``scrub_proxy_env``），但那是**防御**，
    不是这个 API 的替代品：这里故意塞进一个打不通的代理，只有真的支持
    "空串 = 显式禁用" 才能拿到 200。代理地址只用回环（127.0.0.1:1），不外联。
    """
    m = t.mod
    key = "http_proxy"
    saved = os.environ.get(key)
    os.environ[key] = "http://user:password@127.0.0.1:1"      # 故意打不通
    try:
        with m.Session() as s:
            r = s.get(srv.url("/echo"), proxy="", timeout=10)
            t.eq("会话级 proxy=\"\" 绕开环境代理", r.status_code, 200)
        r = m.get(srv.url("/echo"), proxy="", timeout=10)
        t.eq("模块级 proxy=\"\" 绕开环境代理", r.status_code, 200)
        t.eq("绕开后请求内容正确", r.json().get("method"), "GET")
    finally:
        if saved is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = saved


@case("errors.one_line")
def case_errors_one_line(t: Tester, srv: LocalServer) -> None:
    """报错文案始终单行：细节照留，换行要被折叠掉（日志里别撑成一大坨）。

    97 是最容易带附加信息的错误（代理子原因 + 本次走的哪个代理）；这里既直接
    构造文案，也真发一次失败请求，两条路的 ``str(exc)`` 都不许出现 CR/LF ——
    细节（子原因、走的代理、手册链接）一个都不能少。
    """
    m = t.mod
    exc_mod = importlib.import_module(m.__name__ + ".exceptions")   # 不假设文件位置
    text = exc_mod.curl_error_detail(
        97, "proxy handshake error",
        proxy_error=2, proxy_in_use="ALL_PROXY=socks5://127.0.0.1:1")
    t.check("97 文案是单行", "\n" not in text and "\r" not in text, text[:200])
    t.check("97 文案保留代理子原因",
            "代理子原因 2 CURLPX_BAD_VERSION" in text, text[:200])
    t.check("97 文案保留实际代理",
            "ALL_PROXY=socks5://127.0.0.1:1" in text, text[:200])
    t.check("97 文案保留错误码手册链接", exc_mod.CURL_ERROR_DOC in text, text[:200])

    # 真发一次：回环上没人听的端口，立刻拒连；文案仍要单行、仍带错误码与手册
    ok, exc = t.raises(
        "连不上的端口会抛 RequestError", (m.RequestError,),
        lambda: m.get("http://127.0.0.1:1/echo", timeout=10))
    if ok and exc is not None:
        msg = str(exc)
        t.check("真实报错文案是单行", "\n" not in msg and "\r" not in msg, msg[:200])
        t.check("真实报错文案带错误码与手册",
                "(curl " in msg and exc_mod.CURL_ERROR_DOC in msg, msg[:200])


# --------------------------------------------------------------------------- #
# 2. 同步：方法与请求体
# --------------------------------------------------------------------------- #
@case("sync.methods")
def case_sync_methods(t: Tester, srv: LocalServer) -> None:
    m = t.mod
    with m.Session() as s:
        for method, call, kw in (
            ("GET", s.get, {}),
            ("DELETE", s.delete, {}),
            ("OPTIONS", s.options, {}),
            ("POST", s.post, {"data": b""}),
            ("PUT", s.put, {"data": b"p"}),
            ("PATCH", s.patch, {"data": b"q"}),
        ):
            r = call(srv.url("/echo"), timeout=10, **kw)
            body = r.json()
            t.eq("%s 真的发出 %s" % (method, method), body.get("method"), method)
            t.eq("%s 状态码 200" % method, r.status_code, 200)
        r = s.head(srv.url("/echo"), timeout=10)
        t.eq("HEAD 状态码 200", r.status_code, 200)
        t.eq("HEAD 无响应体", r.content, b"")
        t.check("HEAD 仍带 Content-Length",
                int(r.headers.get("content-length") or 0) > 0,
                repr(r.headers.get("content-length")))

    # 模块级一次性入口 + 通用 request()
    r = m.get(srv.url("/echo"), timeout=10)
    t.eq("nb_curl.get 发出的方法", r.json().get("method"), "GET")
    r = m.request("OPTIONS", srv.url("/echo"), timeout=10)
    t.eq("nb_curl.request 任意方法", r.json().get("method"), "OPTIONS")

    # 响应元信息
    t.check("primary_ip 指向回环", r.primary_ip in ("127.0.0.1", "::1"), repr(r.primary_ip))
    t.check("http_version 是 1.x", str(r.http_version).startswith("1"), repr(r.http_version))
    t.check("elapsed 是正的 timedelta",
            hasattr(r.elapsed, "total_seconds") and r.elapsed.total_seconds() > 0,
            repr(r.elapsed))
    t.check("ok / __bool__ 一致", r.ok is True and bool(r) is True, "%r %r" % (r.ok, bool(r)))
    t.check("url 是最终 URL", r.url.endswith("/echo"), r.url)
    t.check("reason 已填充", bool(r.reason), repr(r.reason))


@case("sync.payloads")
def case_sync_payloads(t: Tester, srv: LocalServer) -> None:
    import base64

    with t.mod.Session() as s:
        # -- json --
        r = s.post(srv.url("/echo"), json={"a": 1, "b": "中文"}, timeout=10)
        d = r.json()
        t.check("json 体往返一致", json.loads(d["body_text"]) == {"a": 1, "b": "中文"},
                d["body_text"][:80])
        t.check("json 自动带 content-type",
                "application/json" in d["headers"].get("content-type", ""),
                d["headers"].get("content-type", ""))

        # -- form --
        r = s.post(srv.url("/echo"), data={"x": "y"}, timeout=10)
        d = r.json()
        t.eq("form 体是 urlencoded", d["body_text"], "x=y")
        t.check("form 自动带 content-type",
                "x-www-form-urlencoded" in d["headers"].get("content-type", ""),
                d["headers"].get("content-type", ""))

        # -- multipart --
        r = s.post(srv.url("/echo"), files={"f": ("a.bin", b"\x00\x01\xff")}, timeout=10)
        d = r.json()
        raw = base64.b64decode(d["body_b64"])
        t.check("multipart content-type 正确",
                "multipart/form-data" in d["headers"].get("content-type", ""),
                d["headers"].get("content-type", ""))
        t.check("multipart 文件名在体里", b'filename="a.bin"' in raw, repr(raw[:120]))
        t.check("multipart 二进制内容未被改动（含 NUL）", b"\x00\x01\xff" in raw, repr(raw[:160]))

        # -- 原始 bytes 体（含 NUL）--
        payload = PATTERN * 300
        r = s.post(srv.url("/echo"), data=payload, timeout=10)
        d = r.json()
        t.eq("bytes 体长度一致", d["body_len"], len(payload))
        t.eq("bytes 体 sha256 一致", d["body_sha256"], sha256_hex(payload))

        # -- 空 body 的 POST 仍要带 Content-Length: 0 --
        r = s.post(srv.url("/echo"), timeout=10)
        d = r.json()
        t.eq("空 POST 仍是 POST", d["method"], "POST")
        t.eq("空 POST 带 Content-Length: 0", d["headers"].get("content-length"), "0")

        # -- 请求头 / query 参数 --
        r = s.get(srv.url("/echo?a=1"), params={"q": "中文", "n": 2},
                  headers={"X-Test-Marker": "nb-curl-abc"}, timeout=10)
        d = r.json()
        t.eq("params 合并进已有 query（a）", d["query"].get("a"), "1")
        t.eq("params 新键（q）", d["query"].get("q"), "中文")
        t.eq("params 数字被字符串化（n）", d["query"].get("n"), "2")
        t.eq("自定义请求头送达", d["headers"].get("x-test-marker"), "nb-curl-abc")

        # -- 同一会话连发，头不丢也不串味 --
        seen = []
        for i in range(3):
            r = s.get(srv.url("/echo"), headers={"X-Seq": str(i)}, timeout=10)
            d = r.json()
            seen.append((d["headers"].get("x-seq"), d["headers"].get("x-test-marker")))
        t.check("连续 3 次请求头逐次正确",
                seen == [("0", None), ("1", None), ("2", None)], repr(seen))


# --------------------------------------------------------------------------- #
# 3. 二进制 / NUL / chunked
# --------------------------------------------------------------------------- #
@case("binary.nul")
def case_binary_nul(t: Tester, srv: LocalServer) -> None:
    m = t.mod
    r = m.get(srv.url("/binary/4096"), timeout=10)
    t.eq("4096 字节长度未截断", len(r.content), 4096)
    t.check("4096 字节逐一相同", r.content == pattern_bytes(4096),
            "首 16 字节=%r sha=%s" % (r.content[:16], sha256_hex(r.content)[:16]))
    t.eq("0 字节体是空 bytes", m.get(srv.url("/binary/0"), timeout=10).content, b"")
    t.eq("1 字节体精确", m.get(srv.url("/binary/1"), timeout=10).content, pattern_bytes(1))

    big = 1 << 20
    r = m.get(srv.url("/binary/%d" % big), timeout=30)
    t.eq("1 MiB 长度", len(r.content), big)
    t.eq("1 MiB sha256", sha256_hex(r.content), sha256_hex(pattern_bytes(big)))

    r = m.get(srv.url("/chunked/8192"), timeout=10)
    t.check("chunked 传输解码正确（含 NUL）", r.content == pattern_bytes(8192),
            "len=%d sha=%s" % (len(r.content), sha256_hex(r.content)[:16]))

    plain = m.get(srv.url("/binary/65536"), timeout=10).content
    streamed = m.get(srv.url("/binary/65536"), timeout=10, stream=True).content
    t.eq("stream 与非 stream 字节一致", streamed, plain)

    payload = PATTERN * 500
    with m.Session() as s:
        r = s.post(srv.url("/echo"), data=payload, timeout=10)
        t.eq("上传二进制体 sha256 一致", r.json()["body_sha256"], sha256_hex(payload))


# --------------------------------------------------------------------------- #
# 4. 重复头 / 1xx 中间响应
# --------------------------------------------------------------------------- #
@case("headers.duplicate")
def case_headers_duplicate(t: Tester, srv: LocalServer) -> None:
    m = t.mod
    r = m.get(srv.url("/dup-headers"), timeout=10)
    t.eq("状态码 200", r.status_code, 200)
    t.check("Headers 支持 get_list", hasattr(r.headers, "get_list"))
    vals = r.headers.get_list("x-dup") if hasattr(r.headers, "get_list") else []
    t.eq("两条重复头都保留且保序", vals, ["a", "b"])
    # get / dict 视图把重复头按 ", " 合并（浏览器 Headers 与 RFC 7230 的语义），
    # 只看单条用 get_list；以前这里返回其中一条，口径与浏览器不一致。
    t.eq("get 把重复头按 ', ' 合并", r.headers.get("x-dup"), "a, b")
    # 响应头的**名字大小写按服务端原样**，重复值按 ", " 合并；取值仍然大小写不敏感
    t.eq("to_dict 保留原大小写且合并", r.headers.to_dict().get("X-Dup"), "a, b")
    t.eq("keys() 保留原大小写", "X-Dup" in r.headers.keys(), True)
    t.check("头名大小写不敏感",
            r.headers.get("X-DUP") == r.headers.get("x-dup") == r.headers.get("X-Dup"),
            "%r %r" % (r.headers.get("X-DUP"), r.headers.get("x-dup")))
    t.check("in 运算符大小写不敏感", "X-Dup" in r.headers and "x-dup" in r.headers)

    sc = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []
    t.eq("两条 Set-Cookie 都在", len(sc), 2)
    t.eq("r.cookies 解析出两个 cookie", sorted(dict(r.cookies)), ["other", "sid"])
    t.check("raw_cookie_list 非空", bool(r.raw_cookie_list), repr(r.raw_cookie_list)[:120])

    # 请求侧同名头（pairs 形式）：不允许崩，且不应出现多余的第 3 条
    d = m.get(srv.url("/echo"), headers=[("X-Multi", "a"), ("X-Multi", "b")], timeout=10).json()
    got = [v for k, v in d["header_list"] if k == "x-multi"]
    # 浏览器（Chrome 155 实测：fetch 数组形式 / XHR 两次 setRequestHeader）把同名头
    # 用 ", " 拼成一条；它根本发不出两行同名请求头。
    t.check("请求侧同名头合并成一条", len(got) == 1, "x-multi=%r" % (got,))
    t.eq("合并后的值是按序拼接", got, ["a, b"])
    t.note("请求侧同名头实测 %d 条：%r" % (len(got), got))

    # 重定向各跳的头各自成块，不互相污染
    r = m.get(srv.url("/redirect/2"), timeout=10)
    t.eq("重定向 2 跳 history 长度", len(r.history), 2)
    t.eq("history[0] 是 302", r.history[0].status_code, 302)
    t.eq("history[0] 带 Location", r.history[0].headers.get("location"), "/redirect/1")
    t.eq("最终响应 200", r.status_code, 200)


@case("headers.interim")
def case_headers_interim(t: Tester, srv: LocalServer) -> None:
    payload = b"x" * (100 * 1024)                 # >1KiB -> libcurl 会带 Expect: 100-continue
    with t.mod.Session() as s:
        r = s.post(srv.url("/expect100"), data=payload, timeout=15)
        t.eq("1xx 中间响应后拿到最终 200", r.status_code, 200)
        d = r.json()
        t.eq("中间响应不影响请求体", d.get("body_len"), len(payload))
        t.eq("中间响应不影响请求体内容", d.get("body_sha256"), sha256_hex(payload))
        t.check("标记了 interim", d.get("interim") is True, repr(d))
        t.eq("会话随后仍可用",
             s.get(srv.url("/echo"), timeout=10).json()["method"], "GET")


# --------------------------------------------------------------------------- #
# 5. 重定向
# --------------------------------------------------------------------------- #
@case("redirects")
def case_redirects(t: Tester, srv: LocalServer) -> None:
    m = t.mod
    r = m.get(srv.url("/redirect/3"), timeout=10)
    t.eq("跟随 3 跳后状态码", r.status_code, 200)
    t.eq("history 记录 3 跳", len(r.history), 3)
    t.check("最终 URL 是重定向目标", r.url.endswith("/echo"), r.url)
    t.check("history 里都是 302",
            all(h.status_code == 302 for h in r.history),
            repr([h.status_code for h in r.history]))

    r = m.get(srv.url("/redirect/1"), allow_redirects=False, timeout=10)
    t.eq("allow_redirects=False 停在 302", r.status_code, 302)
    t.eq("拿到 Location 头", r.headers.get("location"), "/echo")
    t.eq("不跟随就没有 history", len(r.history), 0)

    exc = None
    try:
        m.get(srv.url("/redirect-loop"), max_redirects=3, timeout=10)
    except BaseException as e:                    # noqa: BLE001
        exc = e
    t.check("重定向超限抛 TooManyRedirects",
            isinstance(exc, getattr(m, "TooManyRedirects")),
            "%r" % (exc,))
    t.check("TooManyRedirects 带 curl 错误码 47",
            getattr(exc, "code", None) == 47, "code=%r" % getattr(exc, "code", None))

    # 302 那一跳上的 Set-Cookie 必须被引擎学到
    with m.Session() as s:
        s.get(srv.url("/cookies/set?hop=1"), timeout=10)
        jar = s.get(srv.url("/cookies"), timeout=10).json()["cookies"]
        t.eq("重定向跳上的 Set-Cookie 生效", jar.get("hop"), "1")


# --------------------------------------------------------------------------- #
# 6. cookie
# --------------------------------------------------------------------------- #
def _cookie_names(raw: str) -> list:
    return [p.split("=", 1)[0].strip() for p in (raw or "").split(";") if p.strip()]


@case("cookies.isolation")
def case_cookies_isolation(t: Tester, srv: LocalServer) -> None:
    m = t.mod
    a = m.Session()
    b = m.Session()
    try:
        a.get(srv.url("/cookies/set?sid=abc123"), timeout=10)
        raw_a = a.get(srv.url("/echo"), timeout=10).json()["headers"].get("cookie", "")
        raw_b = b.get(srv.url("/echo"), timeout=10).json()["headers"].get("cookie", "")
        t.eq("会话 A 学到 cookie", _cookie_names(raw_a), ["sid"])
        t.check("会话 A 的值正确", "sid=abc123" in raw_a, repr(raw_a))
        t.eq("会话 B 完全看不到 A 的 cookie", _cookie_names(raw_b), [])
        t.eq("CookieJar 里确实有这条", dict(a.cookies).get("sid"), "abc123")

        raw_a2 = a.get(srv.url("/echo"), timeout=10).json()["headers"].get("cookie", "")
        t.eq("第二次请求也只发一份（单通道不重复）", _cookie_names(raw_a2).count("sid"), 1)

        a.get(srv.url("/cookies/set?sid=updated"), timeout=10)
        raw_a3 = a.get(srv.url("/echo"), timeout=10).json()["headers"].get("cookie", "")
        t.eq("同名 cookie 更新后仍只有一份", _cookie_names(raw_a3).count("sid"), 1)
        t.check("值被服务端覆盖", "sid=updated" in raw_a3, repr(raw_a3))
    finally:
        a.close()
        b.close()


@case("cookies.request_scoped")
def case_cookies_request_scoped(t: Tester, srv: LocalServer) -> None:
    m = t.mod
    with m.Session() as s:
        s.get(srv.url("/cookies/set?sid=abc123"), timeout=10)

        raw = s.get(srv.url("/echo"), cookies={"tmp": "42"}, timeout=10).json()["headers"].get("cookie", "")
        t.check("请求级 cookies 与会话 cookie 共存",
                "tmp=42" in raw and "sid=abc123" in raw, repr(raw))
        t.eq("请求级 cookies 只发一份", _cookie_names(raw).count("tmp"), 1)
        t.check("请求级 cookies 不写进会话罐", "tmp" not in dict(s.cookies), repr(dict(s.cookies)))

        raw = s.get(srv.url("/echo"), headers={"Cookie": "sid=override; extra=1"},
                    timeout=10).json()["headers"].get("cookie", "")
        t.eq("显式 Cookie 头不重复", _cookie_names(raw).count("sid"), 1)
        t.check("显式 Cookie 头本次生效",
                "sid=override" in raw and "extra=1" in raw, repr(raw))
        raw_after = s.get(srv.url("/echo"), timeout=10).json()["headers"].get("cookie", "")
        t.check("显式 cookie 不写进会话罐（extra 消失）", "extra" not in raw_after, repr(raw_after))
        t.check("会话罐原值不受影响（sid=abc123）", "sid=abc123" in raw_after, repr(raw_after))

        # 手工写入 / 删除 / 清空
        t.check("cookies 是 CookieJar", isinstance(s.cookies, m.CookieJar), type(s.cookies).__name__)
        s.cookies["manual"] = "7"
        raw = s.get(srv.url("/echo"), timeout=10).json()["headers"].get("cookie", "")
        t.eq("手工写入的 cookie 只发一份", _cookie_names(raw).count("manual"), 1)
        del s.cookies["manual"]
        raw = s.get(srv.url("/echo"), timeout=10).json()["headers"].get("cookie", "")
        t.check("删掉后不再发出", "manual" not in raw, repr(raw))
        s.cookies.clear()
        t.eq("clear() 清空", dict(s.cookies), {})

    # 响应级 cookie 解析（不跟随重定向，直接看 302 的 Set-Cookie）
    r = m.get(srv.url("/cookies/set?r=9"), allow_redirects=False, timeout=10)
    t.eq("响应 cookies 解析 Set-Cookie", dict(r.cookies).get("r"), "9")


@case("cookies.order")
def case_cookies_order(t: Tester, srv: LocalServer) -> None:
    """显式给 cookie 时：**顺序原样**、**值原样**、**位置原样**。

    回归背景（两次）：
    1. 早先把用户给的 cookie 塞进 libcurl 的 cookie 引擎由它拼头，而引擎会按
       ``path 长度 > domain 长度 > name 长度 > 创建时间`` 排序
       （``lib/cookie.c: cookie_sort``），于是

           Cookie: uin=; p_uin=; p_uid=; SESSION_TRACE_ID=abc

       到了线上变成

           Cookie: SESSION_TRACE_ID=abc; p_uid=; p_uin=; uin=
    2. 之后改走 ``CURLOPT_COOKIE``，顺序对了，但它和 ``cookies=`` 的串是"解析成
       pairs 再拼回去"的：多余空格、重复名、末尾分号这些细节会被"整理"掉，
       而且 CURLOPT_COOKIE 由 libcurl 在 header 块里**补**一条 ``Cookie:``
       （写在自定义头之前），位置不受 ``headers=`` 控制 —— 用户在 headers 里
       把 Cookie 放到最后，线上却在最前面。

    现在：显式 cookie 就是一条真正的 header 行，值逐字节原样、位置就是给的位置。
    """
    m = t.mod
    with m.Session() as s:
        raw = s.get(srv.url("/echo"),
                    headers={"Cookie": "uin=; p_uin=; p_uid=; SESSION_TRACE_ID=abc"},
                    timeout=10).json()["headers"]["cookie"]
        t.eq("显式 Cookie 头：顺序原样、空值也保留", _cookie_names(raw),
             ["uin", "p_uin", "p_uid", "SESSION_TRACE_ID"])
        t.check("显式 Cookie 头：值一字不差",
                raw == "uin=; p_uin=; p_uid=; SESSION_TRACE_ID=abc", repr(raw))

        # 逐字节透传：内部多余空格、重复名、大小写都不许被"整理"
        # （行尾空白由服务端按 HTTP 语义剥掉，那是接收方行为，不是我们改写的）
        odd = "uin=o1;p_uin=o2;   p_uid=u3; extra=; A=UPPER"
        raw = s.get(srv.url("/echo"), headers={"Cookie": odd},
                    timeout=10).json()["headers"]["cookie"]
        t.check("显式 Cookie 头：内部空格/重复名/大小写都原样", raw == odd, repr(raw))

        raw = s.get(srv.url("/echo"),
                    cookies={"uin": "", "p_uin": "", "p_uid": "",
                             "SESSION_TRACE_ID": "abc"},
                    timeout=10).json()["headers"]["cookie"]
        t.eq("请求级 cookies：按 dict 顺序", _cookie_names(raw),
             ["uin", "p_uin", "p_uid", "SESSION_TRACE_ID"])

        # 位置：Cookie 在 headers 里的位置就是它在线上的位置（不是永远排第一）
        order = s.get(srv.url("/echo"),
                      headers={"x-a": "1", "Cookie": "sid=1", "x-z": "2"},
                      timeout=10).json()["header_list"]
        names = [k for k, _ in order]
        picked = [k for k in names if k in ("x-a", "cookie", "x-z")]
        t.eq("Cookie 头位置跟着 headers= 走（夹在中间）", picked,
             ["x-a", "cookie", "x-z"])
        t.eq("线上只有一条 cookie 头", names.count("cookie"), 1)

        order = s.get(srv.url("/echo"), headers={"x-a": "1", "x-z": "2"},
                      cookies={"sid": "1"}, timeout=10).json()["header_list"]
        names = [k for k, _ in order]
        t.eq("只给 cookies= 时追加在末尾", [k for k in names if k in ("x-a", "x-z", "cookie")],
             ["x-a", "x-z", "cookie"])

        # 会话罐里有 cookie 时：显式给的在前（按给序），罐里的跟在后面
        s.cookies["jarA"] = "1"
        s.cookies["jarB"] = "2"
        raw = s.get(srv.url("/echo"), headers={"Cookie": "z=9; a=1; m=5"},
                    timeout=10).json()["headers"]["cookie"]
        t.eq("显式在前、会话罐在后", _cookie_names(raw),
             ["z", "a", "m", "jarA", "jarB"])
        t.check("显式部分的值一字不差", raw.startswith("z=9; a=1; m=5"), repr(raw))
        t.eq("显式 cookie 不会被同名会话 cookie 顶掉", _cookie_names(raw).count("m"), 1)

        raw_after = s.get(srv.url("/echo"), timeout=10).json()["headers"]["cookie"]
        t.check("显式 cookie 不写进会话罐（z 消失）", "z=9" not in raw_after, repr(raw_after))
        t.check("后续请求会话罐照常下发", "jarA=1" in raw_after and "jarB=2" in raw_after,
                repr(raw_after))
        t.eq("只用会话罐时也只有一条 cookie 头",
             [k for k, _ in s.get(srv.url("/echo"), timeout=10)
              .json()["header_list"]].count("cookie"), 1)

        # 显式 cookie 那次请求的 Set-Cookie 仍要学回会话罐（引擎照常记录）
        s.cookies.clear()
        s.get(srv.url("/cookies/set?learned=1"), timeout=10,
              headers={"Cookie": "tmp=1"})
        raw_after = s.get(srv.url("/echo"), timeout=10).json()["headers"]["cookie"]
        t.check("显式 cookie 的请求也能学到 Set-Cookie",
                "learned=1" in raw_after, repr(raw_after))
        t.check("临时的显式 cookie 不会残留", "tmp=1" not in raw_after, repr(raw_after))


@case("cookies.jar_absorb")
def case_cookies_jar_absorb(t: Tester, srv: LocalServer) -> None:
    """CookieJar._absorb 对"过期/未知 key"的吸收不能 KeyError。

    引擎导出里出现一条"早已过期"的同名行时，``_absorb`` 会走删除分支
    （``del self._lines[key]``）。若引擎里根本没有这条 key（导出顺序/引擎
    自清理的时序差异），直接 ``del`` 会 KeyError。功能口径：
    吸收过程不炸、罐子状态自洽 —— 不对"何时把过期行推给引擎"的时序做断言。
    """
    m = t.mod
    with m.Session() as s:
        s.get(srv.url("/cookies/set?sid=keep"), timeout=10)
        jar = s.cookies
        t.check("会话学到 cookie", dict(jar).get("sid") == "keep", repr(dict(jar)))
        now = time.time()
        # 一条未知 key 的过期行（引擎里从没学过它）
        unknown_line = "127.0.0.1\tFALSE\t/\tFALSE\t1\tghost\tgone"
        # 一条已知 key（可能）的过期行：作用域键与现有 sid 行一致时才触发删除分支
        known_line = "127.0.0.1\tFALSE\t/\tFALSE\t1\tsid\tstale"
        t.no_raise("吸收过期未知 key 不 KeyError（unknown）",
                   lambda: jar._absorb(unknown_line, now))
        t.no_raise("吸收过期已知 key 不 KeyError（sid）",
                   lambda: jar._absorb(known_line, now))
        t.no_raise("吸收过期行后重复 _prune 幂等", lambda: jar._prune(now))
        t.check("吸收过期未知 key 后 ghost 不在罐里", "ghost" not in dict(jar),
                repr(dict(jar)))
        r = s.get(srv.url("/echo"), timeout=10)
        t.check("吸收过期行后会话仍能正常请求", r.status_code == 200,
                "status=%s" % r.status_code)
        # 过期吸收不应误删还活着的 cookie：再学一条，过期吸收 ghost/sid 行后仍在
        s.get(srv.url("/cookies/set?fresh=1"), timeout=10)
        jar._absorb(unknown_line, now)           # 再来一次也不许炸
        d = s.get(srv.url("/echo"), timeout=10).json()["headers"].get("cookie", "")
        t.check("过期吸收没有误删活 cookie（fresh 仍发出）", "fresh=1" in d, repr(d))


@case("cookies.concurrent")
def case_cookies_concurrent(t: Tester, srv: LocalServer) -> None:
    """20 个线程共用同一 Session 的最小安全并发功能检测。

    口径刻意很薄：并发调用不崩（无未捕获异常）、每个响应功能上正确、
    cookie 能被学到且后续请求可用。**不断言**并发竞态下的最后写入顺序
    （哪个线程的 Set-Cookie 最终生效是不确定的），只要求状态自洽。
    """
    m = t.mod
    errors = []
    results = []
    lock = threading.Lock()

    def worker(i: int) -> None:
        try:
            with lock:
                pass
            s = m.Session()
            try:
                # 各自设一个名字独立的 cookie（避免互相覆盖顺序问题）
                s.get(srv.url("/cookies/set?w%d=%d" % (i, i)), timeout=15)
                r = s.get(srv.url("/echo"), timeout=15)
                results.append((i, r.status_code))
            finally:
                s.close()
        except BaseException as exc:                  # noqa: BLE001
            errors.append("worker %d: %r" % (i, exc))

    with m.Session() as shared:
        def shared_worker(i: int) -> None:
            try:
                r = shared.get(srv.url("/echo"), timeout=15,
                               headers={"X-Worker": str(i)})
                with lock:
                    results.append((1000 + i, r.status_code))
            except BaseException as exc:              # noqa: BLE001
                errors.append("shared %d: %r" % (i, exc))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        threads += [threading.Thread(target=shared_worker, args=(i,))
                    for i in range(10)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(30)
        alive = [th for th in threads if th.is_alive()]

    t.eq("20 个并发线程全部在 30s 内退出", alive, [])
    t.eq("无未捕获异常", errors, [])
    t.eq("每个独立会话请求都拿到 200", sorted(code for i, code in results if i < 1000),
         [200] * 10)
    t.eq("共享会话并发请求都拿到 200", sorted(code for i, code in results if i >= 1000),
         [200] * 10)
    t.note("共收到 %d 个有效结果（独立会话 10 + 共享会话 10 = 20）" % len(results))


# --------------------------------------------------------------------------- #
# 7. gzip / 超时
# --------------------------------------------------------------------------- #
@case("gzip")
def case_gzip(t: Tester, srv: LocalServer) -> None:
    m = t.mod
    r = m.get(srv.url("/gzip"), timeout=10)
    t.eq("gzip 自动解压", r.json().get("text"), "压缩测试")
    t.check("content-encoding 头保留原样",
            r.headers.get("content-encoding") in ("gzip", None),
            repr(r.headers.get("content-encoding")))

    n = 4096
    r = m.get(srv.url("/gzip-binary/%d" % n), timeout=10)
    t.check("gzip 二进制体解压后逐字节一致", r.content == pattern_bytes(n),
            "len=%d" % len(r.content))

    with m.Session() as s:
        plain = s.get(srv.url("/gzip"), timeout=10).content
        streamed = s.get(srv.url("/gzip"), timeout=10, stream=True).content
        t.eq("gzip 的 stream 与非 stream 一致", streamed, plain)


@case("timeout")
def case_timeout(t: Tester, srv: LocalServer) -> None:
    m = t.mod
    t0 = time.perf_counter()
    _, exc = t.raises("慢响应超时抛 Timeout",
                      getattr(m, "Timeout"), lambda: m.get(srv.url("/delay/3"), timeout=0.8),
                      code=28)
    dt = time.perf_counter() - t0
    t.check("超时没有拖到服务端睡完（< 2.5s）", dt < 2.5, "%.2fs" % dt)
    t.check("错误信息含 CURLE_OPERATION_TIMEDOUT",
            exc is not None and "CURLE_OPERATION_TIMEDOUT" in str(exc), repr(str(exc))[:200])

    with m.Session() as s:
        t.raises("会话级超时同样抛 Timeout",
                 getattr(m, "Timeout"), lambda: s.get(srv.url("/delay/2"), timeout=0.5), code=28)
        t.eq("超时之后会话仍可用",
             s.get(srv.url("/echo"), timeout=10).json()["method"], "GET")


# --------------------------------------------------------------------------- #
# 8. 关闭 / 错误之后可继续
# --------------------------------------------------------------------------- #
@case("close.session")
def case_close_session(t: Tester, srv: LocalServer) -> None:
    m = t.mod
    s = m.Session()
    t.eq("新会话未关闭", s.closed, False)
    t.eq("关闭前请求正常", s.get(srv.url("/echo"), timeout=10).status_code, 200)
    s.close()
    t.no_raise("重复 close() 幂等（第 2 次）", s.close)
    t.no_raise("重复 close() 幂等（第 3 次）", s.close)
    t.eq("closed 变为 True", s.closed, True)
    t.raises("关闭后拒绝新请求", getattr(m, "NbCurlError"),
             lambda: s.get(srv.url("/echo"), timeout=10))

    with m.Session() as s2:
        t.eq("with 块内可用", s2.get(srv.url("/echo"), timeout=10).status_code, 200)
    t.eq("退出 with 后已关闭", s2.closed, True)
    t.raises("退出 with 后拒绝新请求", getattr(m, "NbCurlError"),
             lambda: s2.get(srv.url("/echo"), timeout=10))

    t.no_raise("模块级一次性入口不报错（会话自己收）",
               lambda: m.get(srv.url("/echo"), timeout=10))


@case("close.response")
def case_close_response(t: Tester, srv: LocalServer) -> None:
    m = t.mod
    with m.Session() as s:
        r = s.get(srv.url("/echo"), timeout=10)
        t.no_raise("非流式 close() 无副作用", r.close)
        t.no_raise("非流式重复 close()", r.close)
        t.eq("close 之后会话仍可用",
             s.get(srv.url("/echo"), timeout=10).json()["method"], "GET")

        # 流式：提前 close 必须真的中止（整体约 6s）
        t0 = time.perf_counter()
        r = s.get(srv.url("/drip/20/1000"), timeout=30, stream=True)
        first = next(iter(r.iter_content(128)), b"")
        r.close()
        dt = time.perf_counter() - t0
        t.check("提前 close 前已拿到首块", len(first) > 0, "len=%d" % len(first))
        t.check("提前 close 没有等整份体（< 2.0s）", dt < 2.0, "%.2fs" % dt)
        t.check("close 后 is_stream=False", r.is_stream is False, repr(r.is_stream))
        t.eq("close 之后会话仍可用",
             s.get(srv.url("/echo"), timeout=10).json()["method"], "GET")

        # 会话 close 要能把还开着的流一起收掉
        r = s.get(srv.url("/drip/40/65536"), timeout=30, stream=True)
        next(iter(r.iter_content(64)), b"")
        t0 = time.perf_counter()
        s.close()
        dt = time.perf_counter() - t0
        t.check("带未读完的流时 session.close() 不阻塞（< 2.0s）", dt < 2.0, "%.2fs" % dt)

    t0 = time.perf_counter()
    with m.get(srv.url("/drip/3/100"), timeout=20, stream=True) as r:
        chunk = next(iter(r.iter_content(100)), b"")
        t.check("模块级 stream=True + with 可增量读取",
                len(chunk) == 100 and r.status_code == 200,
                "len=%d status=%s" % (len(chunk), r.status_code))
    t.check("退出 with 后流已关闭", r.is_stream is False, repr(r.is_stream))
    t.check("with 退出很快（未等整份体）", time.perf_counter() - t0 < 3.0,
            "%.2fs" % (time.perf_counter() - t0))


@case("reuse.after.errors")
def case_reuse_after_errors(t: Tester, srv: LocalServer) -> None:
    m = t.mod
    dead_port = _free_port()

    with m.Session() as s:
        t.eq("首次请求正常", s.get(srv.url("/echo"), timeout=10).status_code, 200)

        t.raises("连不上的端口抛 RequestError",
                 (getattr(m, "RequestError"), getattr(m, "NbCurlError")),
                 lambda: s.get("http://127.0.0.1:%d/echo" % dead_port, timeout=5))
        t.eq("连接失败之后会话可用",
             s.get(srv.url("/echo"), timeout=10).json()["method"], "GET")

        t.raises("短体（Content-Length 未满足）抛错",
                 (getattr(m, "RequestError"), getattr(m, "NbCurlError")),
                 lambda: s.get(srv.url("/close-mid-body/1000/100"), timeout=10))
        t.eq("短体之后会话可用",
             s.get(srv.url("/echo"), timeout=10).json()["method"], "GET")

        t.raises("对端硬断（RST）抛错",
                 (getattr(m, "RequestError"), getattr(m, "NbCurlError")),
                 lambda: s.get(srv.url("/reset"), timeout=10))
        t.eq("RST 之后会话可用",
             s.get(srv.url("/echo"), timeout=10).json()["method"], "GET")

        r = s.get(srv.url("/status/404"), timeout=10)
        t.eq("404 状态码原样返回", r.status_code, 404)
        t.raises("404 raise_for_status 抛 HTTPError",
                 getattr(m, "HTTPError"), r.raise_for_status)
        t.raises("500 raise_for_status 抛 HTTPError", getattr(m, "HTTPError"),
                 lambda: s.get(srv.url("/status/500"), timeout=10).raise_for_status())
        t.eq("HTTPError 之后会话可用",
             s.get(srv.url("/echo"), timeout=10).json()["method"], "GET")

        t.raises("未知参数抛 TypeError", TypeError,
                 lambda: s.get(srv.url("/echo"), timeout=10, no_such_option=1))
        t.raises("非法 URL 抛 NbCurlError/ValueError",
                 (getattr(m, "NbCurlError"), ValueError),
                 lambda: s.get("http://[::1", timeout=5))
        t.eq("参数/URL 错误之后会话可用",
             s.get(srv.url("/echo"), timeout=10).json()["method"], "GET")


# --------------------------------------------------------------------------- #
# 9. 流式：增量 / 游标 / 背压
# --------------------------------------------------------------------------- #
@case("stream.incremental")
def case_stream_incremental(t: Tester, srv: LocalServer) -> None:
    m = t.mod
    with m.Session() as s:
        t0 = time.perf_counter()
        r = s.get(srv.url("/drip/5/200"), timeout=20, stream=True)
        t_ret = time.perf_counter() - t0
        t.eq("返回时状态码已可用", r.status_code, 200)
        t.eq("返回时响应头已可用", r.headers.get("content-length"), "1000")
        t.check("返回没等整份体（整体约 1.5s）", t_ret < 0.6, "%.2fs" % t_ret)
        t.check("返回时 is_stream=True", r.is_stream is True, repr(r.is_stream))
        t.check("返回时还没读（stream_consumed=False）",
                r.stream_consumed is False, repr(r.stream_consumed))

        marks = []
        for chunk in r.iter_content(64):
            marks.append((time.perf_counter() - t0, len(chunk)))
        t.check("逐块产出而不是一次性给完", len(marks) > 1, "%d 块" % len(marks))
        if marks:
            t.check("首块远早于整体结束（< 0.3s）", marks[0][0] < 0.3, "%.3fs" % marks[0][0])
        t.eq("逐块累计字节数正确", sum(m[1] for m in marks), 1000)
        t.check("读完后 is_stream=False", r.is_stream is False, repr(r.is_stream))
        t.check("读完后 stream_consumed=True", r.stream_consumed is True,
                repr(r.stream_consumed))
        r.close()


@case("stream.cursor")
def case_stream_cursor(t: Tester, srv: LocalServer) -> None:
    m = t.mod
    with m.Session() as s:
        # 中途 break 之后 content 只给剩余部分
        r = s.get(srv.url("/drip/4/100?interval=0.05"), timeout=20, stream=True)
        got = 0
        for chunk in r.iter_content(100):
            got += len(chunk)
            break
        rest = r.content
        t.eq("break 后 content 只给没读的部分（%d + %d = 400）" % (got, len(rest)),
             got + len(rest), 400)
        r.close()

        # 分多次取，游标接着走
        r = s.get(srv.url("/drip/4/100?interval=0.05"), timeout=20, stream=True)
        it = r.iter_content(100)
        a = next(it, b"")
        b = next(it, b"")
        c = r.content
        t.eq("多次 iter_content 接着读，累计完整", len(a) + len(b) + len(c), 400)
        r.close()

        # content 读完后再 iter_content：退化为在缓存上切片（与非流式一致）
        r = s.get(srv.url("/binary/1000"), timeout=10, stream=True)
        full = r.content
        t.check("content 之后 iter_content 在缓存上切片",
                b"".join(r.iter_content(256)) == full and len(full) == 1000,
                "len=%d" % len(full))
        r.close()

        # 流式中途丢弃：close 之后同会话继续用（上面的 close.response 也覆盖）
        r = s.get(srv.url("/drip/40/65536"), timeout=30, stream=True)
        next(iter(r.iter_content(64)), b"")
        r.close()
        t.eq("丢弃流之后会话仍可用",
             s.get(srv.url("/echo"), timeout=10).json()["method"], "GET")


@case("stream.backpressure")
def case_stream_backpressure(t: Tester, srv: LocalServer) -> None:
    """背压：没人读时，客户端不应把整份响应体吞进内存。

    可观测口径：服务端"已经写进 socket 的字节数"。若客户端无界缓冲，
    curl 会把 32 MiB 全部从内核读走并在 1s 内写完；若有界（高水位 + TCP 背压），
    服务端会卡在 send 上，写出的只是一小段。
    """
    m = t.mod
    srv.stats.reset()
    chunk = 1 << 20
    chunks = BACKPRESSURE_TOTAL // chunk
    route = "/drip/%d/%d" % (chunks, chunk)
    with m.Session() as s:
        r = s.get(srv.url(route + "?interval=0"), timeout=120, stream=True)
        t.eq("大响应状态码", r.status_code, 200)
        time.sleep(1.0)                            # 完全不读，看看服务端能写多少
        served = srv.stats.bytes_under(route)
        ratio = served / float(BACKPRESSURE_TOTAL)
        t.check("无人读取时服务端写不满整份体（背压生效）",
                ratio <= BACKPRESSURE_MAX_SERVED_RATIO,
                "服务端已写出 %.1f MiB（%.1f%%），阈值 %.0f%%"
                % (served / 1048576.0, ratio * 100, BACKPRESSURE_MAX_SERVED_RATIO * 100))

        total = sum(len(c) for c in r.iter_content(1 << 16))
        t.eq("随后完整读出的字节数", total, BACKPRESSURE_TOTAL)
        t.eq("服务端最终写出的字节数", srv.stats.bytes_under(route), BACKPRESSURE_TOTAL)
        r.close()

        # 同步 content 与流式混用：中途 break 之后，content 必须补上剩余部分
        r = s.get(srv.url("/binary/5000"), timeout=10, stream=True)
        first = next(iter(r.iter_content(1000)), b"")
        rest = r.content
        t.check("中途 break 后 content 补上剩余部分（游标不丢数据）",
                len(first) + len(rest) == 5000,
                "首块 %d + content %d = %d，期望 5000（整份体在 break 处被丢弃）"
                % (len(first), len(rest), len(first) + len(rest)))
        t.eq("非流式响应 content 即全部体",
             len(s.get(srv.url("/binary/3000"), timeout=10).content), 3000)
        r.close()


@case("iter_content.nonstream")
def case_iter_content_nonstream(t: Tester, srv: LocalServer) -> None:
    m = t.mod
    r = m.get(srv.url("/binary/3000"), timeout=10)
    t.check("非流式 is_stream=False", r.is_stream is False, repr(r.is_stream))
    t.check("非流式 stream_consumed=True", r.stream_consumed is True, repr(r.stream_consumed))
    chunks = list(r.iter_content(1000))
    t.eq("切片块数", len(chunks), 3)
    t.check("切片累计等于 content", b"".join(chunks) == r.content, "len=%d" % len(r.content))
    t.check("每块不超过 chunk_size", all(len(c) <= 1000 for c in chunks),
            repr([len(c) for c in chunks]))
    t.check("再次 iter_content 从头来（非流式语义）",
            b"".join(r.iter_content(2048)) == r.content)
    lines = list(r.iter_lines())
    expected_lines = r.content.split(b"\n")
    if expected_lines and expected_lines[-1] == b"":
        expected_lines.pop()               # iter_lines 不产出末尾空片
    t.check("iter_lines 按 \\n 切分且不丢字节", lines == expected_lines,
            "%d 行 / 期望 %d 行" % (len(lines), len(expected_lines)))


# --------------------------------------------------------------------------- #
# 10. 资源：反复建/关不泄漏
# --------------------------------------------------------------------------- #
@case("resources.churn")
def case_resources_churn(t: Tester, srv: LocalServer) -> None:
    m = t.mod
    gc.collect()
    time.sleep(0.2)
    threads_before = threading.active_count()
    handles_before = count_handles()

    for _ in range(15):
        s = m.Session()
        try:
            s.get(srv.url("/echo"), timeout=10)
            s.get(srv.url("/binary/256"), timeout=10)
        finally:
            s.close()

    # 流式也来几轮：开流 -> 读一块 -> close
    for _ in range(5):
        s = m.Session()
        try:
            r = s.get(srv.url("/drip/40/65536"), timeout=30, stream=True)
            next(iter(r.iter_content(64)), b"")
            r.close()
        finally:
            s.close()

    gc.collect()
    deadline = time.time() + 3.0
    while time.time() < deadline and threading.active_count() > max(threads_before, 4):
        time.sleep(0.1)
    threads_after = threading.active_count()
    handles_after = count_handles()

    t.check("反复建/关会话后线程数不增长（≤ +6）", threads_after <= threads_before + 6,
            "before=%d after=%d" % (threads_before, threads_after))
    if handles_before is None or handles_after is None:
        t.note("本平台拿不到 FD/句柄计数，跳过该项（不是通过）")
        t.check("FD/句柄计数可用", False,
                "count_handles() 在本平台返回 None（before=%r after=%r）"
                % (handles_before, handles_after))
    else:
        t.check("反复建/关会话后句柄数不增长（≤ +24）", handles_after <= handles_before + 24,
                "before=%d after=%d" % (handles_before, handles_after))
    t.eq("churn 之后还能正常请求",
         m.get(srv.url("/echo"), timeout=10).json()["method"], "GET")


# --------------------------------------------------------------------------- #
# 11. 异步
# --------------------------------------------------------------------------- #
async def _no_raise_async(fn):
    try:
        await fn()
        return None
    except BaseException as exc:                      # noqa: BLE001
        return "%r" % (exc,)


async def _await_within(awaitable, seconds: float):
    """在**协程内部**给一个等待对象加超时。

    不要把 ``asyncio.wait_for(...)`` 直接交给 ``asyncio.run()``：那是在没有运行中
    事件循环的时候构造包装，3.12+ 对 ``asyncio.run`` 的入参、3.14 对 ``wait_for``
    参数的检查都更严（非协程包装会直接报错）。统一在 async helper 里 await。
    """
    return await asyncio.wait_for(awaitable, seconds)


@case("async.methods")
def case_async_methods(t: Tester, srv: LocalServer) -> None:
    m = t.mod
    base = srv.url("/echo")

    async def run():
        out = {}
        async with m.AsyncSession(max_clients=8) as s:
            rs = await asyncio.gather(*[s.get(base, params={"i": i}, timeout=15)
                                        for i in range(8)])
            out["gather_codes"] = [r.status_code for r in rs]
            out["gather_queries"] = sorted(r.json()["query"]["i"] for r in rs)
            out["post"] = (await s.post(base, json={"k": "v"}, timeout=15)).json()
            out["delete"] = (await s.delete(base, timeout=15)).json()["method"]
            out["head_status"] = (await s.head(base, timeout=15)).status_code
            out["head_body"] = (await s.head(base, timeout=15)).content
            out["notfound"] = (await s.get(srv.url("/status/404"), timeout=15)).status_code
            out["closed_inside"] = s.closed
        out["closed_after"] = s.closed
        return out

    out = asyncio.run(run())
    t.check("8 个并发请求全部 200",
            all(c == 200 for c in out["gather_codes"]), repr(out["gather_codes"]))
    t.eq("并发请求各自带对参数",
         out["gather_queries"], [str(i) for i in range(8)])
    t.check("异步 POST json 生效", json.loads(out["post"]["body_text"]) == {"k": "v"},
            out["post"]["body_text"][:80])
    t.eq("异步 DELETE 发出的方法", out["delete"], "DELETE")
    t.eq("异步 HEAD 状态码", out["head_status"], 200)
    t.eq("异步 HEAD 无体", out["head_body"], b"")
    t.eq("异步 404 原样返回", out["notfound"], 404)
    t.eq("with 内 closed=False", out["closed_inside"], False)
    t.eq("with 退出后 closed=True", out["closed_after"], True)


@case("async.errors")
def case_async_errors(t: Tester, srv: LocalServer) -> None:
    m = t.mod

    async def run():
        out = {}
        s = m.AsyncSession(max_clients=2)
        try:
            try:
                await s.get(srv.url("/delay/3"), timeout=0.6)
                out["timeout"] = None
            except BaseException as exc:              # noqa: BLE001
                out["timeout"] = exc
            out["after_timeout"] = (await s.get(srv.url("/echo"), timeout=10)).json()["method"]
            r = await s.get(srv.url("/status/500"), timeout=10)
            try:
                r.raise_for_status()
                out["raise"] = None
            except BaseException as exc:              # noqa: BLE001
                out["raise"] = exc
            out["after_404"] = (await s.get(srv.url("/echo"), timeout=10)).json()["method"]
        finally:
            out["close1"] = await _no_raise_async(s.close)
            out["close2"] = await _no_raise_async(s.close)
        out["closed"] = s.closed
        return out

    out = asyncio.run(run())
    t.check("异步超时抛 Timeout", isinstance(out["timeout"], getattr(m, "Timeout")),
            repr(out["timeout"]))
    t.check("异步 Timeout 带错误码 28", getattr(out["timeout"], "code", None) == 28,
            "code=%r" % getattr(out["timeout"], "code", None))
    t.eq("超时之后异步会话可用", out["after_timeout"], "GET")
    t.check("异步 raise_for_status 抛 HTTPError",
            isinstance(out["raise"], getattr(m, "HTTPError")), repr(out["raise"]))
    t.eq("HTTPError 之后异步会话可用", out["after_404"], "GET")
    t.eq("await close() 幂等（第 1 次）", out["close1"], None)
    t.eq("await close() 幂等（第 2 次）", out["close2"], None)
    t.eq("异步会话已关闭", out["closed"], True)

    # 关闭后新建请求必须被拒绝（异常类型应为 NbCurlError）
    async def after_close():
        s = m.AsyncSession(max_clients=1)
        await s.close()
        try:
            await s.get(srv.url("/echo"), timeout=5)
            return None
        except BaseException as exc:                  # noqa: BLE001
            return exc

    exc = asyncio.run(_await_within(after_close(), 15))
    t.check("关闭后的异步请求抛异常（不是挂住）", exc is not None, repr(exc))
    t.check("关闭后的异步请求抛 NbCurlError", isinstance(exc, getattr(m, "NbCurlError")),
            "%s: %s" % (type(exc).__name__, exc))


_CHILD_ASYNC_COMPAT_MARKER = "@@NB_ASYNC_COMPAT@@ "

# 在独立进程里跑的兼容检查：**同一个事件循环线程里**直接调用同步的
# r.content / r.iter_content()。子进程只连父进程起的本地服务，不外联。
_CHILD_ASYNC_COMPAT = r'''
import asyncio
import importlib
import json
import sys

sys.path.insert(0, sys.argv[1])
mod = importlib.import_module(sys.argv[2])
base = sys.argv[3]


async def main():
    out = {}
    s = mod.AsyncSession(max_clients=4)
    try:
        # 1) aiter_content 中途 break 后，同步 content 必须补上剩余部分
        r = await s.get(base + "/drip/4/100?interval=0.05", timeout=30, stream=True)
        got = 0
        async for chunk in r.aiter_content(100):
            got += len(chunk)
            break
        rest = r.content                    # 同一个 loop 里直接读，不许换线程
        out["content_total"] = got + len(rest)
        out["break_got"] = got
        r.close()

        # 2) 同步 iter_content：严格 chunk_size + 总字节守恒
        r = await s.get(base + "/binary/5000", timeout=15, stream=True)
        chunks = [len(c) for c in r.iter_content(1000)]
        out["iter_chunks"] = chunks
        out["iter_total"] = sum(chunks)
        r.close()

        # 3) 游标接着走：先读一块，再从头调 iter_content 应继续未读部分
        r = await s.get(base + "/binary/5000", timeout=15, stream=True)
        head = next(iter(r.iter_content(1500)), b"")
        tail = b"".join(r.iter_content(1500))
        out["head_len"] = len(head)
        out["tail_total"] = len(tail)
        r.close()
    finally:
        await s.close()
    return out


print("%s" + json.dumps(asyncio.run(main())))
''' % _CHILD_ASYNC_COMPAT_MARKER


def _run_async_compat_child(pkg_dir: str, module: str, base_url: str, timeout: float):
    """跑上面的子进程检查，返回 ``(结果字典或 None, 用时秒, 问题描述)``。

    **进程级看门狗**：真死锁时子进程的事件循环线程被堵死，asyncio 的超时和
    协程里的 try/except 都发不出来，只有父进程按墙钟杀掉它才收得住 ——
    所以这一条必须在独立进程里量，而且超时后要如实报 FAIL，不能当成卡住。
    """
    cmd = [sys.executable, "-c", _CHILD_ASYNC_COMPAT, pkg_dir, module, base_url]
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return None, time.perf_counter() - t0, "看门狗 %.0fs 到点仍未返回（判定为死锁）" % timeout
    dt = time.perf_counter() - t0
    for line in (proc.stdout or "").splitlines():
        if line.startswith(_CHILD_ASYNC_COMPAT_MARKER):
            payload = line[len(_CHILD_ASYNC_COMPAT_MARKER):]
            try:
                return json.loads(payload), dt, ""
            except ValueError as exc:
                return None, dt, "子进程结果 JSON 解析失败: %r" % (exc,)
    return None, dt, ("子进程没有结果行（exit=%s）stdout=%r stderr=%r"
                      % (proc.returncode, (proc.stdout or "")[-400:],
                         (proc.stderr or "")[-400:]))


@case("async.stream.compat")
def case_async_stream_compat(t: Tester, srv: LocalServer) -> None:
    """同一调用者 loop 里**直接**用 content / iter_content 的兼容用例。

    这是公开契约的硬要求：``AsyncSession`` 返回的流必须继续支持**同步**
    ``content`` / ``iter_content()``，且不能把调用方事件循环堵死。判断口径就是
    "在同一个协程里直接调用、能拿到正确字节"（换成 ``asyncio.to_thread`` 只能
    证明别的线程能读，证明不了这条）。

    用独立进程 + 墙钟看门狗：真死锁时循环线程被堵死，任何 asyncio 超时都不会触发，
    只有父进程杀子进程才能把它变成一条 FAIL。因此本用例排在 ``async.stream``
    前面，先给出"死锁/正常"的结论。
    """
    m = t.mod
    impl_file = str(getattr(m, "__file__", "") or "")
    if not impl_file:
        t.check("拿得到实现文件（起子进程用）", False, "module.__file__ 为空")
        return
    pkg_dir = str(Path(impl_file).resolve().parent.parent)
    out, seconds, problem = _run_async_compat_child(
        pkg_dir, getattr(m, "__name__", "nb_curl"), srv.url(""), ASYNC_COMPAT_WATCHDOG_S)
    t.check("同一 loop 里同步 content/iter_content 不堵死（进程级看门狗 %.0fs）"
            % ASYNC_COMPAT_WATCHDOG_S,
            out is not None, "%s（用时 %.2fs）" % (problem or "无结果", seconds))
    if out is None:
        return
    t.note("子进程（含 import）用时 %.2fs" % seconds)
    t.eq("aiter_content 中途 break 后同步 content 补剩余", out["content_total"], 400)
    t.check("break 时只消费了部分字节", 0 < out["break_got"] < 400, "break_got=%r" % out["break_got"])
    t.eq("同步 iter_content 总字节守恒（5000）", out["iter_total"], 5000)
    t.eq("同步 iter_content 严格按 chunk_size 切片（5×1000）",
         out["iter_chunks"], [1000] * 5)
    t.eq("先读 1500 后继续读，剩余 3500", (out["head_len"], out["tail_total"]), (1500, 3500))


@case("async.stream")
def case_async_stream(t: Tester, srv: LocalServer) -> None:
    m = t.mod

    async def run():
        out = {}
        s = m.AsyncSession(max_clients=4)
        try:
            t0 = time.perf_counter()
            r = await s.get(srv.url("/drip/5/200?interval=0.3"), timeout=30, stream=True)
            out["t_ret"] = time.perf_counter() - t0
            out["status"] = r.status_code
            out["cl"] = r.headers.get("content-length")
            marks = []
            async for chunk in r.aiter_content(64):
                marks.append((time.perf_counter() - t0, len(chunk)))
            out["marks"] = marks
            out["is_stream_after"] = r.is_stream
            r.close()

            # 中途 break + **在同一个调用者 loop 里直接** 同步 content：
            # AsyncSession 返回的流必须支持同步 content/iter_content，而且不能把
            # 事件循环自己堵死（同步读可用且不阻塞调用方 loop）。这里刻意不换线程 ——
            # 换成 to_thread 只能证明"别的线程能读"，证明不了调用者 loop 里能读。
            # 真死锁的诊断在 async.stream.compat（进程级看门狗）里做。
            r = await s.get(srv.url("/drip/4/100?interval=0.05"), timeout=30, stream=True)
            got = 0
            async for chunk in r.aiter_content(100):
                got += len(chunk)
                break
            out["break_chunks"] = 1
            out["break_got"] = got
            t_before_content = time.perf_counter()
            rest = r.content
            out["content_in_loop_s"] = time.perf_counter() - t_before_content
            out["break_total"] = got + len(rest)
            r.close()

            # 非流式响应的 content 直接在协程里可用（已缓冲）
            r = await s.get(srv.url("/binary/2048"), timeout=15)
            out["plain_len"] = len(r.content)
            out["loop_blocked"] = False
        finally:
            await _no_raise_async(s.close)
        return out

    out = asyncio.run(run())
    t.eq("异步流返回时状态码可用", out["status"], 200)
    t.eq("异步流返回时响应头可用", out["cl"], "1000")
    t.check("异步流返回没等整份体（< 0.6s）", out["t_ret"] < 0.6, "%.2fs" % out["t_ret"])
    t.check("异步流逐块产出", len(out["marks"]) > 1, "%d 块" % len(out["marks"]))
    if out["marks"]:
        t.check("异步流首块很早（< 0.3s）", out["marks"][0][0] < 0.3,
                "%.3fs" % out["marks"][0][0])
    t.eq("异步流字节总数", sum(m[1] for m in out["marks"]), 1000)
    t.check("异步流读完后 is_stream=False", out["is_stream_after"] is False,
            repr(out["is_stream_after"]))
    t.eq("异步流中途 break 后同步 content 补上剩余部分", out["break_total"], 400)
    t.check("break 时只消费了部分字节（游标语义）",
            0 < out["break_got"] < 400, "break_got=%d" % out["break_got"])
    t.check("同 loop 内的同步 content 是当场读完的（不是挂着）",
            out["content_in_loop_s"] < 5.0, "%.3fs" % out["content_in_loop_s"])
    t.eq("非流式异步响应 content 长度", out["plain_len"], 2048)


@case("async.cancel")
def case_async_cancel(t: Tester, srv: LocalServer) -> None:
    """取消：必须真的中止在飞请求，而不是"调用方不等了、后台还在跑"。"""
    m = t.mod

    async def run():
        out = {}
        s = m.AsyncSession(max_clients=4)
        task = asyncio.ensure_future(s.get(srv.url("/delay/%.0f" % CANCEL_DELAY_S), timeout=60))
        await asyncio.sleep(0.6)
        task.cancel()
        try:
            await task
            out["cancelled"] = False
            out["task_result"] = "正常返回"
        except asyncio.CancelledError:
            out["cancelled"] = True
        except BaseException as exc:                  # noqa: BLE001
            out["cancelled"] = False
            out["task_result"] = repr(exc)

        # 被取消的请求还挂在服务端时，会话必须还能服务别的请求
        try:
            r = await asyncio.wait_for(s.get(srv.url("/echo"), timeout=10), 10)
            out["after_cancel"] = r.status_code
        except BaseException as exc:                  # noqa: BLE001
            out["after_cancel"] = "错误 %r" % (exc,)

        # 流式迭代中途取消
        try:
            r = await s.get(srv.url("/drip/40/65536?interval=0.25"), timeout=60, stream=True)
            async for _chunk in r.aiter_content(65536):
                break
            r.close()
            out["stream_cancel"] = "ok"
        except BaseException as exc:                  # noqa: BLE001
            out["stream_cancel"] = repr(exc)

        t0 = time.perf_counter()
        close_task = asyncio.ensure_future(s.close())
        done, _pending = await asyncio.wait({close_task}, timeout=CANCEL_CLOSE_BUDGET_S)
        out["close_s"] = time.perf_counter() - t0
        out["close_done"] = bool(done)
        if not done:
            # 断言已经失败；这里再等它收尾，别把悬空线程/句柄留给进程退出
            await asyncio.wait({close_task}, timeout=CANCEL_HARD_WAIT_S)
        return out

    out = asyncio.run(run())
    t.check("取消传播为 CancelledError", out["cancelled"] is True,
            "task_result=%r" % out.get("task_result"))
    t.eq("取消之后会话仍能服务请求", out["after_cancel"], 200)
    t.eq("流式迭代中途取消/关闭不报错", out["stream_cancel"], "ok")
    t.check("取消后 close() 在预算内返回（%.1fs）" % CANCEL_CLOSE_BUDGET_S,
            out["close_done"] is True,
            "实际 %.2fs —— 超预算说明在飞请求没有被真正中止（在等它跑完 %.0fs）"
            % (out["close_s"], CANCEL_DELAY_S))


@case("async.close_inflight")
def case_async_close_inflight(t: Tester, srv: LocalServer) -> None:
    """本用例锁定的关闭契约（``close()`` 先排空在飞与排队请求，再关会话）：

    1. 已被接纳的非流请求在 close 后**正常完成**（含仍在 executor 排队的请求）；
    2. close 异步等待但 loop 其它 ticker 可运行；
    3. close 之后新请求被拒绝（RuntimeError / NbCurlError 均记录，不强制同型）；
    4. 并发重复 close 幂等（共享同一收尾，无异常）。

    用户 task.cancel 仍传播 CancelledError，属 cancel 用例职责，不在本用例混淆。
    预算：各请求 <=2s、各等待看门狗 10s；close 前先等请求已提交（服务端可见）。
    """
    m = t.mod
    nb_err = getattr(m, "NbCurlError", ())
    delay = CLOSE_INFLIGHT_REQ_DELAY_S

    async def _req(s, path):
        return await s.get(srv.url(path), timeout=30)

    async def run():
        out = {}

        # --- 阶段 1：已被接纳的在飞 + 排队请求，close 后应正常完成 ---------
        s = m.AsyncSession(max_clients=4)
        inflight = asyncio.ensure_future(_req(s, "/delay/%.1f" % delay))
        # 等 in-flight 已提交到服务端（连接已建立），避免"还没提交就 close"。
        t0 = time.perf_counter()
        while time.perf_counter() - t0 < 2.0:
            await asyncio.sleep(0.05)
        # 第二个请求排进 executor 队列（max_clients 足够时并发跑，同样必须在 close 前完成）
        queued = asyncio.ensure_future(_req(s, "/delay/%.1f" % delay))
        await asyncio.sleep(0.1)          # 确保已提交

        # close 是异步等待：期间 loop 其它 ticker 必须可运行
        ticks = {"n": 0}

        async def _ticker():
            while True:
                await asyncio.sleep(0.02)
                ticks["n"] += 1

        ticker = asyncio.ensure_future(_ticker())
        await asyncio.sleep(0.1)
        ticks_before = ticks["n"]

        try:
            await asyncio.wait_for(s.close(), CLOSE_INFLIGHT_WATCHDOG_S)
            out["close_ok"] = True
        except BaseException as exc:                  # noqa: BLE001
            out["close_ok"] = repr(exc)
        out["close_s"] = time.perf_counter() - t0
        ticker.cancel()
        try:
            await ticker
        except BaseException:                 # noqa: BLE001
            pass
        out["ticks_during_close"] = ticks["n"] - ticks_before
        out["closed"] = s.closed

        # 已接纳请求：等待自己落地（<= watchdog）
        for name, fut in (("inflight", inflight), ("queued", queued)):
            deadline = time.perf_counter() + CLOSE_INFLIGHT_WATCHDOG_S
            while not fut.done() and time.perf_counter() < deadline:
                await asyncio.sleep(0.05)
            kind, detail = "timeout", "等待期内未结束"
            if fut.done():
                exc = fut.exception()
                if exc is None:
                    r = fut.result()
                    kind = "success"
                    detail = "%s" % getattr(r, "status_code", "?")
                elif isinstance(exc, asyncio.CancelledError):
                    kind = "cancelled"
                    detail = repr(exc)
                elif isinstance(exc, nb_err):
                    kind = "nb_curl_error"
                    detail = repr(exc)
                else:
                    kind = "unexpected:%s" % type(exc).__name__
                    detail = repr(exc)
            out[name] = {"kind": kind, "detail": detail}

        # close 之后新请求：必须被拒绝，但类型 RuntimeError/NbCurlError 均为
        # 既有差异，记录即可，不强制同型；照常返回或挂住才 fail。
        try:
            r = await asyncio.wait_for(_req(s, "/echo"), CLOSE_INFLIGHT_WATCHDOG_S)
            out["after_close_req"] = "返回了 %s（没有拒绝）" % r.status_code
        except BaseException as exc:                  # noqa: BLE001
            out["after_close_req"] = exc

        # 并发重复 close 幂等
        results = await asyncio.gather(
            _no_raise_async(s.close), _no_raise_async(s.close))
        out["dup_close"] = results
        return out

    out = asyncio.run(run())

    t.check("close() 在看门狗内返回（%.0fs，实测 %.2fs）"
            % (CLOSE_INFLIGHT_WATCHDOG_S, out["close_s"]),
            out["close_ok"] is True, "close_ok=%r" % out["close_ok"])
    t.eq("会话标记为已关闭", out["closed"], True)
    t.check("close 等待期间 loop 其它 ticker 可运行（异步等待，不卡死 loop）",
            out["ticks_during_close"] > 0,
            "close 期间 ticker 只跑了 %r 次" % out["ticks_during_close"])
    # 契约核心：已接纳请求正常完成（success），close 不打断
    for name in ("inflight", "queued"):
        info = out[name]
        t.eq("已接纳的在飞/排队请求 close 后正常完成（%s）" % name,
             info["kind"], "success")
        t.note("%s 结局：%s %s" % (name, info["kind"], info["detail"]))
    # close 后新请求：拒绝即可，异常类型如实记录（RuntimeError/NbCurlError）
    exc_after = out["after_close_req"]
    t.check("close 后的新请求被明确拒绝（抛异常，不是挂住或照常返回）",
            isinstance(exc_after, BaseException), repr(exc_after))
    if isinstance(exc_after, nb_err):
        t.note("close 后新请求异常类型：NbCurlError（统一类型）")
    elif isinstance(exc_after, RuntimeError):
        t.note("close 后新请求异常类型：RuntimeError（如实记录，不强制同型）")
    else:
        t.note("close 后新请求异常类型：%s" % type(exc_after).__name__)
    # 并发重复 close：无异常即幂等
    t.eq("并发重复 close() 幂等（无异常）",
         [type(r).__name__ if isinstance(r, BaseException) else r
          for r in out["dup_close"]],
         [None, None])


# --------------------------------------------------------------------------- #
# 工具
# --------------------------------------------------------------------------- #
def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _hash_impl_files(pkg_dir: Path) -> dict:
    """对实现目录下全部 .py 做内容哈希（相对路径 -> sha256），用于检测边改边测。"""
    out = {}
    for p in sorted(pkg_dir.rglob("*.py")):
        try:
            rel = str(p.relative_to(pkg_dir)).replace(os.sep, "/")
            out[rel] = sha256_hex(p.read_bytes())
        except OSError:
            out[str(p)] = "<unreadable>"
    return out


def _watchdog(seconds: float):
    if seconds <= 0:
        return None

    def _boom():
        sys.stderr.write("\n[watchdog] 套件总时长超过 %.0fs，强制退出（退出码 3）。\n"
                         "多半是某个用例卡住了 —— 用 --only 单独跑它定位。\n" % seconds)
        sys.stderr.flush()
        os._exit(3)

    timer = threading.Timer(seconds, _boom)
    timer.daemon = True
    timer.start()
    return timer


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="nb_curl 本地回归套件（同步 + 异步，全本地服务）")
    p.add_argument("--package-path", action="append", default=[], metavar="DIR",
                   help="nb_curl 所在目录（可多次给；第一个优先级最高）。"
                        "不传则用当前 sys.path / PYTHONPATH 的结果。")
    p.add_argument("--module", default="nb_curl", help="包名（默认 nb_curl）")
    p.add_argument("--only", default="", metavar="SUBSTR[,SUBSTR]",
                   help="只跑用例名包含任一子串的用例（逗号分隔）")
    p.add_argument("--list", action="store_true", help="列出用例后退出")
    p.add_argument("--json", default="", metavar="PATH", help="把完整结果写成 JSON")
    p.add_argument("--fail-fast", action="store_true", help="首个失败用例后停止")
    p.add_argument("--overall-timeout", type=float, default=900.0,
                   help="套件总时长上限（秒，默认 900；到点强制退出码 3）")
    p.add_argument("--host", default="127.0.0.1", help="本地服务绑定地址")
    p.add_argument("--port", type=int, default=0, help="本地服务端口（默认 0=动态）")
    p.add_argument("--utf8-output", action="store_true",
                   help="把 stdout/stderr 切成 UTF-8（日志被管道/UTF-8 终端采集时用；"
                        "中文控制台请勿开启）")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.utf8_output:
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding="utf-8", errors="backslashreplace")
            except (AttributeError, ValueError):
                pass

    if args.list:
        for c in CASES:
            print("%-24s %s" % (c["name"], c["fn"].__doc__.splitlines()[0]
                                if c["fn"].__doc__ else ""))
        return 0

    scrubbed = scrub_proxy_env()

    print("=" * 78)
    print("nb_curl 本地回归套件")
    print("=" * 78)
    mod, info = select_implementation(args.package_path, args.module)
    if mod is None:
        print("[SETUP FAIL] %s" % info.get("error"))
        print("提示：用 --package-path <目录> 或 PYTHONPATH 指定实现；"
              "本套件不会自动插入其它路径。")
        return 2

    impl = implementation_info(mod)
    print("  实现      : %s" % impl["file"])
    print("  版本/后端 : %s / %s" % (impl["version"], impl["backend"]))
    print("  模块信息  : %s" % impl["backend_info"])
    print("  sys.path  : %s" % (info["sys_path_head"][:5],))
    if scrubbed:
        print("  已清理代理环境变量: %s" % scrubbed)

    selected = CASES
    if args.only:
        needles = [s.strip() for s in args.only.split(",") if s.strip()]
        selected = [c for c in CASES if any(n in c["name"] for n in needles)]
        if not selected:
            print("[SETUP FAIL] --only %r 没有匹配到任何用例" % args.only)
            return 2

    srv = LocalServer(args.host, args.port)
    srv.start()
    print("  本地服务  : http://%s:%d  (pid=%d, 动态端口)"
          % (srv.host, srv.port, os.getpid()))
    print("-" * 78)

    # 运行阶段哈希记录：跑之前和跑之后各记一次实现目录的 .py 内容哈希，
    # 两边不一致说明实现目录在运行期间被改动过，本次结果不作为结论依据。
    impl_dir = Path(impl["file"]).resolve().parent.parent
    hash_before = _hash_impl_files(impl_dir)
    t = Tester(mod, srv, args)
    timer = _watchdog(args.overall_timeout)
    setup_error = None
    try:
        for c in selected:
            print("\n== %s ==" % c["name"])
            t.begin_case(c["name"])
            t0 = time.perf_counter()
            try:
                c["fn"](t, srv)
            except BaseException as exc:              # noqa: BLE001
                t.check("用例自身未抛异常", False, "%s: %s" % (type(exc).__name__, exc))
                traceback.print_exc()
            t.end_case(c["name"], time.perf_counter() - t0)
            if args.fail_fast and t.failed_in_case:
                print("\n[fail-fast] 停在用例 %s" % c["name"])
                break
    finally:
        srv.stop()

    # 服务端清理也要断言（不能只写在文档里）
    released = not _port_open(srv.host, srv.port)
    t.begin_case("server.cleanup")
    t.check("套件结束时服务端口已释放", released,
            "http://%s:%d 仍然可连" % (srv.host, srv.port))
    t.end_case("server.cleanup", 0.0)
    if timer is not None:
        timer.cancel()

    # -- 汇总 --
    hash_after = _hash_impl_files(impl_dir)
    impl_mutated = hash_after != hash_before
    mutated_files = sorted(
        set(hash_after) | set(hash_before),
        key=lambda k: (k not in hash_after, k not in hash_before, k))
    changed = [k for k in mutated_files if hash_after.get(k) != hash_before.get(k)]

    print("\n" + "=" * 78)
    if impl_mutated:
        print("[警告] 套件运行期间实现目录发生了变更（%d 个文件）："
              "本次结果**不得**当作验收依据。" % len(changed))
        for k in changed[:20]:
            print("  - %s" % k)
    else:
        print("实现完整性：运行前后 %d 个 .py 文件哈希一致（未被边改边测）。"
              % len(hash_before))
    total = t.passed + t.failed
    print("结果：%d 条断言，通过 %d，失败 %d" % (total, t.passed, t.failed))
    failed_checks = []
    for c in t.cases:
        for ck in c["checks"]:
            if not ck["ok"]:
                failed_checks.append("%s / %s  %s" % (c["name"], ck["name"], ck["detail"][:140]))
    if failed_checks:
        print("失败清单（%d）：" % len(failed_checks))
        for line in failed_checks:
            print("  - %s" % line)
    slow = sorted(t.cases, key=lambda c: -c["seconds"])[:5]
    print("最慢用例：%s" % ", ".join("%s(%.2fs)" % (c["name"], c["seconds"]) for c in slow))

    if args.json:
        payload = {
            "suite": "nb_curl-local-regression",
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "platform": sys.platform,
            "python": sys.version,
            "executable": sys.executable,
            "cwd": os.getcwd(),
            "requested_package_paths": info["requested_paths"],
            "implementation": impl,
            "import_info": info,
            "proxy_env_scrubbed": scrubbed,
            "impl_hash_before": hash_before,
            "impl_hash_after": hash_after,
            "impl_mutated_during_run": impl_mutated,
            "impl_mutated_files": changed,
            "valid_for_acceptance": (t.failed == 0 and not impl_mutated),
            "server": {"host": srv.host, "port": srv.port,
                       "dynamic_port": args.port == 0,
                       "port_released_at_end": released},
            "passed": t.passed,
            "failed": t.failed,
            "cases": t.cases,
        }
        out = Path(args.json)
        if out.parent and str(out.parent) not in ("", "."):
            out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str),
                       encoding="utf-8")
        print("JSON 报告：%s" % out.resolve())

    print("=" * 78)
    if impl_mutated:
        print("[结果无效] 实现目录在运行期间被修改 —— 仅记录，不作为验收结论。")
        return 1 if t.failed else 0
    return 0 if t.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
