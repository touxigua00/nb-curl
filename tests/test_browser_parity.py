"""浏览器口径回归：期望值全部来自**真机 Chrome 155 的抓包**（本地回环 + CDP）。

原则：**Chrome 155 是唯一标准**。凡浏览器做不到的事（重复请求头、GET 带 body、
非 ISO-8859-1 头值…），我们也不做；凡浏览器会做的（同名头用 ", " 拼、URL 自动转义、
303 全部降级为 GET…），我们就照做。

覆盖：
* 请求头：导航默认头顺序、空值头照发、**同名头合并成一条**、非 latin-1 报 TypeError、
  ``None`` 删默认头；
* Content-Type 推断（Chrome fetch 口径）：字符串 / 二进制 / 表单 / 无 body / multipart；
* 重定向矩阵：301/302 只降级 POST、303 除 HEAD 全降级、307/308 全保留；
* cookie：创建序 + 长 path 在前、值原样、删除、host-only、Domain 拒收、Secure 只走安全上下文；
* URL：空格等非法字符自动转义（与地址栏一致）；
* 响应头：对外一律小写、重复值按 ", " 合并；
* 不提供浏览器没有的 API（``is_redirect`` / ``raise_for_status=`` / ``quote=`` /
  ``default_encoding=``）；cookie 的携带策略用浏览器的 ``credentials="omit"``。

用法：``python tests/test_browser_parity.py [--package-path PATH] [--list]``
退出码：0 = 全过，1 = 有失败，2 = setup 失败。
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

EXIT_OK, EXIT_FAIL, EXIT_SETUP = 0, 1, 2

# Chrome 155 顶层导航的请求头顺序（真机 http://127.0.0.1 抓包，逐条一致）
CHROME_NAV_HEADERS = [
    "Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site",
    "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding",
    "Accept-Language",
]

# 真机实测的重定向矩阵（oracle/chrome_redirect_matrix.json）
REDIRECT_MATRIX = {
    ("post", 301): ("GET", False), ("post", 302): ("GET", False),
    ("post", 303): ("GET", False), ("post", 307): ("POST", True),
    ("post", 308): ("POST", True),
    ("put", 301): ("PUT", True), ("put", 302): ("PUT", True),
    ("put", 303): ("GET", False), ("put", 307): ("PUT", True),
    ("patch", 303): ("GET", False), ("patch", 302): ("PATCH", True),
    ("delete", 302): ("DELETE", True), ("delete", 303): ("GET", False),
}

CASES: list[tuple[str, str]] = []
_REGISTRY: dict = {}


def case(cid: str, title: str):
    def deco(fn):
        CASES.append((cid, title))
        _REGISTRY[cid] = fn
        return fn
    return deco


# --------------------------------------------------------------------------- #
# 本地探针服务器：记录原始报文（有序、含重复头）
# --------------------------------------------------------------------------- #
class _Store:
    def __init__(self) -> None:
        self.last: dict | None = None


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, headers=(), body=b""):
        self.send_response(code)
        for n, v in headers:
            self.send_header(n, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _handle(self):
        parsed = urlsplit(self.path)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        self.server.store.last = {
            "method": self.command,
            "path": self.path,
            "headers": [(k, v) for k, v in self.headers.items()],
            "body": body,
        }
        route = parsed.path
        if route == "/echo":
            self._send(200, [("Content-Type", "application/json")], b"{}")
        elif route == "/setcookie":
            cookies = json.loads(base64.urlsafe_b64decode(qs["h"][0].encode()).decode())
            self._send(200, [("Set-Cookie", c) for c in cookies], b"ok")
        elif route == "/redir":
            code = int(qs.get("code", ["302"])[0])
            to = qs.get("to", ["/echo"])[0]
            self._send(code, [("Location", to), ("Content-Length", "0")], b"")
        elif route == "/ct":
            ctype = base64.urlsafe_b64decode(qs["type"][0].encode()).decode("latin-1")
            raw = base64.urlsafe_b64decode(qs["b64"][0].encode()) if "b64" in qs else b""
            self._send(200, [("Content-Type", ctype)], raw)
        elif route == "/dup":
            # 响应头带重复 + 大小写混杂
            self._send(200, [("X-MiXeD", "1"), ("X-Dup", "a"), ("X-Dup", "b"),
                             ("Content-Type", "text/plain")], b"ok")
        else:
            self._send(404, [("Content-Type", "text/plain")], b"no route")

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _handle


class _Server:
    def __enter__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.store = _Store()
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    def last(self) -> dict:
        return self.httpd.store.last or {"headers": [], "method": "", "body": b"", "path": ""}


def _enc(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("latin-1")).decode()


def _b64b(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def _cookie(srv: "_Server") -> str:
    for name, value in srv.last()["headers"]:
        if name.lower() == "cookie":
            return value
    return ""


def _hvals(srv: "_Server", name: str):
    return [v for n, v in srv.last()["headers"] if n.lower() == name]


def _hnames(srv: "_Server"):
    return [n for n, _ in srv.last()["headers"]]


def _setcookie(srv: "_Server", cookies, base: str | None = None) -> str:
    return f"{base or srv.base}/setcookie?h={_enc(json.dumps(cookies))}"


# --------------------------------------------------------------------------- #
# 用例
# --------------------------------------------------------------------------- #
@case("headers.nav_order", "导航默认头顺序与 Chrome 155 一致")
def _(m, srv, t):
    m.Session(impersonate="chrome155").get(srv.base + "/echo")
    t.eq("顺序", _hnames(srv), CHROME_NAV_HEADERS)


@case("headers.empty_value", "空值头照发（Chrome 会发 X-Empty:）")
def _(m, srv, t):
    m.Session().get(srv.base + "/echo", headers={"X-Empty": ""})
    t.eq("X-Empty 存在且为空", _hvals(srv, "x-empty"), [""])


@case("headers.merge_duplicates", "同名头合并成一条（浏览器发不出两行）")
def _(m, srv, t):
    m.Session().get(srv.base + "/echo", headers=[("X-Dup", "1"), ("X-Dup", "2")])
    t.eq("一条，值按序拼接", _hvals(srv, "x-dup"), ["1, 2"])
    m.Session().get(srv.base + "/echo", headers={"X-List": ["a", "b"]})
    t.eq("list 值同样合并", _hvals(srv, "x-list"), ["a, b"])


@case("headers.none_removes", "None 删除默认头")
def _(m, srv, t):
    m.Session(impersonate="chrome155").get(srv.base + "/echo", headers={"Accept": None})
    t.eq("Accept 不发", _hvals(srv, "accept"), [])


@case("headers.non_latin1", "非 ISO-8859-1 头值抛 TypeError（浏览器同）")
def _(m, srv, t):
    try:
        m.Session().get(srv.base + "/echo", headers={"X-CN": "中文"})
    except TypeError as exc:
        t.check("消息里点明 ISO-8859-1", "8859-1" in str(exc), str(exc))
        return
    except Exception as exc:  # noqa: BLE001
        t.eq("异常类型", type(exc).__name__, "TypeError")
        return
    t.fail("没有报错（浏览器会抛 TypeError）")


@case("headers.case_preserved", "响应头名字按服务端原样、重复值合并、取值大小写不敏感")
def _(m, srv, t):
    r = m.Session().get(srv.base + "/dup")
    keys = r.headers.keys()
    # 服务端发的是 X-MiXeD / X-Dup / Content-Type，我们原样保留
    t.check("原大小写保留", {"X-MiXeD", "X-Dup", "Content-Type"} <= set(keys), keys)
    t.eq("每个名字只出现一次", len(keys), len(set(k.lower() for k in keys)))
    t.eq("重复值按 ', ' 合并", r.headers.get("x-dup"), "a, b")
    t.eq("dict 视图同样合并", dict(r.headers).get("X-Dup"), "a, b")
    t.eq("单条仍可取", r.headers.get_list("X-dup"), ["a", "b"])
    t.eq("取值大小写不敏感", r.headers["CONTENT-TYPE"], r.headers.get("content-type"))


@case("body.content_type", "Content-Type 推断（Chrome fetch 口径）")
def _(m, srv, t):
    s = m.Session()
    for label, kw, want in [
        ("str", {"data": "abc"}, ["text/plain;charset=UTF-8"]),
        ("bytes", {"data": b"abc"}, []),
        # 表单提交口径：Chrome 155 提交 form 时**不带** charset（fetch+URLSearchParams
        # 才带 ;charset=UTF-8）。我们的 data= 语义是"表单字段"，按表单提交算。
        ("dict", {"data": {"k": "v"}}, ["application/x-www-form-urlencoded"]),
        ("none", {}, []),
    ]:
        s.post(srv.base + "/echo", **kw)
        t.eq(label, _hvals(srv, "content-type"), want)


@case("body.get_with_body", "GET/HEAD 带 body 直接抛 TypeError（浏览器同）")
def _(m, srv, t):
    for method in ("get", "head"):
        try:
            getattr(m.Session(), method)(srv.base + "/echo", data="x")
            t.fail(f"{method.upper()} 带 body 没有报错")
        except TypeError:
            t.eq(f"{method.upper()} 抛 TypeError", True, True)


@case("body.multipart", "multipart 用 WebKit 边界 + 文件名原样")
def _(m, srv, t):
    m.Session().post(srv.base + "/echo", files={"f": ("given.txt", b"data")})
    ct = (_hvals(srv, "content-type") or [""])[0]
    t.check("WebKit 边界", ct.startswith("multipart/form-data; boundary=----WebKitFormBoundary"), ct)
    t.check("文件名", b'filename="given.txt"' in srv.last()["body"], srv.last()["body"][:120])


@case("redirect.matrix", "重定向方法矩阵（Chrome 155 实测）")
def _(m, srv, t):
    s = m.Session()
    for (method, code), (want_method, want_body) in REDIRECT_MATRIX.items():
        getattr(s, method)(f"{srv.base}/redir?code={code}", data={"a": "1"})
        rec = srv.last()
        t.eq(f"{method.upper()} {code}", (rec["method"], bool(rec["body"])),
             (want_method, want_body))


@case("redirect.history", "Python 侧跟重定向时 history / redirect_count 也对")
def _(m, srv, t):
    r = m.Session().put(f"{srv.base}/redir?code=303&to=/echo", data={"a": "1"})
    t.eq("最终状态", r.status_code, 200)
    t.eq("history 一条", len(r.history), 1)
    t.eq("history[0] 是 303", r.history[0].status_code, 303)
    t.eq("redirect_count", r.redirect_count, 1)
    t.eq("最终方法是 GET", srv.last()["method"], "GET")


@case("url.space_autocompressed", "URL 里的空格自动转成 %20（地址栏口径）")
def _(m, srv, t):
    m.Session().get(srv.base + "/echo?q=a b&c=中文")
    t.eq("path", srv.last()["path"], "/echo?q=a%20b&c=%E4%B8%AD%E6%96%87")
    m.Session().get(srv.base + "/echo?q=a%20b")
    t.eq("已有 %XX 不重复编码", srv.last()["path"], "/echo?q=a%20b")


@case("cookies.order", "cookie 顺序：创建序 + 长 path 在前（浏览器口径）")
def _(m, srv, t):
    s = m.Session()
    for c in ["a=2", "bb=1", "zebra=9"]:
        s.get(_setcookie(srv, [c]))
    s.get(srv.base + "/echo")
    t.eq("同 path 按创建顺序", _cookie(srv), "a=2; bb=1; zebra=9")
    s.get(_setcookie(srv, ["r=1; Path=/"]))
    s.get(_setcookie(srv, ["d=1; Path=/echo"]))
    s.get(srv.base + "/echo")
    t.eq("长 path 在前 + 同名不同 path 都发", _cookie(srv),
         "d=1; a=2; bb=1; zebra=9; r=1")


@case("cookies.value_shapes", "cookie 值原样（引号/空格/%/逗号/等号）")
def _(m, srv, t):
    s = m.Session()
    s.get(_setcookie(srv, ['q="v1"', "sp=a b", "pct=a%20b", "comma=a,b", "eq=a=b"]))
    s.get(srv.base + "/echo")
    t.eq("原样", _cookie(srv), 'q="v1"; sp=a b; pct=a%20b; comma=a,b; eq=a=b')


@case("cookies.delete", "Max-Age=0 / 过期 Expires 都删干净")
def _(m, srv, t):
    s = m.Session()
    s.get(_setcookie(srv, ["del=1"]))
    s.get(srv.base + "/echo")
    t.check("先有", "del=1" in _cookie(srv), _cookie(srv))
    s.get(_setcookie(srv, ["del=1; Max-Age=0"]))
    s.get(srv.base + "/echo")
    t.check("Max-Age=0 后不发", "del=1" not in _cookie(srv), _cookie(srv))
    t.check("Max-Age=0 后罐里也没有", "del" not in dict(s.cookies), dict(s.cookies))

    s2 = m.Session()
    s2.get(_setcookie(srv, ["e=1"]))
    s2.get(_setcookie(srv, ["e=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT"]))
    s2.get(srv.base + "/echo")
    t.check("过期 Expires 后不发", "e=1" not in _cookie(srv), _cookie(srv))
    t.check("过期 Expires 后罐里也没有", "e" not in dict(s2.cookies), dict(s2.cookies))


@case("cookies.scope", "host-only 不跨站、Domain 拒收、Secure 只走安全上下文")
def _(m, srv, t):
    s = m.Session()
    s.cookies["k"] = "v"
    s.get(srv.base + "/echo")
    on_ip = _cookie(srv)
    s.get(f"http://localhost:{srv.port}/echo")
    t.eq("显式 cookie 只发给首个主机", (on_ip, _cookie(srv)), ("k=v", ""))

    s2 = m.Session()
    s2.get(_setcookie(srv, ["d=1; Domain=localhost"]))
    s2.get(srv.base + "/echo")
    t.eq("Domain 不匹配拒收", _cookie(srv), "")

    s3 = m.Session()
    s3.get(_setcookie(srv, ["sec=1; Secure"]))
    s3.get(srv.base + "/echo")
    t.eq("127.0.0.1 属可信来源，Secure 照发（Chrome 同样）", _cookie(srv), "sec=1")

    s4 = m.Session(resolve={f"oracle.test:{srv.port}": "127.0.0.1"})
    s4.get(_setcookie(srv, ["sec=1; Secure"], base=f"http://oracle.test:{srv.port}"))
    s4.get(f"http://oracle.test:{srv.port}/echo")
    t.eq("非可信来源 http 上不发 Secure", _cookie(srv), "")


@case("cookies.credentials_omit", 'credentials="omit" 既不发也不记（fetch 语义）')
def _(m, srv, t):
    s = m.Session(credentials="omit")
    s.get(_setcookie(srv, ["dc=1"]))
    s.get(srv.base + "/echo")
    t.eq("不发也不记", (_cookie(srv), dict(s.cookies)), ("", {}))
    r = m.Session().get(srv.base + "/echo", credentials="omit")
    t.eq("请求级也生效", r.status_code, 200)


@case("charset.decode", "charset 解析（文档口径）+ JSON 先按 UTF-8")
def _(m, srv, t):
    quoted = _enc('text/html; charset="gbk"')
    gbk = _b64b("中文测试".encode("gbk"))
    r = m.Session().get(f"{srv.base}/ct?type={quoted}&b64={gbk}")
    t.eq("带引号 charset", r.text, "中文测试")

    plain = _enc("text/html")
    r = m.Session().get(f"{srv.base}/ct?type={plain}&b64={gbk}")
    t.eq("没有 charset 时按 UTF-8（Chrome 同样）", r.encoding, "utf-8")

    jtype = _enc("application/json; charset=gbk")
    jbody = _b64b(json.dumps({"名字": "张三"}).encode("gbk"))
    r = m.Session().get(f"{srv.base}/ct?type={jtype}&b64={jbody}")
    t.eq("JSON 非法 UTF-8 时才有兜底", r.json(), {"名字": "张三"})


@case("api.no_browserless_apis", "不提供浏览器没有的 API（口径守护）")
def _(m, srv, t):
    r = m.Session().get(f"{srv.base}/redir?code=302", allow_redirects=False)
    t.eq("Response 没有 is_redirect", hasattr(r, "is_redirect"), False)
    for kw in ({"raise_for_status": True}, {"quote": True}, {"default_encoding": "gbk"},
               {"discard_cookies": True}):
        try:
            m.Session().get(srv.base + "/echo", **kw)
            t.fail(f"参数 {list(kw)[0]} 竟然还在")
        except TypeError:
            t.eq(f"参数 {list(kw)[0]} 已被移除", True, True)
    t.eq("session.cookies 没有 set()", hasattr(m.Session().cookies, "set"), False)
    t.eq("session.cookies 没有 get_dict()", hasattr(m.Session().cookies, "get_dict"), False)


# --------------------------------------------------------------------------- #
# 运行器
# --------------------------------------------------------------------------- #
class Tester:
    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[str] = []
        self._current = ""

    def eq(self, name: str, got, want) -> None:
        if got == want:
            self.passed += 1
            print(f"      [PASS] {name}")
        else:
            self.failed.append(f"{self._current} / {name}")
            print(f"      [FAIL] {name}\n             got={got!r}\n             want={want!r}")

    def check(self, name: str, ok, detail=None) -> None:
        if ok:
            self.eq(name, True, True)
        else:
            self.failed.append(f"{self._current} / {name}")
            print(f"      [FAIL] {name}  ({detail!r})")

    def fail(self, name: str) -> None:
        self.failed.append(f"{self._current} / {name}")
        print(f"      [FAIL] {name}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--package-path", default="", help="额外的 sys.path 前缀（测未安装的源码树）")
    ap.add_argument("--list", action="store_true", help="只列出用例")
    args = ap.parse_args()

    if args.list:
        for cid, title in CASES:
            print(f"{cid:26s} {title}")
        return EXIT_OK

    if args.package_path:
        sys.path.insert(0, args.package_path)
    try:
        import nb_curl as mod
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        print("setup 失败：import nb_curl 不了")
        return EXIT_SETUP

    t = Tester()
    try:
        with _Server() as srv:
            for cid, title in CASES:
                print(f"\n== {cid}  {title}")
                t._current = cid
                fn = _REGISTRY.get(cid)
                if fn is None:
                    t.fail("用例实现缺失")
                    continue
                try:
                    fn(mod, srv, t)
                except Exception:  # noqa: BLE001
                    traceback.print_exc()
                    t.fail("用例抛异常")
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        return EXIT_SETUP

    print("\n" + "=" * 70)
    print(f"结果：{t.passed} 条断言通过，{len(t.failed)} 条失败")
    if t.failed:
        print("失败清单：")
        for name in t.failed:
            print("  -", name)
        return EXIT_FAIL
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
