# -*- coding: utf-8 -*-
"""stream=True 响应元信息（meta）回归套件。

只对照**本仓库 nb_curl 的实际行为**，不从 requests 搬语义：

* 同一 Session 上 stream=True 读完后，Set-Cookie 的会话罐 / 后续请求 cookie 发送；
* 头就绪时 vs 完成后 ``Response.url / history / status / headers / elapsed /
  http_version`` 的契约口径（elapsed 只对比"非负 timedelta"，数值不要求相等）；
* HEAD / 204 无响应体不挂起、1xx 之后最终头可用；
* 重定向最终 ``url`` / ``history``；
* 完成后 ``raw_cookie_list``（流式实测为空 —— 如实记录，不强行断言非空）。

用法（在仓库根目录执行）::

    python tests/test_stream_metadata.py --package-path . \
        --backend cffi --json stream-metadata.json
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
import threading
import time
import traceback
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from local_server import LocalServer  # noqa: E402


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="stream metadata regression")
    p.add_argument("--package-path", required=True)
    p.add_argument("--backend", default="", choices=["", "cffi", "ctypes"])
    p.add_argument("--json", default="")
    p.add_argument("--timeout", type=float, default=120.0)
    return p.parse_args(argv)


class _T:
    """超薄断言收集器：一条不中断，结束时统一汇报。"""

    def __init__(self):
        self.checks = []
        self.failed = 0
        self.passed = 0
        self.notes = []

    def check(self, name, ok, detail=""):
        ok = bool(ok)
        self.checks.append({"name": name, "ok": ok, "detail": str(detail)[:300]})
        if ok:
            self.passed += 1
        else:
            self.failed += 1
        print("  [%s] %s  %s" % ("PASS" if ok else "FAIL", name, "" if ok else detail))
        return ok

    def eq(self, name, got, want):
        return self.check(name, got == want, "got=%r want=%r" % (got, want))

    def note(self, msg):
        self.notes.append(str(msg))
        print("  [info] %s" % msg)


def main(argv=None) -> int:
    args = parse_args(argv)
    if os.name == "nt":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if args.backend:
        os.environ["NB_CURL_BACKEND"] = args.backend
    sys.path.insert(0, str(Path(args.package_path).resolve()))
    mod = importlib.import_module("nb_curl")

    t = _T()
    t.note("impl=%s version=%s backend=%s" % (mod.__file__, mod.__version__, mod.backend_name()))
    deadline = time.monotonic() + args.timeout
    _stop = threading.Event()

    def _watchdog():
        _stop.wait(max(1.0, deadline - time.monotonic()))
        if not _stop.is_set():
            print("[watchdog] 套件总时长超过 %.0fs，强制退出(3)" % args.timeout)
            os._exit(3)

    threading.Thread(target=_watchdog, daemon=True).start()

    srv = LocalServer()
    srv.start()
    try:
        _run(mod, srv, t)
    except BaseException as exc:  # noqa: BLE001
        t.check("套件自身未抛异常", False, "%s: %s" % (type(exc).__name__, exc))
        traceback.print_exc()
    finally:
        srv.stop()
        _stop.set()

    total = t.passed + t.failed
    print("=" * 70)
    print("结果：%d 条，通过 %d，失败 %d" % (total, t.passed, t.failed))
    if t.failed:
        for c in t.checks:
            if not c["ok"]:
                print("  - %s  %s" % (c["name"], c["detail"][:160]))

    if args.json:
        payload = {
            "suite": "stream-metadata",
            "package_path": args.package_path,
            "backend": mod.backend_name(),
            "impl_file": str(mod.__file__),
            "version": mod.__version__,
            "python": sys.version.split()[0],
            "passed": t.passed,
            "failed": t.failed,
            "notes": t.notes,
            "checks": t.checks,
        }
        out = Path(args.json)
        if out.parent and str(out.parent) not in ("", "."):
            out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        print("JSON: %s" % out.resolve())

    return 0 if t.failed == 0 else 1


def _run(mod, srv, t: _T) -> None:
    s = mod.Session()
    try:
        # -- 1. 流式读完后 cookie 进会话罐，下一条普通请求带上 ------------------ #
        url_set = srv.url("/cookies/set?sid=abc&dup=1")
        r = s.get(url_set, timeout=10, stream=True)
        # 实测口径：头就绪时 url 还是请求 URL（重定向后的最终 URL 要到完成后才刷）；
        # 状态码已经是最终 200。
        t.eq("[cookie] 头就绪时 status 已是最终 200", r.status_code, 200)
        t.eq("[cookie] 头就绪时 url 仍是请求 URL", r.url, url_set)
        body = _drain(r)
        t.check("[cookie] 读完后流已收尾", r.is_stream is False, repr(r.is_stream))
        t.check("[cookie] 完成后 body 可解析（跟随到了 /cookies）",
                b'"ok"' in body or b"ok" in body, repr(body[:120]))
        # 流式响应读完后，会话罐里应能学到 Set-Cookie
        t.eq("[cookie] 读完后 session.cookies 有 sid", dict(s.cookies).get("sid"), "abc")
        t.eq("[cookie] 读完后 session.cookies 有 dup", dict(s.cookies).get("dup"), "1")
        raw = s.get(srv.url("/echo"), timeout=10).json()["headers"].get("cookie", "")
        names = [p.split("=", 1)[0].strip() for p in raw.split(";") if p.strip()]
        t.check("[cookie] 下一条普通请求带 sid", "sid=abc" in raw, repr(raw)[:200])
        t.check("[cookie] 下一条普通请求带 dup", "dup=1" in raw, repr(raw)[:200])
        t.check("[cookie] 每个名字只发一份（不重复）",
                names.count("sid") == 1 and names.count("dup") == 1, repr(raw)[:200])
        # 实测：流式响应完成后 raw_cookie_list 为空 —— 如实记录，不断言非空。
        t.note("[cookie] 流式完成后 raw_cookie_list=%r（流式为空；非流式才有）"
               % (r.raw_cookie_list,))
        rn0 = s.get(srv.url("/dup-headers"), timeout=10)
        t.check("[cookie] 非流式 raw_cookie_list 非空（对照）",
                bool(rn0.raw_cookie_list), repr(rn0.raw_cookie_list)[:120])
        rn0.close()

        # 请求级 cookies= 不进会话罐
        r2 = s.get(srv.url("/echo"), cookies={"tmp": "42"}, timeout=10, stream=True)
        body2 = _drain(r2)
        d2 = json.loads(body2.decode("utf-8", "replace"))
        d2raw = d2["headers"].get("cookie", "")
        t.check("[cookie] 请求级 cookies 与会话 cookie 共存",
                "tmp=42" in d2raw and any(k in d2raw for k in ("sid=", "dup=", "other=")),
                repr(d2raw)[:200])
        t.check("[cookie] 请求级 cookies 不进会话罐",
                "tmp" not in dict(s.cookies), repr(dict(s.cookies))[:200])

        # 同名 cookie 更新
        s.get(srv.url("/cookies/set?sid=updated2"), timeout=10, stream=True).close()
        raw2 = s.get(srv.url("/echo"), timeout=10).json()["headers"].get("cookie", "")
        t.check("[cookie] 同名更新后仍只发一份且为新值",
                raw2.count("sid") == 1 and "sid=updated2" in raw2, repr(raw2)[:200])

        # -- 2. 头就绪时的元信息契约 --------------------------------------- #
        r = s.get(srv.url("/drip/5/200"), timeout=20, stream=True)
        t.eq("[head-ready] status 已可用", r.status_code, 200)
        t.check("[head-ready] headers 已可用（content-length）",
                r.headers.get("content-length") == "1000",
                repr(dict(r.headers.to_dict()))[:200])
        t.check("[head-ready] url 已可用", r.url.endswith("/drip/5/200"), r.url)
        t.eq("[head-ready] history 为空（无重定向）", len(r.history), 0)
        t.check("[head-ready] elapsed 是 timedelta 且非负",
                hasattr(r.elapsed, "total_seconds") and r.elapsed.total_seconds() >= 0,
                repr(r.elapsed))
        t.note("[head-ready] 头就绪时 http_version=%r" % (r.http_version,))
        t.check("[head-ready] http_version 取值在契约集合内",
                r.http_version in ("", "0", "1.0", "1.1", "2"), repr(r.http_version))
        _drain(r)
        t.note("[head-done] 完成后 http_version=%r elapsed=%r url=%r"
               % (r.http_version, r.elapsed, r.url))
        t.check("[head-done] 完成后 http_version 是 1.1",
                r.http_version == "1.1", repr(r.http_version))
        t.check("[head-done] 完成后 elapsed 非负",
                r.elapsed.total_seconds() >= 0, repr(r.elapsed))
        t.check("[head-done] 完成后 url 不变", r.url.endswith("/drip/5/200"), r.url)

        # 重复响应头：流式与非流式在同一端点上对齐
        rs = s.get(srv.url("/dup-headers"), timeout=10, stream=True)
        _drain(rs)
        rn = s.get(srv.url("/dup-headers"), timeout=10)
        for tag, resp in (("stream", rs), ("non-stream", rn)):
            t.eq("[%s] 重复头 get_list 保序" % tag,
                 resp.headers.get_list("x-dup"), ["a", "b"])
            t.eq("[%s] 两条 Set-Cookie 都在" % tag,
                 len(resp.headers.get_list("set-cookie")), 2)
            t.eq("[%s] cookies 解析出两个" % tag,
                 sorted(dict(resp.cookies)), ["other", "sid"])
        t.check("[dup] 流式与非流式重复头一致",
                rs.headers.get_list("x-dup") == rn.headers.get_list("x-dup"),
                "%r vs %r" % (rs.headers.get_list("x-dup"), rn.headers.get_list("x-dup")))
        rn.close()

        # -- 3. HEAD / 204 无响应体不挂 ------------------------------------ #
        t0 = time.perf_counter()
        rh = s.head(srv.url("/echo"), timeout=10, stream=True)
        _drain(rh)
        dt = time.perf_counter() - t0
        t.eq("[no-body] HEAD 状态码", rh.status_code, 200)
        t.eq("[no-body] HEAD content", rh.content, b"")
        t.check("[no-body] HEAD 在 3s 内收尾（没挂起）", dt < 3.0, "%.2fs" % dt)
        t.check("[no-body] HEAD 完成后 is_stream=False",
                rh.is_stream is False, repr(rh.is_stream))

        r204 = s.get(srv.url("/status/204"), timeout=10, stream=True)
        _drain(r204)
        t.eq("[no-body] 204 状态码", r204.status_code, 204)
        t.eq("[no-body] 204 content", r204.content, b"")
        t.check("[no-body] 204 完成后 is_stream=False",
                r204.is_stream is False, repr(r204.is_stream))
        t.check("[no-body] 204 完成后 elapsed 非负",
                r204.elapsed.total_seconds() >= 0, repr(r204.elapsed))

        # -- 4. 1xx 中间响应之后最终头可用 ---------------------------------- #
        payload = b"x" * (100 * 1024)
        r1xx = s.post(srv.url("/expect100"), data=payload, timeout=15, stream=True)
        t.eq("[1xx] 最终状态码 200", r1xx.status_code, 200)
        body1xx = _drain(r1xx)
        d = json.loads(body1xx.decode("utf-8", "replace"))
        t.eq("[1xx] 体长度正确", d.get("body_len"), len(payload))
        t.check("[1xx] interim 标记", d.get("interim") is True, repr(d)[:200])
        t.eq("[1xx] 完成后 history 为空（1xx 不进 history）", len(r1xx.history), 0)
        t.eq("[1xx] 会话随后可用", s.get(srv.url("/echo"), timeout=10).json()["method"], "GET")

        # -- 5. 重定向：最终 url / history ---------------------------------- #
        rr = s.get(srv.url("/redirect/3"), timeout=10, stream=True)
        t.eq("[redirect] 头就绪时状态码已最终（200 而不是 302）", rr.status_code, 200)
        t.eq("[redirect] 头就绪时 history 已含 3 跳（history 在 _refresh_locked 里建）",
             len(rr.history), 3)
        _drain(rr)
        t.eq("[redirect] 完成后状态码", rr.status_code, 200)
        t.eq("[redirect] 完成后 history 长度", len(rr.history), 3)
        t.check("[redirect] history 里都是 302",
                all(h.status_code == 302 for h in rr.history),
                repr([h.status_code for h in rr.history]))
        t.eq("[redirect] history[0] Location", rr.history[0].headers.get("location"),
             "/redirect/2")
        t.note("[redirect] 完成后 url=%r（实测）" % (rr.url,))
        t.check("[redirect] 完成后 url 是最终 url", rr.url.endswith("/echo"), rr.url)
        t.check("[redirect] 完成后 http_version 1.x",
                rr.http_version in ("1.0", "1.1", "2"), repr(rr.http_version))

        # allow_redirects=False：停在 302
        r302 = s.get(srv.url("/redirect/1"), allow_redirects=False,
                     timeout=10, stream=True)
        _drain(r302)
        t.eq("[redirect] 不跟随停在 302", r302.status_code, 302)
        t.eq("[redirect] 不跟随 history 为空", len(r302.history), 0)
        t.eq("[redirect] 不跟随 url 原地", r302.url, srv.url("/redirect/1"))

        # 302 跳上的 Set-Cookie 也要被学到（cookie 引擎通道）
        with mod.Session() as s2:
            s2.get(srv.url("/cookies/set?hop=1"), timeout=10, stream=True).close()
            jar = s2.get(srv.url("/cookies"), timeout=10).json()["cookies"]
            t.eq("[redirect] 302 跳上的 Set-Cookie 生效", jar.get("hop"), "1")
    finally:
        s.close()


def _drain(resp) -> bytes:
    """把响应体读干净并返回累计字节（'读完后'语义；最后 close 释放连接）。"""
    out = bytearray()
    try:
        for chunk in resp.iter_content(4096):
            out += chunk
    except BaseException:
        try:
            out += resp.content
        except BaseException:
            pass
    try:
        resp.close()
    except BaseException:
        pass
    return bytes(out)


if __name__ == "__main__":
    sys.exit(main())
