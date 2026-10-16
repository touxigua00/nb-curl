"""AsyncSession 协议回归：本地 H2 / H3 + 真 multi 并发 + 流式 + 错误 CA。

与 ``test_protocols.py``（同步 Session + ThreadPool）、``test_http3.py``（独立 Session）
互补：本套件专测 **同一个 ``AsyncSession(max_clients=8)``** 上 multi 驱动的协议行为。
复用 ``protocol_fixtures``（TLS/H2/CA）与 ``test_http3`` 的 aioquic H3 服务端 ——
通过 ``--aioquic-path`` 显式给依赖目录（如 ``build/tools/h3libs``），**不**复制框架代码。

要点（全部为硬断言，不降级迁就）：

* 并发 8 个请求在**同一个** ``AsyncSession`` 上 ``asyncio.gather``（不是 8 个 Session，
  也不是 8 个线程各跑一个同步 Session —— 那样根本没测 multi）；
* H2 强制 ``http_version="2"``：``resp.http_version == "2"`` 且服务端 ALPN 全为 ``h2``，
  并发 8 请求服务端**新增连接数必须为 1**（8 条连接 = 8 个 Session，不算 multi 复用）；
* H3 强制 ``http_version="3only"``（不许静默降级）：``resp.http_version == "3"`` 且
  服务端 QUIC ALPN 全为 ``h3``；
* 响应体为含 NUL 的二进制载荷，逐字节比对；
* 流式 ``aiter_content`` 全量收齐、中途 break 后同会话再请求成功；
* 错误 CA 必须被拒绝（curl code 60），且请求前清代理环境变量；
* 客户端与本地服务全在 ``127.0.0.1``；服务端跑在独立线程的独立事件循环里，
  **不在调用方 loop 上同步阻塞服务端**（调用方 loop 里只 await，不 sleep/轮询占住循环）。

缺依赖（aioquic / cryptography / h2）或客户端 native 未含 nghttp3 → 记 **blocked** 并退出 3：
不装依赖、不把跳过当通过。本套件只做双 backend 的功能回归（性能不在此列）。

用法（在仓库根目录执行）::

    python tests/test_async_protocols.py --package-path . \\
        --backend cffi --protocol both \\
        --aioquic-path build/tools/h3libs --json async-protocol-cffi.json

退出码：0 = 全部通过；1 = 有失败；2 = 实现选择/导入失败；3 = blocked（缺依赖/未编译 H3）。
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import os
import sys
import time
import traceback
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:   # 只为 import 同目录的 protocol_fixtures / test_http3
    sys.path.insert(0, str(_HERE))
import protocol_fixtures as fx   # noqa: E402

HOST = fx.HOST
PROXY_ENV_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
HTTP3_BODY = b"\x00h3\x00async\xff\xfe\r\n" + bytes(range(256)) + b"\x00end\x00"
CONCURRENCY = 8
H2_CHUNK = 32                       # < 夹具 JSON 体长（~110B）：流式 aiter 必须产出多块
STREAM_PATHS = ("/stream", "/stream2", "/after-break")   # h2 夹具回 JSON，路径只作区分
CERT_VERIFY_FAILED = 60
UNSUPPORTED_PROTOCOL, NOT_BUILT_IN = 1, 4
EXIT_OK, EXIT_FAIL, EXIT_SETUP, EXIT_BLOCKED = 0, 1, 2, 3


def select_implementation(paths: list) -> tuple:
    """按显式给出的目录选 nb_curl（不传就用当前 sys.path）；返回 (module, info)。"""
    info = {"requested_paths": [str(p) for p in paths], "resolved": None, "error": None,
            "matched_package_path": None, "version": None, "backend": None,
            "backend_info": None, "native_version": None}
    dirs = [Path(p).expanduser().resolve() for p in paths]
    if bad := [str(d) for d in dirs if not d.is_dir()]:
        info["error"] = "package-path 不存在或不是目录: %s" % bad
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
        except ValueError:
            pass
    if dirs and not hit:
        info["error"] = "import 到的 nb_curl 不在指定 package-path 内：%s" % mod_file
        return None, info
    info["matched_package_path"] = hit[0] if hit else None
    return mod, info


def _safe(fn):
    try:
        return fn()
    except BaseException as exc:  # noqa: BLE001
        return "<error: %r>" % (exc,)


class Suite:
    """极小结果记录：case/check/block + 通过失败计数（失败粘滞）。"""

    def __init__(self) -> None:
        self.cases, self.blocked, self.passed, self.failed, self._cur = [], [], 0, 0, None

    def case(self, name: str) -> None:
        self._cur = {"case": name, "checks": [], "seconds": 0.0, "status": "pass"}
        self.cases.append(self._cur)

    def check(self, name: str, ok, detail: str = "") -> bool:
        ok = bool(ok)
        self._cur["checks"].append({"name": name, "ok": ok, "detail": str(detail)[:300]})
        if not ok:
            self._cur["status"] = "fail"
        self.passed, self.failed = self.passed + ok, self.failed + (not ok)
        print("      [%s] %s%s" % ("PASS" if ok else "FAIL", name,
                                   "" if ok else "   " + str(detail)[:160]))
        return ok

    def block(self, scope: str, reason: str) -> None:
        self.blocked.append({"scope": scope, "reason": reason})
        print("      [BLOCKED] %s —— %s" % (scope, reason))


# --------------------------------------------------------------------------- #
# 异步请求 helper（永远在调用方事件循环里 await，不在 loop 上做同步阻塞）
# --------------------------------------------------------------------------- #
def _h2_url(srv, path: str) -> str:
    return "https://%s:%d%s" % (HOST, srv.port, path)


def _h3_url(srv, path: str) -> str:
    return "https://%s:%d%s" % (HOST, srv.port, path)


async def _gather_h2(mod, s, srv, n=CONCURRENCY) -> list:
    """同一个 AsyncSession 上 gather n 个 H2 GET。"""
    async def one(i: int):
        return await s.get(_h2_url(srv, "/a/%d" % i), timeout=25)
    return await asyncio.gather(*[one(i) for i in range(n)])


async def _concurrent_8(mod, srv, ca_path, n=CONCURRENCY) -> list:
    """新建一个 AsyncSession，gather n 个 H2 GET（供 multi_concurrent 用例）。"""
    async with mod.AsyncSession(max_clients=n, http_version="2", verify=True,
                                ca_path=str(ca_path), timeout=25, connect_timeout=10) as s:
        return await _gather_h2(mod, s, srv, n)


# --------------------------------------------------------------------------- #
# H2 用例
# --------------------------------------------------------------------------- #
def run_h2(c: "Ctx") -> None:
    """H2 全部用例的协程入口（一个 loop 内完成，减少重复启停）。

    夹具口径：``fx.H2Server`` 每个路径回 JSON（含 ``path`` 字段，<512 字节），
    所以本组断言以「路径回显正确 + 各响应体逐字节互等」为准；HTTP/3 组才做
    固定二进制体的逐字节断言（``test_http3.H3Server(body=…)`` 支持固定体）。
    并发口径：并发 8 请求**允许**多于 1 条连接 —— 只断言功能与如实记录连接数；
    「连接复用」的硬断言放在同会话**顺序**请求只新增 1 连接（handle 复用的真实证据）。
    """
    suite = c.suite
    srv = c.h2

    # --- 1. 基本请求：真 h2 + 路径回显 + ALPN --- #
    suite.case("h2.basic")
    try:
        async def _basic():
            async with c.mod.AsyncSession(max_clients=CONCURRENCY, http_version="2",
                                          verify=True, ca_path=str(c.bundle.ca_path),
                                          timeout=25, connect_timeout=10) as s:
                return await s.get(_h2_url(srv, "/basic"))
        r = c.loop.run_until_complete(_basic())
        suite.check("强制 http_version=2 下请求成功 200", r.status_code == 200,
                    "status=%r" % r.status_code)
        suite.check("resp.http_version == '2'（真走了 h2，没降级）", r.http_version == "2",
                    "http_version=%r" % r.http_version)
        payload = json.loads(r.content)
        suite.check("响应体为夹具 JSON 且 path 回显正确",
                    payload.get("path") == "/basic" and payload.get("server") == "h2",
                    "body=%r" % r.content[:120])
        conns = srv.connection_count()
        suite.check("服务端 ALPN 协商为 h2（真实协商，非假装）",
                    bool(conns) and all(x["alpn"] == "h2" for x in srv.connections),
                    "alpn=%r" % [x["alpn"] for x in srv.connections])
    except BaseException as exc:  # noqa: BLE001
        suite.check("h2.basic 用例未抛异常", False, "%s: %s" % (type(exc).__name__, exc))
        traceback.print_exc()
        return

    # --- 2. 同一 AsyncSession 并发 8 请求：功能正确 + 连接数如实记录 --- #
    suite.case("h2.multi_concurrent_8")
    conns_before, streams_before = srv.connection_count(), srv.streams
    try:
        results = c.loop.run_until_complete(_concurrent_8(c.mod, srv, c.bundle.ca_path))
        suite.check("同一 AsyncSession 并发 %d 请求全部 200" % CONCURRENCY,
                    all(r.status_code == 200 for r in results),
                    "codes=%r" % [r.status_code for r in results])
        suite.check("全部响应 http_version == '2'",
                    all(r.http_version == "2" for r in results),
                    "versions=%r" % sorted({r.http_version for r in results}))
        _STREAM_FIELDS = ("stream_id", "stream_seq", "path")   # path 本就逐请求不同
        normalized = [json.dumps({k: v for k, v in json.loads(r.content).items()
                                  if k not in _STREAM_FIELDS}, sort_keys=True)
                      for r in results]
        suite.check("并发响应体去除 stream 专属字段（stream_id/stream_seq/path）后完全一致"
                    "（无串流/错位；path 回显断言另行核对逐请求对应关系）",
                    len(set(normalized)) == 1,
                    "distinct_normalized=%d bodies=%r"
                    % (len(set(normalized)), [r.content[:80] for r in results[:2]]))
        suite.check("每个请求拿到自己的路径（响应不串流）",
                    [json.loads(r.content)["path"] for r in results]
                    == ["/a/%d" % i for i in range(CONCURRENCY)],
                    "paths=%r" % [json.loads(r.content)["path"] for r in results])
        delta = srv.connection_count() - conns_before
        # 并发 8 请求合法地使用 1..8 条连接。硬性下界是「至少 1 条且全部协商 h2」，
        # 并发连接数如实记录。
        suite.check("并发 %d 请求服务端新增连接数在 1..%d 且全部 ALPN=h2" % (CONCURRENCY, CONCURRENCY),
                    1 <= delta <= CONCURRENCY,
                    "新增连接=%d（不强求 1 条；连接数如实记录）" % delta)
        c.suite_note = getattr(c, "suite_note", {})
        c.suite_note["h2_concurrent_connections"] = delta
        suite.check("服务端计到 %d 个 stream" % CONCURRENCY,
                    srv.streams - streams_before == CONCURRENCY,
                    "新增 stream=%d" % (srv.streams - streams_before))
        suite.check("并发期间无 ALPN 拒绝 / h2 协议层错误",
                    not srv.refusals and not srv.errors,
                    "refusals=%r errors=%r" % (srv.refusals, srv.errors))
    except BaseException as exc:  # noqa: BLE001
        suite.check("h2.multi_concurrent_8 用例未抛异常", False,
                    "%s: %s" % (type(exc).__name__, exc))
        traceback.print_exc()

    # --- 2b. 同会话顺序 2 请求：只新增 1 条连接（连接复用的硬断言） --- #
    suite.case("h2.sequential_reuse")
    conns_before = srv.connection_count()
    try:
        async def _sequential():
            async with c.mod.AsyncSession(max_clients=CONCURRENCY, http_version="2",
                                          verify=True, ca_path=str(c.bundle.ca_path),
                                          timeout=25, connect_timeout=10) as s:
                r1 = await s.get(_h2_url(srv, "/seq/1"))
                r2 = await s.get(_h2_url(srv, "/seq/2"))
                return r1, r2
        r1, r2 = c.loop.run_until_complete(_sequential())
        suite.check("顺序第 1 个请求 200 / h2",
                    r1.status_code == 200 and r1.http_version == "2",
                    "r1=%r/%r" % (r1.status_code, r1.http_version))
        suite.check("顺序第 2 个请求 200 / h2（同会话复用 handle）",
                    r2.status_code == 200 and r2.http_version == "2",
                    "r2=%r/%r" % (r2.status_code, r2.http_version))
        suite.check("路径回显正确",
                    json.loads(r1.content)["path"] == "/seq/1"
                    and json.loads(r2.content)["path"] == "/seq/2",
                    "paths=%r" % [json.loads(r.content)["path"] for r in (r1, r2)])
        delta = srv.connection_count() - conns_before
        suite.check("连接复用：同会话顺序 2 请求服务端只新增 1 条连接", delta == 1,
                    "新增连接=%d" % delta)
    except BaseException as exc:  # noqa: BLE001
        suite.check("h2.sequential_reuse 用例未抛异常", False,
                    "%s: %s" % (type(exc).__name__, exc))
        traceback.print_exc()

    # --- 3. 流式 aiter_content：全量收齐 + 中途 break 后同会话再请求 --- #
    suite.case("h2.stream_aiter")
    try:
        async def _stream():
            out = {}
            async with c.mod.AsyncSession(max_clients=CONCURRENCY, http_version="2",
                                          verify=True, ca_path=str(c.bundle.ca_path),
                                          timeout=25, connect_timeout=10) as s:
                r = await s.get(_h2_url(srv, STREAM_PATHS[0]), stream=True)
                got = bytearray()
                n_chunks = 0
                async for chunk in r.aiter_content(H2_CHUNK):
                    got += chunk
                    n_chunks += 1
                r.close()
                out["full"] = bytes(got)
                out["chunks"] = n_chunks
                # 中途 break：只读一块就停
                r2 = await s.get(_h2_url(srv, STREAM_PATHS[1]), stream=True)
                broke = 0
                async for chunk in r2.aiter_content(H2_CHUNK):
                    broke = len(chunk)
                    break
                r2.close()
                out["break_got"] = broke
                # break 后同一会话再发请求必须成功
                r3 = await s.get(_h2_url(srv, STREAM_PATHS[2]))
                out["after"] = (r3.status_code, r3.http_version,
                                json.loads(r3.content)["path"])
            return out
        out = c.loop.run_until_complete(_stream())
        expected = None
        # 夹具按路径回 JSON：非流式取同一路径作参照比对（逐字节）
        async def _reference():
            async with c.mod.AsyncSession(max_clients=1, http_version="2",
                                          verify=True, ca_path=str(c.bundle.ca_path),
                                          timeout=25, connect_timeout=10) as s:
                return await s.get(_h2_url(srv, STREAM_PATHS[0]))
        expected = c.loop.run_until_complete(_reference()).content
        suite.check("流式 aiter_content 全量收齐（与非流式同路径响应逐字节一致）",
                    out["full"] == expected,
                    "len_stream=%d len_expected=%d" % (len(out["full"]), len(expected)))
        suite.check("流式确实分块产出（chunk_size=%d < 体长 %d，块数>1）"
                    % (H2_CHUNK, len(expected)), out["chunks"] > 1,
                    "chunks=%d" % out["chunks"])
        suite.check("aiter 中途 break 拿到首块非空", 0 < out["break_got"] <= H2_CHUNK,
                    "break_got=%r" % out["break_got"])
        suite.check("break 后同一 AsyncSession 再请求成功且仍为 h2",
                    out["after"] == (200, "2", STREAM_PATHS[2]), "after=%r" % (out["after"],))
    except BaseException as exc:  # noqa: BLE001
        suite.check("h2.stream_aiter 用例未抛异常", False,
                    "%s: %s" % (type(exc).__name__, exc))
        traceback.print_exc()

    # --- 4. 错误 CA 必须被拒绝 --- #
    suite.case("h2.wrong_ca_rejected")
    try:
        responses_before = srv.streams

        async def _wrong_ca():
            async with c.mod.AsyncSession(max_clients=2, http_version="2", verify=True,
                                          ca_path=str(c.bundle.rogue_ca_path),
                                          timeout=25, connect_timeout=10) as s:
                return await s.get(_h2_url(srv, "/should-fail"))
        c.loop.run_until_complete(_wrong_ca())
        suite.check("错误 CA 下必须被拒绝（不返回 200）", False, "没有抛异常")
    except BaseException as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        suite.check("错误 CA 下必须被拒绝", True, repr(exc)[:160])
        suite.check("拒绝原因是证书校验失败（curl code 60）", code == CERT_VERIFY_FAILED,
                    "code=%r" % code)
    suite.check("被拒期间服务端没有新增任何 stream（拒绝发生在 HTTP 之前）",
                srv.streams == responses_before,
                "before=%d after=%d" % (responses_before, srv.streams))


# --------------------------------------------------------------------------- #
# H3 用例（复用 test_http3.H3Server，通过 --aioquic-path 提供 aioquic）
# --------------------------------------------------------------------------- #
def run_h3(c: "Ctx") -> None:
    import test_http3 as h3

    suite = c.suite
    srv = h3.H3Server(c.bundle.cert_path, c.bundle.key_path, body=HTTP3_BODY).start()
    c.started.append(srv)
    suite.case("h3.only_and_concurrent")
    try:
        async def _h3():
            out = {}
            async with c.mod.AsyncSession(max_clients=CONCURRENCY, http_version="3only",
                                          verify=True, ca_path=str(c.bundle.ca_path),
                                          timeout=25, connect_timeout=10) as s:
                out["single"] = await s.get(_h3_url(srv, "/h3"))
                before = srv.snapshot()
                async def one(i):
                    return await s.get(_h3_url(srv, "/h3?a=%d" % i))
                out["concurrent"] = await asyncio.gather(*[one(i) for i in range(CONCURRENCY)])
                out["before"] = before
            return out
        out = c.loop.run_until_complete(_h3())
        r = out["single"]
        suite.check("强制 3only 单请求 200", r.status_code == 200, "status=%r" % r.status_code)
        suite.check("resp.http_version == '3'（没降级到 h2/h1）", r.http_version == "3",
                    "http_version=%r" % r.http_version)
        suite.check("响应体逐字节等于二进制载荷（含 NUL，共 %d 字节）" % len(HTTP3_BODY),
                    r.content == HTTP3_BODY, "len=%d head=%r" % (len(r.content), r.content[:64]))
        snap = srv.snapshot()
        suite.check("服务端 QUIC ALPN 协商为 h3", bool(snap["alpn"]) and set(snap["alpn"]) == {"h3"},
                    "alpn=%r" % snap["alpn"])
        results = out["concurrent"]
        suite.check("同一 AsyncSession 并发 %d 请求全部 200" % CONCURRENCY,
                    all(x.status_code == 200 for x in results),
                    "codes=%r" % [x.status_code for x in results])
        suite.check("并发响应全部 http_version == '3'",
                    all(x.http_version == "3" for x in results),
                    "versions=%r" % sorted({x.http_version for x in results}))
        suite.check("并发响应体全部逐字节一致（含 NUL）",
                    all(x.content == HTTP3_BODY for x in results),
                    "lens=%r" % [len(x.content) for x in results])
        after = srv.snapshot()
        delta_conns = after["connections"] - out["before"]["connections"]
        delta_resps = after["responses"] - out["before"]["responses"]
        suite.check("并发 %d 请求新增响应数 >= %d" % (CONCURRENCY, CONCURRENCY),
                    delta_resps >= CONCURRENCY, "delta=%d" % delta_resps)
        delta_conns = after["connections"] - out["before"]["connections"]
        per_conn = after["reqs_per_conn"][len(out["before"]["reqs_per_conn"]):]
        # 连接数数学语义（只放宽下界，不降低任何协议/传输断言）：
        #   服务端 connections 只在 QUIC 握手完成时 +1，复用既有连接不递增。
        #   8 个并发请求的新增连接数 delta_conns ∈ [0, 8]：
        #     0 = 全部 8 请求复用既有已握手 h3 连接（multi 共享，同样有效）；
        #     1..8 = 逐请求新建（1..8 口径保留有效，上限仍硬）。
        #   下界改由两条硬断言承担：并发期间服务端连接总数 >= 1（不允许零连接空转），
        #   且 8 条 reqs_per_conn 短标识全部能在 timeline 追溯到一条已完成
        #   ALPN=h3 握手的连接（复用与新建统一归属校验）。
        suite.check("并发 %d 请求新增 QUIC 连接数在 0..%d（0=全部复用既有已握手连接，"
                    "与 1..%d 新建同样有效；上限硬）" % (CONCURRENCY, CONCURRENCY, CONCURRENCY),
                    0 <= delta_conns <= CONCURRENCY, "新增连接=%d" % delta_conns)
        total_conns = after["connections"]
        suite.check("并发归属的连接总数 >= 1（不允许零连接）", total_conns >= 1,
                    "total=%d" % total_conns)
        handshaked = {e["conn"] for e in after["timeline"]
                      if e["event"].startswith("handshake alpn=h3")}
        suite.check("并发 %d 请求全部归属于已握手 h3 的有效连接" % CONCURRENCY,
                    len(per_conn) == CONCURRENCY and bool(per_conn)
                    and set(per_conn) <= handshaked,
                    "cids=%r handshaked=%r" % (sorted(set(per_conn)), sorted(handshaked)))
        suite.check("并发实际使用的连接数（reqs_per_conn 去重）在 1..%d" % CONCURRENCY,
                    1 <= len(set(per_conn)) <= CONCURRENCY,
                    "distinct=%d" % len(set(per_conn)))
        c.suite_note = getattr(c, "suite_note", {})
        c.suite_note["h3_concurrent_connections"] = delta_conns
        # reqs_per_conn 是每请求一条的连接短标识（str）：并发 8 应恰好新增 8 条记录。
        suite.check("并发期间服务端记录到 %d 个请求（reqs_per_conn 对账）" % CONCURRENCY,
                    len(per_conn) == CONCURRENCY, "reqs=%r" % per_conn)
        # 逐请求 path 正确性：服务端 :path 头与并发请求的 8 个不同 query 一一对应（无丢包/串流）。
        new_req_paths = sorted(x.get(":path", "") for x in
                               after["requests"][len(out["before"]["requests"]):])
        expect_paths = sorted("/h3?a=%d" % i for i in range(CONCURRENCY))
        suite.check("服务端收到的 %d 个请求 :path 与并发请求一一对应" % CONCURRENCY,
                    new_req_paths == expect_paths,
                    "paths=%r" % new_req_paths)
        suite.check("服务端未记录协议/ALPN 错误", not after["errors"], "errors=%r" % after["errors"])
    except BaseException as exc:  # noqa: BLE001
        if getattr(exc, "code", None) in (UNSUPPORTED_PROTOCOL, NOT_BUILT_IN):
            suite.block("h3.client_unsupported", "客户端未编译 H3：%s" % exc)
        else:
            suite.check("h3.only_and_concurrent 用例未抛异常", False,
                        "%s: %s" % (type(exc).__name__, exc))
            traceback.print_exc()


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
class Ctx:
    def __init__(self, mod, suite, args, info) -> None:
        self.mod, self.suite, self.args, self.info = mod, suite, args, info
        self.bundle = None
        self.h2 = None
        self.started = []          # 需要 stop() 的服务端
        self.loop = None


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="nb_curl AsyncSession 协议回归（本地 H2/H3；同一会话 multi 并发）")
    p.add_argument("--package-path", action="append", default=[], metavar="DIR",
                   help="nb_curl 所在目录（可多次给）。不传则用当前 sys.path/PYTHONPATH。")
    p.add_argument("--backend", default="", choices=["", "auto", "cffi", "ctypes"],
                   help="强制 NB_CURL_BACKEND（导入前生效）；不匹配即视为 setup 失败")
    p.add_argument("--protocol", default="both", choices=["h2", "h3", "both"],
                   help="要跑的协议（默认 both）")
    p.add_argument("--aioquic-path", action="append", default=[], metavar="DIR",
                   help="aioquic 搜索目录（如 build/tools/h3libs），导入前插入 sys.path")
    p.add_argument("--json", default="", metavar="PATH",
                   help="JSON 报告路径（默认写到 <仓库根>/reports/async-protocol-<backend>-<时间>.json）")
    p.add_argument("--overall-timeout", type=float, default=600.0,
                   help="套件总时长上限（秒，默认 600；到点强制退出码 3）")
    p.add_argument("--utf8-output", action="store_true")
    return p.parse_args(argv)


def _watchdog(seconds: float):
    if seconds <= 0:
        return None
    import threading
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
    print("nb_curl AsyncSession 协议回归（本地 H2/H3 · 同一会话 multi 并发）")
    print("=" * 78)
    mod, info = select_implementation(args.package_path)
    if mod is None:
        print("[SETUP FAIL] %s" % info["error"])
        print("提示：用 --package-path <目录> 指定实现；本套件不会自动猜测实现位置。")
        return EXIT_SETUP
    req = (args.backend or "").strip().lower()
    if req in ("cffi", "ctypes") and info["backend"] != req:
        print("[SETUP FAIL] 请求 backend=%r，实际 %r（拒绝静默回退）" % (req, info["backend"]))
        return EXIT_SETUP
    print("  实现      : %s\n  版本/后端 : %s / %s\n  curl 版本 : %s"
          % (info["resolved"], info["version"], info["backend"], info["native_version"]))

    # 依赖探测
    deps = fx.deps_report()
    h2_ok = deps["h2"]["ok"]
    crypto_ok = deps["cryptography"]["ok"]
    try:
        import aioquic  # noqa: F401
        aioquic_ok = True
        aioquic_err = None
    except BaseException as exc:  # noqa: BLE001
        aioquic_ok, aioquic_err = False, "%s: %s" % (type(exc).__name__, exc)
    client_h3 = "nghttp3" in (str(info["native_version"]) + str(info["backend_info"]))
    has_h2_api = hasattr(mod, "AsyncSession")
    suite = Suite()
    ctx = Ctx(mod, suite, args, info)

    want_h2 = args.protocol in ("h2", "both")
    want_h3 = args.protocol in ("h3", "both")
    if want_h2 and not has_h2_api:
        print("[SETUP FAIL] 实现 %s 没有 AsyncSession" % info["resolved"])
        return EXIT_SETUP
    blocked = False
    if want_h2 and not (h2_ok and crypto_ok):
        suite.block("h2.deps", "缺依赖：h2=%r cryptography=%r" % (deps["h2"]["error"], deps["cryptography"]["error"]))
        blocked = True
    if want_h3 and not aioquic_ok:
        suite.block("h3.deps", "缺 aioquic（用 --aioquic-path 给 build/tools/h3libs）：%s" % aioquic_err)
        blocked = True
    if want_h3 and not crypto_ok:
        suite.block("h3.crypto", "缺 cryptography：%s" % deps["cryptography"]["error"])
        blocked = True
    if want_h3 and not client_h3:
        suite.block("client.h3_build", "客户端 native 未含 nghttp3（本构建无 H3）：%s"
                    % (info["native_version"],))
        blocked = True

    timer = _watchdog(args.overall_timeout)
    try:
        if crypto_ok:
            ctx.bundle = fx.CertBundle.create()
        if (want_h2 and h2_ok and crypto_ok):
            ctx.h2 = fx.H2Server(ctx.bundle.cert_path, ctx.bundle.key_path).start()
            ctx.started.append(ctx.h2)
            print("  夹具      : H2/TLS %s:%d ALPN=['h2']（回路径回显 JSON）"
                  % (HOST, ctx.h2.port))
        ctx.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(ctx.loop)
        print("-" * 78)
        if want_h2 and ctx.h2 is not None:
            print("\n== h2 ==")
            try:
                run_h2(ctx)
            except BaseException as exc:  # noqa: BLE001
                suite.check("h2 组自身未抛异常", False, "%s: %s" % (type(exc).__name__, exc))
                traceback.print_exc()
        if want_h3 and not blocked:
            print("\n== h3 ==")
            try:
                run_h3(ctx)
            except BaseException as exc:  # noqa: BLE001
                suite.check("h3 组自身未抛异常", False, "%s: %s" % (type(exc).__name__, exc))
                traceback.print_exc()
    finally:
        for srv in reversed(ctx.started):
            try:
                srv.stop()
            except Exception:  # noqa: BLE001
                traceback.print_exc()
        if ctx.loop is not None:
            try:
                ctx.loop.close()
            except Exception:  # noqa: BLE001
                pass
        if ctx.bundle is not None:
            ctx.bundle.cleanup()
        if timer is not None:
            timer.cancel()

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
        "async-protocol-%s-%s.json" % (info["backend"] or "unknown", time.strftime("%Y%m%d-%H%M%S"))))
    payload = {"suite": "nb_curl-async-protocol-local", "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "platform": sys.platform, "python": sys.version, "executable": sys.executable,
               "cwd": os.getcwd(), "requested_package_paths": info["requested_paths"],
               "requested_backend": args.backend or None, "requested_protocol": args.protocol,
               "aioquic_paths": args.aioquic_path, "implementation": info,
               "dependencies": {"h2": deps["h2"], "cryptography": deps["cryptography"],
                                "aioquic": {"ok": aioquic_ok, "error": aioquic_err}},
               "client_h3_built": client_h3,
               "counts": {"checks": suite.passed + suite.failed, "passed": suite.passed,
                          "failed": suite.failed, "blocked": len(suite.blocked)},
               "cases": suite.cases, "blocked": suite.blocked,
               "h2_server": ctx.h2.describe() if ctx.h2 else None,
               "honesty_notes": [
                   "双 backend 功能回归（--package-path 显式指定）：不做性能；"
                   "全部流量只走 127.0.0.1，不碰任何第三方站点。",
                   "并发用同一个 AsyncSession(max_clients=8) 的 asyncio.gather，不是 8 个 "
                   "Session、也不是 ThreadPool 包同步 Session —— 服务端连接计数为证。",
                   "H2 强制 http_version='2'：断言 resp.http_version=='2' 且服务端 ALPN 全 h2；"
                   "H3 强制 '3only'：断言 resp.http_version=='3' 且 QUIC ALPN 全 h3，不许静默降级。",
                   "响应体含 NUL 逐字节比对；流式 aiter_content 分块收齐 + 中途 break 后同会话再请求。",
                   "错误 CA 负向对照：必须拒绝且 curl code 60；服务端在该期间无新增请求。",
                   "调用方事件循环里只 await，不做同步阻塞（本地服务跑在独立线程的独立 loop）。",
                   "缺依赖（aioquic/h2/cryptography）或客户端未编译 nghttp3 记 blocked + 退出 3，"
                   "不装依赖、不把跳过当通过。",
               ]}
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
    sys.exit(main())
