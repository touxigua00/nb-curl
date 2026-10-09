"""nb_curl 功能自测

分层设计：
* 指纹相关（1-5）打真实站点 xcctls.top —— 只有真实 TLS 才能验证指纹；
* HTTP 语义（6）打本地回显服务 —— 精确断言"客户端到底发了什么"，
  这是验证"GET 被误发成 POST""响应体被 \\0 截断"这类 bug 的唯一可靠手段
  （httpbin.org 等公共站点会拦截 curl-impersonate 指纹，不适合做基准）；
* 韧性/一致性（7-9）验证连接复用自愈、双后端结果一致、并发。

运行:  python tests/test_nb_curl.py
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)                      # 同级模块 local_server
# 兼容两种目录布局：
#   <root>/tests/          且 <root>/nb_curl/            （Windows 项目）
#   <root>/tests/          且 <root>/python/nb_curl/     （Linux 构建套件）
_PROJECT_ROOT = os.path.dirname(_HERE)
for _cand in (_PROJECT_ROOT, os.path.join(_PROJECT_ROOT, "python")):
    if os.path.isdir(os.path.join(_cand, "nb_curl")):
        _PROJECT_ROOT = _cand
        sys.path.insert(0, _cand)
        break

import nb_curl  # noqa: E402
from local_server import LocalServer  # noqa: E402

PROBE = "https://www.xcctls.top/all"
FAILS: list[str] = []
PASSES = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASSES
    if ok:
        PASSES += 1
        print("  [PASS] %s" % name)
    else:
        FAILS.append(name)
        print("  [FAIL] %s  %s" % (name, detail))


def section(title: str) -> None:
    print("\n=== %s ===" % title)


def probe(impersonate=None, **kwargs):
    r = nb_curl.get(PROBE, impersonate=impersonate, timeout=25, **kwargs)
    return json.loads(r.text)


# --------------------------------------------------------------------------- #
# 1. 内置指纹
# --------------------------------------------------------------------------- #
def test_builtin_fingerprints():
    section("1. 内置指纹（7 个）")
    expect_ua = {
        "chrome99": "Chrome/99.",
        "chrome116": "Chrome/116.",
        "chrome131": "Chrome/131.",
        "chrome146": "Chrome/146.",
        "chrome150": "Chrome/150.",
        "chrome152": "Chrome/152.",
        "firefox147": "Firefox/147.",
    }
    for target, ua_part in expect_ua.items():
        try:
            data = probe(target)
        except Exception as exc:  # noqa: BLE001
            check("%s 请求" % target, False, repr(exc))
            continue
        ch = data.get("client_hello", {})
        h2 = data.get("http2", {})
        ja4 = (ch.get("ja4") or {}).get("ja4")
        akamai = h2.get("akamai")
        ua = (h2.get("headers") or {}).get("user-agent", "")
        grease = "GREASE" in str(ch.get("cipher_suites", [])[:1])

        check("%s ja4 非空" % target, bool(ja4), str(ja4))
        check("%s akamai 非空" % target, bool(akamai), str(akamai))
        check("%s UA 是 %s" % (target, ua_part), ua_part in ua, ua[:90])
        check("%s HTTP/2" % target, r_http_version(target) == "2")
        if target.startswith("chrome"):
            check("%s 带 GREASE" % target, grease,
                  "cipher 首个=%s" % ch.get("cipher_suites", [])[:1])


def r_http_version(target: str) -> str:
    r = nb_curl.get(PROBE, impersonate=target, timeout=25)
    return r.http_version


# --------------------------------------------------------------------------- #
# 2. 平台
# --------------------------------------------------------------------------- #
def test_platform_is_windows():
    section("2. 平台改为 Windows")
    for target in ("chrome131", "chrome146", "chrome150"):
        data = probe(target)
        h = (data.get("http2") or {}).get("headers") or {}
        ua = h.get("user-agent", "")
        platform = h.get("sec-ch-ua-platform", "")
        check("%s UA 是 Windows" % target, "Windows NT 10.0" in ua, ua[:90])
        check("%s sec-ch-ua-platform=Windows" % target, platform == '"Windows"', platform)
    data = probe("firefox147")
    ua = ((data.get("http2") or {}).get("headers") or {}).get("user-agent", "")
    check("firefox147 UA 是 Windows", "Windows NT 10.0" in ua, ua[:90])


# --------------------------------------------------------------------------- #
# 3. 头持久性
# --------------------------------------------------------------------------- #
def test_header_persistence():
    section("3. 同一 Session 连发 3 次，自定义头不丢")
    custom = {"X-Test-Marker": "nb_curl-abc123", "X-Custom-Ua": "my-custom-agent/9.9"}
    with nb_curl.Session(impersonate="chrome116") as s:
        seen = []
        for _ in range(3):
            r = s.get(PROBE, headers=custom, timeout=25)
            h = json.loads(r.text)["http2"]["headers"]
            seen.append((h.get("x-test-marker"), h.get("x-custom-ua"),
                         h.get("user-agent", ""), h.get("accept-language")))
        for i, row in enumerate(seen):
            check("第%d次 X-Test-Marker" % (i + 1), row[0] == "nb_curl-abc123", str(row[:2]))
            check("第%d次 X-Custom-Ua" % (i + 1), row[1] == "my-custom-agent/9.9", str(row[:2]))
            check("第%d次 UA 未被破坏" % (i + 1), "Chrome/116" in row[2], row[2][:80])
            check("第%d次 accept-language 仍在" % (i + 1), bool(row[3]), str(row[3]))
        check("三次完全一致", len(set(seen)) == 1, str(seen))


# --------------------------------------------------------------------------- #
# 4. 自定义指纹
# --------------------------------------------------------------------------- #
def test_custom_fingerprint():
    section("4. 自定义 ja3 / akamai / diy_fp")
    ja3 = ("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
           "0-11-10-35-16-5-51-43-13-45-65281,29-23-24,0")
    akamai = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
    r = nb_curl.get(PROBE, ja3=ja3, akamai=akamai, timeout=25)
    check("自定义指纹请求成功", r.status_code == 200, str(r.status_code))
    data = json.loads(r.text)
    ch, h2 = data.get("client_hello", {}), data.get("http2", {})
    ext_order = [int((e.get("type") or "0").split("(")[-1].rstrip(")")) if "(" in (e.get("type") or "") else -1
                 for e in ch.get("extensions", [])]
    check("akamai settings 生效",
          h2.get("akamai", "").startswith("1:65536;2:0;4:6291456;6:262144"), str(h2.get("akamai")))
    check("akamai 伪头顺序 masp", (h2.get("akamai") or "").endswith("m,a,s,p"), str(h2.get("akamai")))
    check("ja3 扩展顺序下发", ext_order[:1] in ([0], [-1]) or ext_order[0] == 0,
          str(ext_order[:6]))

    r2 = nb_curl.get(PROBE, impersonate="chrome116",
                   diy_fp={"http2_no_priority": True, "tls_grease": True}, timeout=25)
    check("diy_fp 组合请求成功", r2.status_code == 200, str(r2.status_code))

    # extra_fp 已彻底移除：传了直接 TypeError（不再是兼容别名）
    try:
        nb_curl.get(PROBE, impersonate="chrome116", extra_fp={"tls_grease": True}, timeout=25)
        check("extra_fp 已移除（应报 TypeError）", False, "竟然没报错")
    except TypeError:
        check("extra_fp 已移除（应报 TypeError）", True)
    except Exception as exc:  # noqa: BLE001
        check("extra_fp 已移除（应报 TypeError）", False, repr(exc))


# --------------------------------------------------------------------------- #
# 5. 连接池隔离
# --------------------------------------------------------------------------- #
def test_pool_isolation():
    section("5. 连接池按指纹隔离")
    with nb_curl.Session() as s:
        s.get(PROBE, impersonate="chrome116", timeout=25)
        n1 = len(s.pool_keys())
        s.get(PROBE, impersonate="firefox147", timeout=25)
        n2 = len(s.pool_keys())
        s.get(PROBE, impersonate="chrome116", timeout=25)
        n3 = len(s.pool_keys())
        check("分区 1 起始", n1 == 1, "keys=%d" % n1)
        check("不同指纹 -> 不同分区", n2 == 2, "keys=%d" % n2)
        check("复用同一指纹不再新增分区", n3 == 2, "keys=%d" % n3)


# --------------------------------------------------------------------------- #
# 6. HTTP 语义（本地服务）
# --------------------------------------------------------------------------- #
def test_http_semantics():
    section("6. HTTP 语义（本地回显服务）")
    with LocalServer() as srv:
        # --- 方法正确性（回归：GET 曾被误发成 POST） ---
        for method, fn in (("GET", nb_curl.get), ("DELETE", nb_curl.delete)):
            r = fn(srv.url("/echo"), impersonate="chrome116", timeout=10)
            check("%s 实际发出 %s" % (method, method),
                  r.json()["method"] == method, r.json()["method"])
        for method, fn, kw in (
            ("POST", nb_curl.post, {"json": {"a": 1}}),
            ("PUT", nb_curl.put, {"data": "hello"}),
            ("PATCH", nb_curl.patch, {"data": "p"}),
        ):
            r = fn(srv.url("/echo"), impersonate="chrome116", timeout=10, **kw)
            check("%s 实际发出 %s" % (method, method),
                  r.json()["method"] == method, r.json()["method"])

        # 空 body 的 POST 也应带 Content-Length: 0
        r = nb_curl.post(srv.url("/echo"), impersonate="chrome116", timeout=10)
        check("空 body POST 仍是 POST",
              r.json()["method"] == "POST" and r.json()["headers"].get("content-length") == "0",
              str(r.json()["headers"].get("content-length")))

        # --- POST 体与 content-type ---
        r = nb_curl.post(srv.url("/echo"), json={"a": 1, "b": "中文"},
                       impersonate="chrome116", timeout=10)
        d = r.json()
        check("POST json 体正确", json.loads(d["body"]) == {"a": 1, "b": "中文"}, d["body"][:80])
        check("POST content-type 为 json",
              "application/json" in d["headers"].get("content-type", ""),
              d["headers"].get("content-type", ""))

        r = nb_curl.post(srv.url("/echo"), data={"x": "y"}, impersonate="chrome150", timeout=10)
        check("POST form 体正确", r.json()["body"] == "x=y", r.json()["body"])

        # --- 重定向 ---
        r = nb_curl.get(srv.url("/redirect/3"), impersonate="chrome116", timeout=10)
        check("跟随重定向", r.status_code == 200 and len(r.history) == 3,
              "status=%d history=%d" % (r.status_code, len(r.history)))
        r = nb_curl.get(srv.url("/redirect/1"), impersonate="chrome116",
                      allow_redirects=False, timeout=10)
        check("不跟随重定向", r.status_code == 302, "status=%d" % r.status_code)

        # --- cookie 持久化 ---
        with nb_curl.Session(impersonate="chrome116") as s:
            s.get(srv.url("/cookies/set?nb_curl_test=1"), timeout=10)
            r = s.get(srv.url("/cookies"), timeout=10)
            check("cookie 持久化", r.json().get("cookies", {}).get("nb_curl_test") == "1",
                  str(r.json()))

        # --- 状态码 ---
        r = nb_curl.get(srv.url("/status/404"), impersonate="chrome116", timeout=10)
        check("404 状态码", r.status_code == 404, str(r.status_code))
        try:
            r.raise_for_status()
            check("404 raise_for_status", False, "未抛异常")
        except nb_curl.HTTPError:
            check("404 raise_for_status", True)

        # --- 二进制体完整性（回归：含 \\0 的响应体曾被截断） ---
        r = nb_curl.get(srv.url("/binary/4096"), impersonate="chrome116", timeout=10)
        pattern = b"\x00\x01\x02\xff\xfe\r\n\x00ABC"
        expected = (pattern * (4096 // len(pattern) + 1))[:4096]
        check("二进制体长度未截断", len(r.content) == 4096, "len=%d" % len(r.content))
        check("二进制体内容完整", r.content == expected, "首 16 字节=%r" % r.content[:16])

        # --- gzip 自动解压 ---
        r = nb_curl.get(srv.url("/gzip"), impersonate="chrome116", timeout=10)
        check("gzip 自动解压", r.json().get("text") == "压缩测试", r.text[:80])

        # --- 超时 ---
        try:
            nb_curl.get(srv.url("/delay/3"), impersonate="chrome116", timeout=0.8)
            check("超时抛 Timeout", False, "未抛异常")
        except nb_curl.Timeout as exc:
            check("超时抛 Timeout", True)
            check("Timeout 带 curl 错误码 28", exc.code == 28, "code=%r" % exc.code)
            check("Timeout 消息含符号名", "CURLE_OPERATION_TIMEDOUT" in str(exc), str(exc))
        except nb_curl.NbCurlError as exc:
            check("超时抛 Timeout", False, "抛了 %r" % exc)


# --------------------------------------------------------------------------- #
# 7. H2 连接复用自愈
# --------------------------------------------------------------------------- #
def test_reuse_resilience():
    section("7. H2 连接复用自愈（xcctls.top 已知每次响应后关连接）")
    with nb_curl.Session(impersonate="chrome116") as s:
        ok = 0
        for _ in range(10):
            try:
                r = s.get(PROBE, timeout=25)
                ok += (r.status_code == 200)
            except nb_curl.NbCurlError:
                pass
        check("连发 10 次全部成功", ok == 10, "成功 %d/10" % ok)
        check("已记住该 origin 需要新建连接",
              ("https", "www.xcctls.top", 443) in s._no_reuse_origins,
              str(s._no_reuse_origins))


# --------------------------------------------------------------------------- #
# 8. 后端一致性（cffi vs ctypes）
# --------------------------------------------------------------------------- #
_SNIPPET = r"""
import json, sys
import nb_curl
out = {"backend": nb_curl.backend_name()}
r = nb_curl.get("%s", impersonate="chrome116", timeout=25)
d = json.loads(r.text)
ch, h2 = d.get("client_hello", {}), d.get("http2", {})
h = h2.get("headers") or {}
out.update({
    "status": r.status_code,
    "http": r.http_version,
    "ja4": (ch.get("ja4") or {}).get("ja4"),
    "akamai": (h2.get("akamai") or "")[:80],
    "ua": h.get("user-agent", ""),
    "accept_language": h.get("accept-language", ""),
})
print("@@" + json.dumps(out))
""" % PROBE


def test_backend_parity():
    section("8. cffi / ctypes 两个后端结果一致")
    root = _PROJECT_ROOT
    results = {}
    for backend in ("cffi", "ctypes"):
        env = dict(os.environ)
        env["NB_CURL_BACKEND"] = backend
        env["PYTHONPATH"] = root
        for key in ("http_proxy", "https_proxy", "all_proxy",
                    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            env.pop(key, None)
        proc = subprocess.run([sys.executable, "-c", _SNIPPET],
                              capture_output=True, text=True, env=env, cwd=root)
        line = next((l for l in proc.stdout.splitlines() if l.startswith("@@")), None)
        if line is None:
            check("%s 后端可运行" % backend, False, (proc.stderr or "")[-300:])
            continue
        results[backend] = json.loads(line[2:])
        check("%s 后端生效" % backend, results[backend]["backend"] == backend,
              results[backend]["backend"])

    if len(results) == 2:
        a, b = results["cffi"], results["ctypes"]
        same = {k: (a.get(k) == b.get(k)) for k in
                ("status", "http", "ja4", "akamai", "ua", "accept_language")}
        check("两后端指纹输出完全一致", all(same.values()),
              str({k: (a.get(k), b.get(k)) for k, v in same.items() if not v}))


# --------------------------------------------------------------------------- #
# 9. 并发
# --------------------------------------------------------------------------- #
def test_async():
    section("9. AsyncSession 并发")
    async def run():
        async with nb_curl.AsyncSession(impersonate="chrome116", max_clients=8) as s:
            tasks = [s.get(PROBE, timeout=25) for _ in range(6)]
            return await asyncio.gather(*tasks)

    started = time.perf_counter()
    results = asyncio.run(run())
    elapsed = time.perf_counter() - started
    check("6 个并发全部 200", all(r.status_code == 200 for r in results),
          str([r.status_code for r in results]))
    print("       并发 6 请求耗时 %.2fs" % elapsed)


# --------------------------------------------------------------------------- #
# 10. 参数校验（离线，不打网络）
# --------------------------------------------------------------------------- #
def test_param_validation():
    section("10. 参数校验（取值范围，离线）")
    from nb_curl import tls
    from nb_curl.fingerprint import parse_ja3, parse_akamai, parse_diy_fp
    from nb_curl.const import resolve_http_version

    # --- 自省 API 与权威表规模一致（升级 BoringSSL 后表变了这里会提醒） ---
    check("套件表 34+3", len(tls.supported_ciphers()) == 34
          and len(tls.supported_tls13_ciphers()) == 3,
          "%d+%d" % (len(tls.supported_ciphers()), len(tls.supported_tls13_ciphers())))
    check("曲线表 9 个", len(tls.supported_groups()) == 9,
          str(len(tls.supported_groups())))
    check("签名算法表 16 个", len(tls.supported_signature_algorithms()) == 16,
          str(len(tls.supported_signature_algorithms())))
    check("扩展表 32 个", len(tls.supported_extensions()) == 32,
          str(len(tls.supported_extensions())))
    check("TLS 版本 1.0-1.3", tls.supported_tls_versions() == ("1.0", "1.1", "1.2", "1.3"),
          str(tls.supported_tls_versions()))
    check("证书压缩 3 种", set(tls.supported_cert_compression()) == {"brotli", "zlib", "zstd"},
          str(tls.supported_cert_compression()))

    # --- 合法输入必须能解析 ---
    good_ja3 = ("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
                "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0")
    try:
        ov = parse_ja3(good_ja3)
        check("合法 ja3 解析通过", ov.ciphers is not None and ov.extension_order is not None)
    except nb_curl.FingerprintError as exc:
        check("合法 ja3 解析通过", False, repr(exc))
    try:
        parse_akamai("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p")
        check("合法 akamai 解析通过", True)
    except nb_curl.FingerprintError as exc:
        check("合法 akamai 解析通过", False, repr(exc))
    try:
        parse_diy_fp({"tls_signature_algorithms": "rsa_pss_rsae_sha256:ecdsa_secp256r1_sha256",
                        "tls_cert_compression": "brotli,zstd",
                        "tls_min_version": "1.2",
                        "tls13_ciphers": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256",
                        "tls_extension_order": "0-10-13-51-43",
                        "tls_record_size_limit": 16384})
        check("合法 diy_fp 解析通过", True)
    except nb_curl.FingerprintError as exc:
        check("合法 diy_fp 解析通过", False, repr(exc))

    # --- 非法输入必须在解析期报错（不是建连期） ---
    bad_cases = [
        ("cipher 0xCCAC 不受支持", lambda: parse_ja3("771,49195-52396,0-23,29-23,0")),
        ("曲线 P-224 不受支持", lambda: parse_ja3("771,49195,0-23,21-29,0")),
        ("扩展 24(token_binding) 不受支持", lambda: parse_ja3("771,49195,0-23-24,29-23,0")),
        ("签名算法乱写", lambda: parse_diy_fp({"tls_signature_algorithms": ["rsa_pss_sha999"]})),
        ("TLS1.3 CCM 套件不受支持", lambda: parse_diy_fp({"tls13_ciphers": "TLS_AES_128_CCM_SHA256"})),
        ("证书压缩 lz4 不支持", lambda: parse_diy_fp({"tls_cert_compression": "lz4"})),
        ("TLS 版本 0.9 不支持", lambda: parse_diy_fp({"tls_min_version": "0.9"})),
        ("record_size_limit 超范围", lambda: parse_diy_fp({"tls_record_size_limit": 70000})),
        ("extension_order 带非法 id", lambda: parse_diy_fp({"tls_extension_order": "0-10-9999"})),
        ("stream_weight 超范围", lambda: parse_diy_fp({"http2_stream_weight": 999})),
        ("akamai SETTINGS id=9", lambda: parse_akamai("9:65536|15663105|0|masp")),
        ("akamai MAX_FRAME_SIZE 过小", lambda: parse_akamai("5:100|15663105|0|masp")),
        ("diy_fp 未知键", lambda: parse_diy_fp({"tls_no_such_key": 1})),
    ]
    for name, fn in bad_cases:
        try:
            fn()
            check(name, False, "竟然没报错")
        except nb_curl.FingerprintError:
            check(name, True)
        except Exception as exc:  # noqa: BLE001
            check(name, False, "异常类型不对: %r" % exc)

    # 报错消息可查（含参数名与查询入口）
    try:
        parse_diy_fp({"tls_cert_compression": "lz4"})
    except nb_curl.FingerprintError as exc:
        msg = str(exc)
        check("报错消息含参数名与取值提示",
              "tls_cert_compression" in msg and "brotli" in msg, msg)

    # --- 直接构造 FingerprintOverrides 也会被兜底校验 ---
    ov = nb_curl.FingerprintOverrides(ciphers="TLS_FAKE_CIPHER")
    try:
        ov.validate()
        check("直接构造对象兜底校验", False, "竟然没报错")
    except nb_curl.FingerprintError:
        check("直接构造对象兜底校验", True)

    # --- http_version ---
    ok_vals = [(None, None), ("default", None), ("1.0", 10), ("1.1", 11),
               ("2", 20), ("2tls", 21), ("2_prior_knowledge", 22), (0, 0),
               ("3", 30), ("3.0", 30), ("3only", 31), (30, 30), (31, 31),
               # 数值写法：与字符串别名等价（1 / 1.0 / 1.1 / 2 / 2.0 / 3 / 3.0）
               (1, 11), (1.0, 10), (1.1, 11), (2, 20), (2.0, 20), (3, 30), (3.0, 30)]
    for value, expect in ok_vals:
        try:
            got = resolve_http_version(value)
            check("http_version %r -> %r" % (value, expect), got == expect, str(got))
        except ValueError as exc:
            check("http_version %r -> %r" % (value, expect), False, repr(exc))
    for bad in ("4", "h2c", 99, 3.5, 2.5, "3.5"):
        try:
            resolve_http_version(bad)
            check("http_version %r 应报错" % (bad,), False, "竟然没报错")
        except ValueError:
            check("http_version %r 应报错" % (bad,), True)
    # Session 构造期就拒绝非法 http_version（不用等发请求）
    try:
        nb_curl.Session(http_version="h2c")
        check("Session 构造期拒绝非法 http_version", False, "竟然没报错")
    except ValueError:
        check("Session 构造期拒绝非法 http_version", True)


# --------------------------------------------------------------------------- #
# 11. xcctls 快照与 Python 预设
# --------------------------------------------------------------------------- #
_SNAPSHOT_FIXTURE = {
    "client_hello": {
        "version": 771,
        "cipher_suites": [
            "TLS_AES_128_GCM_SHA256 (4865)",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (49199)",
            "TLS_RSA_WITH_AES_128_GCM_SHA256 (156)",
        ],
        "extensions": [
            {"type": "server_name (0)"},
            {"type": "supported_groups (10)", "groups": ["X25519 (29)", "secp256r1 (23)"]},
            {"type": "signature_algorithms (13)",
             "algorithms": ["ecdsa_secp256r1_sha256 (1027)", "rsa_pss_rsae_sha256 (2052)"]},
            {"type": "compress_certificate (27)", "algorithms": ["zstd (3)"]},
            {"type": "application_settings (17613)", "protocols": ["h2"]},
            {"type": "supported_versions (43)", "versions": ["TLS 1.3 (772)", "TLS 1.2 (771)"]},
        ],
    },
    "http2": {
        "akamai": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
        "headers": {
            ":method": "GET",
            "user-agent": "TestAgent/1.0",
            "accept": "*/*",
            "accept-language": "xx-XX,xx;q=0.9",
        },
    },
}


def test_snapshot_and_presets():
    section("11. xcctls 快照（fp_file）与内置 chrome152")
    import tempfile
    from nb_curl.xcctls import parse_xcctls, load_fp_snapshot

    # --- 离线：解析快照 ---
    fp = parse_xcctls(_SNAPSHOT_FIXTURE)
    check("快照套件解析",
          fp.overrides.ciphers ==
          "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_128_GCM_SHA256"
          and fp.overrides.tls13_ciphers == "TLS_AES_128_GCM_SHA256",
          "ciphers=%r tls13=%r" % (fp.overrides.ciphers, fp.overrides.tls13_ciphers))
    check("快照曲线解析", fp.overrides.curves == "X25519:P-256", str(fp.overrides.curves))
    check("快照签名算法解析", fp.overrides.sig_hash_algs ==
          "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256", str(fp.overrides.sig_hash_algs))
    check("快照证书压缩解析", fp.overrides.cert_compression == "zstd",
          str(fp.overrides.cert_compression))
    check("快照 ALPS 解析", fp.overrides.enable_alps is True
          and fp.overrides.use_new_alps_codepoint is True)
    check("快照 akamai 解析", fp.overrides.http2_settings == "1:65536;2:0;4:6291456;6:262144"
          and fp.overrides.http2_pseudo_headers_order == "masp")
    check("快照请求头（伪头剔除）",
          [k for k, _ in fp.headers] == ["user-agent", "accept", "accept-language"],
          str(fp.headers))
    check("快照底座：陌生 UA 不选底座", fp.impersonate is None, str(fp.impersonate))

    # --- 离线：Chrome UA 自动选底座 ---
    chrome_fp = parse_xcctls({
        "client_hello": _SNAPSHOT_FIXTURE["client_hello"],
        "http2": {"akamai": _SNAPSHOT_FIXTURE["http2"]["akamai"],
                  "headers": {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                                            "Chrome/152.0.0.0 Safari/537.36"}},
    })
    check("Chrome UA 自动选底座 chrome152", chrome_fp.impersonate == "chrome152",
          str(chrome_fp.impersonate))

    # --- 离线：不支持的值要报规范错误 ---
    bad_ch = json.loads(json.dumps(_SNAPSHOT_FIXTURE["client_hello"]))
    bad_ch["extensions"][2]["algorithms"] = ["rsa_magic_sha999 (61439)"]
    try:
        parse_xcctls({"client_hello": bad_ch, "http2": _SNAPSHOT_FIXTURE["http2"]})
        check("快照含不支持签名算法应报错", False, "竟然没报错")
    except nb_curl.FingerprintError as exc:
        check("快照含不支持签名算法应报错",
              "0xEFFF" in str(exc) or "签名算法" in str(exc), str(exc))

    # --- 离线：文件加载（含 <pre> 包裹与缓存失效） ---
    with tempfile.TemporaryDirectory() as tmp:
        snap_path = os.path.join(tmp, "snap.json")
        with open(snap_path, "w", encoding="utf-8") as fh:
            fh.write("<html><body><pre>" + json.dumps(_SNAPSHOT_FIXTURE) + "</pre></body></html>")
        fp2 = load_fp_snapshot(snap_path)
        check("<pre> 包裹的快照可解析", fp2.overrides.curves == "X25519:P-256",
              str(fp2.overrides.curves))
        # 缓存：同一路径命中；改文件后（mtime/size 变化）重新解析
        fp3 = load_fp_snapshot(snap_path)
        check("同一路径复用缓存对象", fp2 is fp3)
        with open(snap_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "client_hello": _SNAPSHOT_FIXTURE["client_hello"],
                "http2": {"akamai": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
                          "headers": {"user-agent": "TestAgent/2.0"}},
            }))
        fp4 = load_fp_snapshot(snap_path)
        check("文件更新后重新解析", fp4 is not fp3
              and [v for k, v in fp4.headers if k == "user-agent"] == ["TestAgent/2.0"],
              str(fp4.headers))

    # --- 在线：真实快照回环（抓 chrome150 -> 存文件 -> fp_file 回放 -> 比对） ---
    # 注：不能用人工精简的 fixture——设置了 extension_order 后，未列入清单的
    # 扩展（如 key_share）会被 BoringSSL 全部不发，握手直接失败。真实快照
    # 包含全部扩展，回放才是有意义的验证。
    def _nogrease(items):
        return [i for i in items if "grease" not in str(i).lower()]

    def _ext_types(ch):
        return _nogrease([e.get("type", "") for e in ch.get("extensions", [])])

    def _ext_items(ch, prefix, key):
        return _nogrease([
            item for e in ch.get("extensions", [])
            if e.get("type", "").startswith(prefix)
            for item in (e.get(key) or [])
        ])

    data1 = probe(impersonate="chrome150")
    fp_live = parse_xcctls(data1)
    check("真实快照自动选底座 chrome150", fp_live.impersonate == "chrome150",
          str(fp_live.impersonate))
    check("真实快照默认关扩展随机排列", fp_live.overrides.permute_extensions is False,
          str(fp_live.overrides.permute_extensions))

    with tempfile.TemporaryDirectory() as tmp:
        snap_live = os.path.join(tmp, "snap_live.json")
        with open(snap_live, "w", encoding="utf-8") as fh:
            json.dump(data1, fh, ensure_ascii=False)
        data2 = probe(fp_file=snap_live)
        ch1, ch2 = data1.get("client_hello", {}), data2.get("client_hello", {})
        check("fp_file 回放请求成功且 UA 来自快照",
              (data2.get("http2", {}).get("headers", {}).get("user-agent") or "") ==
              (data1.get("http2", {}).get("headers", {}).get("user-agent") or ""),
              str(data2.get("http2", {}).get("headers", {}).get("user-agent")))
        check("fp_file 回放套件一致（GREASE 除外）",
              _nogrease(ch1.get("cipher_suites", [])) ==
              _nogrease(ch2.get("cipher_suites", [])))
        check("fp_file 回放曲线一致", _ext_items(ch1, "supported_groups", "groups") ==
              _ext_items(ch2, "supported_groups", "groups"))
        check("fp_file 回放签名算法一致",
              _ext_items(ch1, "signature_algorithms", "algorithms") ==
              _ext_items(ch2, "signature_algorithms", "algorithms"))
        check("fp_file 回放证书压缩一致",
              _ext_items(ch1, "compress_certificate", "algorithms") ==
              _ext_items(ch2, "compress_certificate", "algorithms"))
        check("fp_file 回放扩展顺序一致", _ext_types(ch1) == _ext_types(ch2),
              "%s vs %s" % (_ext_types(ch1), _ext_types(ch2)))
        check("fp_file 回放 akamai 一致",
              data1.get("http2", {}).get("akamai") == data2.get("http2", {}).get("akamai"))

    # --- 在线：impersonate 直接传 Fingerprint 对象 ---
    data3 = probe(impersonate=fp_live)
    check("impersonate=Fingerprint 可用且回放一致",
          _nogrease(data3.get("client_hello", {}).get("cipher_suites", [])) ==
          _nogrease(data1.get("client_hello", {}).get("cipher_suites", [])))
    with nb_curl.Session(impersonate=fp_live) as s:
        r = s.get(PROBE, timeout=25)
        check("Session(impersonate=Fingerprint) 可用", r.status_code == 200,
              str(r.status_code))

    # --- 在线：chrome152（C 内核内置） ---
    from nb_curl.impersonate import BUILTIN_TARGETS, ImpersonateTarget
    import typing
    check("chrome152 在 C 内置表中", "chrome152" in BUILTIN_TARGETS
          and nb_curl.is_available("chrome152"))
    check("available_targets 含 chrome152", "chrome152" in nb_curl.available_targets())
    check("Literal 提示与内置表一致",
          set(typing.get_args(ImpersonateTarget)) == set(BUILTIN_TARGETS))

    data = probe(impersonate="chrome152")
    ch, h2 = data.get("client_hello", {}), data.get("http2", {})
    ua = h2.get("headers", {}).get("user-agent", "")
    check("chrome152 UA 为 152 正式版", "Chrome/152" in ua and "Headless" not in ua, ua[:90])
    sigs = next((e.get("algorithms") for e in ch.get("extensions", [])
                 if e.get("type", "").startswith("signature_algorithms")), [])
    check("chrome152 签名算法含 mldsa", any("mldsa44" in s for s in sigs), str(sigs[:4]))
    check("chrome152 签名算法头部带 GREASE",
          any("GREASE" in s for s in sigs[:2]), str(sigs[:3]))
    check("chrome152 带 trust_anchors(51764) 扩展",
          any("51764" in e.get("type", "") for e in ch.get("extensions", [])),
          str([e.get("type") for e in ch.get("extensions", [])]))
    check("chrome152 akamai 与真实 Chrome 一致",
          (h2.get("akamai") or "").startswith("1:65536;2:0;4:6291456;6:262144"),
          str(h2.get("akamai")))
    check("chrome152 ECH 生效",
          any("encrypted_client_hello" in e.get("type", "") for e in ch.get("extensions", [])))

    # diy_fp 显式下发 GREASE 签名算法与 trust_anchors 同样可用
    data_diy = probe(impersonate="chrome150",
                     diy_fp={"tls_grease_sigalgs": True, "tls_trust_anchors": ""})
    ch_diy = data_diy.get("client_hello", {})
    sigs_diy = next((e.get("algorithms") for e in ch_diy.get("extensions", [])
                     if e.get("type", "").startswith("signature_algorithms")), [])
    check("chrome150+diy_fp 也能带 GREASE 签名算法",
          any("GREASE" in s for s in sigs_diy[:2]), str(sigs_diy[:3]))
    check("chrome150+diy_fp 也能带 trust_anchors",
          any("51764" in e.get("type", "") for e in ch_diy.get("extensions", [])))
    # tls_signature_algorithms 里直接写 GREASE 条目 -> 等价于开关
    data_g = probe(impersonate="chrome150",
                   diy_fp={"tls_signature_algorithms":
                           "GREASE:mldsa44:mldsa65:mldsa87:ecdsa_secp256r1_sha256:"
                           "rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:"
                           "rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:"
                           "rsa_pkcs1_sha512"})
    sigs_g = next((e.get("algorithms") for e in
                   data_g.get("client_hello", {}).get("extensions", [])
                   if e.get("type", "").startswith("signature_algorithms")), [])
    check("签名算法列表写 GREASE 条目也生效",
          any("GREASE" in s for s in sigs_g[:2]), str(sigs_g[:3]))

    # 扩展顺序随机：同 Session 连发 3 次，至少一次顺序不同
    orders = []
    with nb_curl.Session(impersonate="chrome152") as s:
        for _ in range(3):
            d = json.loads(s.get(PROBE, timeout=25).text)
            orders.append(tuple(e.get("type") for e in d["client_hello"]["extensions"]))
    check("chrome152 扩展顺序随机排列", len(set(orders)) > 1, "三次顺序完全相同")


# --------------------------------------------------------------------------- #
# 12. proxy / proxies 参数语义
# --------------------------------------------------------------------------- #
def test_proxy_params():
    section("12. proxy / proxies 参数（两种写法等价可用）")
    from nb_curl.session import Session

    url_https = "https://example.com/a"
    url_http = "http://example.com/a"
    p = "socks5h://user:pass@1.2.3.4:1080"
    pd = {"http": "socks5h://user:pass@1.2.3.4:1080",
          "https": "socks5h://user:pass@1.2.3.4:1080"}

    # 会话级：proxy（单字符串）与 proxies（dict）等价
    s1 = Session(proxy=p)
    s2 = Session(proxies=pd)
    check("Session(proxy=) 生效", s1._proxy_for(url_https, None) == p)
    check("Session(proxies=) 按 scheme 生效",
          s2._proxy_for(url_https, None) == pd["https"]
          and s2._proxy_for(url_http, None) == pd["http"])

    # 请求级覆盖会话级；proxy 优先于 proxies
    s3 = Session(proxy=p, proxies={"https": "http://old:1"})
    check("请求级 proxy 覆盖会话级",
          s3._proxy_for(url_https, "socks5h://new:2") == "socks5h://new:2")
    check("请求级 proxies 覆盖会话级",
          s3._proxy_for(url_https, None, {"https": "socks5h://req:3"}) == "socks5h://req:3")
    check("proxy 优先于 proxies",
          s3._proxy_for(url_https, "socks5h://a:1", {"https": "socks5h://b:2"}) == "socks5h://a:1")

    # proxies 支持字符串形式与 "all" 键
    s4 = Session(proxies="socks5h://all-traffic:9")
    check("proxies 传字符串也生效", s4._proxy_for(url_https, None) == "socks5h://all-traffic:9")
    s5 = Session(proxies={"all": "socks5h://any:9"})
    check("proxies 支持 all 键", s5._proxy_for(url_https, None) == "socks5h://any:9")

    # 不设代理时为 None；"" 是"显式禁用"（覆盖环境变量），区别于 None 的"跟随环境"
    s6 = Session()
    check("默认无代理", s6._proxy_for(url_https, None) is None)
    check('空字符串代理 = 显式禁用（返回 ""，屏蔽环境变量）',
          s6._proxy_for(url_https, "") == "")

    # 在线验证（需要真实代理时设 NB_CURL_TEST_PROXY）
    real_proxy = os.environ.get("NB_CURL_TEST_PROXY")
    if real_proxy:
        try:
            r = nb_curl.get(PROBE, proxy=real_proxy, impersonate="chrome152", timeout=30)
            check("经 proxy 在线请求成功", r.status_code == 200, str(r.status_code))
            r = nb_curl.get(PROBE, proxies={"https": real_proxy},
                          impersonate="chrome152", timeout=30)
            check("经 proxies 在线请求成功", r.status_code == 200, str(r.status_code))
        except Exception as exc:  # noqa: BLE001
            check("经代理在线请求成功", False, repr(exc))
    else:
        print("  [SKIP] 在线代理测试（设 NB_CURL_TEST_PROXY 后启用）")


# --------------------------------------------------------------------------- #
def test_resolve():
    section("13. DNS 覆盖（resolve=，等价 curl 的 --resolve）")
    entries = nb_curl.session._resolve_entries
    check("dict 形式生成 host:port:addr 条目",
          entries({"a.com:443": "1.2.3.4"}) == ["a.com:443:1.2.3.4"], str(entries({"a.com:443": "1.2.3.4"})))
    check("一个域名可给多个地址",
          entries({"a.com:443": ["1.1.1.1", "2.2.2.2"]}) == ["a.com:443:1.1.1.1,2.2.2.2"])
    check("原始条目原样透传",
          entries(["+a.com:443:1.2.3.4", "-b.com:443"]) == ["+a.com:443:1.2.3.4", "-b.com:443"])
    try:
        entries({"a.com": "1.2.3.4"})
        check("键缺端口时报错", False, "没有报错")
    except nb_curl.NbCurlError:
        check("键缺端口时报错", True)

    # 真实生效：拿一个 DNS 永远解析不出来的保留域名，钉到本地回显服务。
    with LocalServer() as srv:
        fake = "nb-curl-resolve.invalid"
        url = "http://%s:%d/echo" % (fake, srv.port)
        r = nb_curl.get(url, impersonate="chrome116", timeout=10,
                        resolve={"%s:%d" % (fake, srv.port): "127.0.0.1"})
        check("不存在的域名被钉到本地后请求成功", r.status_code == 200, str(r.status_code))
        try:
            nb_curl.get(url, impersonate="chrome116", timeout=10)
            check("不设 resolve 时该域名解析失败", False, "竟然成功了")
        except Exception:  # noqa: BLE001
            check("不设 resolve 时该域名解析失败", True)


# --------------------------------------------------------------------------- #
# 14. curl 错误码透出（离线）
# --------------------------------------------------------------------------- #
def test_curl_error_codes():
    section("14. curl 错误码透出（CURLcode 数值 + 符号名）")
    from nb_curl._curle_generated import CurlE, curl_error_name
    from nb_curl.exceptions import RequestError

    check("错误码名表 56 -> CURLE_RECV_ERROR", curl_error_name(56) == "CURLE_RECV_ERROR",
          curl_error_name(56))
    check("错误码名表 28 -> CURLE_OPERATION_TIMEDOUT",
          curl_error_name(28) == "CURLE_OPERATION_TIMEDOUT", curl_error_name(28))
    check("CurlE 枚举值与 curl.h 一致（RECV_ERROR=56）", int(CurlE.RECV_ERROR) == 56)
    check("未知错误码返回 CURLE_<n>", curl_error_name(999) == "CURLE_999",
          curl_error_name(999))

    e = RequestError("Failure when receiving data from the peer", 56)
    check("RequestError.curl_name 属性", e.curl_name == "CURLE_RECV_ERROR", str(e.curl_name))
    r = repr(e)
    check("RequestError repr 带码与符号名", "56" in r and "CURLE_RECV_ERROR" in r, r)

    # 报错文案要"自解释"：带符号名 + 中文说明 + libcurl 官方错误码手册链接
    from nb_curl.exceptions import CURL_ERROR_DOC, curl_error_detail, curl_hint

    check("常用错误码有中文说明", "证书" in curl_hint(60), curl_hint(60))
    check("未知错误码没有中文说明（回退符号名）", curl_hint(999) == "", repr(curl_hint(999)))
    detail = curl_error_detail(60, "SSL peer certificate or SSH remote key was not OK")
    check("错误文案带官方手册链接", CURL_ERROR_DOC in detail, detail)
    check("错误文案带符号名与中文说明",
          "CURLE_PEER_FAILED_VERIFICATION" in detail and "证书" in detail, detail)

    # 线上路径也要是新文案：真跑一次必然失败的请求（本地 discard 端口，不会真连出去）
    try:
        with nb_curl.Session(timeout=5) as s:
            s.get("https://127.0.0.1:9/", verify=False)
        check("失败请求抛出的异常带手册链接", False, "竟然没报错")
    except RequestError as exc:
        check("失败请求抛出的异常带手册链接",
              CURL_ERROR_DOC in str(exc) and "curl " in str(exc), str(exc))
        check("失败请求抛出的异常保留了错误码数值", isinstance(exc.code, int),
              repr(getattr(exc, "code", None)))


# --------------------------------------------------------------------------- #
# 14b. 代理失败的细粒度文案（CURLE_PROXY 97 / CURLINFO_PROXY_ERROR）
# --------------------------------------------------------------------------- #
def test_proxy_error_detail():
    """第 14b 节：97 不能只有一句 proxy handshake error。

    回归背景：以前无论代理坏在哪一步，报错都长一个样，看不出是端口不对、
    协议配错还是被代理拒绝，也看不出请求到底走了哪个代理。
    """
    import socket
    import threading

    from nb_curl.const import CURLINFO_PROXY_ERROR, proxy_error_name
    from nb_curl.exceptions import (CURL_ERROR_DOC, curl_error_detail,
                                    curl_hint, curl_proxy_hint)
    from nb_curl.session import _env_lookup, _env_proxy_names, _proxy_in_use

    # -- 常量表 --
    check("CURLINFO_PROXY_ERROR = CURLINFO_LONG + 59",
          CURLINFO_PROXY_ERROR == 0x200000 + 59, CURLINFO_PROXY_ERROR)
    check("代理子原因名表 2 -> CURLPX_BAD_VERSION",
          proxy_error_name(2) == "CURLPX_BAD_VERSION", proxy_error_name(2))
    check("代理子原因名表越界回退", proxy_error_name(999) == "CURLPX_999",
          proxy_error_name(999))

    # -- 中文说明 --
    check("97 有中文说明且指向代理配置", "代" in curl_hint(97), curl_hint(97))
    check("子原因 2 有中文说明", curl_proxy_hint(2) != "", curl_proxy_hint(2))
    check("未知子原因没有中文说明（回退空串）", curl_proxy_hint(999) == "",
          repr(curl_proxy_hint(999)))

    # -- 文案拼装：带子原因 + 带"走的哪个代理" --
    d = curl_error_detail(97, "proxy handshake error",
                          proxy_error=2, proxy_in_use="socks5://127.0.0.1:1080")
    check("97 文案带 CURLE_PROXY 与手册链接",
          "CURLE_PROXY" in d and CURL_ERROR_DOC in d, d)
    check("97 文案带代理子原因符号名", "CURLPX_BAD_VERSION" in d, d)
    check("97 文案指出实际使用的代理", "socks5://127.0.0.1:1080" in d, d)
    check("97 文案给出禁用代理的办法", 'proxy=""' in d, d)

    # 不传附加信息时必须与老文案兼容（ws.py / options.py 还是这样调）
    plain = curl_error_detail(97, "proxy handshake error")
    check("不传附加信息时不带子原因行", "CURLPX" not in plain, plain)
    check("不传附加信息时仍是单行", "\n" not in plain, plain)

    # 非代理错误不该冒出代理子原因
    t = curl_error_detail(28, "Timeout was reached")
    check("非 97 不出现代理子原因字样", "CURLPX" not in t, t)

    # -- 环境变量代理的名字顺序（照 libcurl lib/proxy.c）--
    names_https = _env_proxy_names("https://a.example/")
    names_http = _env_proxy_names("http://a.example/")
    check("https 先看 https_proxy 再看 all_proxy",
          names_https[:2] == ["https_proxy", "HTTPS_PROXY"]
          and names_https[-1] == "ALL_PROXY", names_https)
    check("http 只看小写 http_proxy（curl 有意忽略大写）",
          names_http[0] == "http_proxy" and "HTTP_PROXY" not in names_http, names_http)

    # -- _env_lookup：读环境变量的方式必须与 C 端一致 --
    #    Windows 上不能读 os.environ：环境块允许同名不同大小写两项共存，
    #    而 os.environ 把键统一转成大写，pop 一次只删掉一项，剩下那项 libcurl 照样看得见。
    check("_env_lookup 能读到 PATH", bool(_env_lookup("PATH")), _env_lookup("PATH"))
    check("_env_lookup 对不存在的名字返回 None",
          _env_lookup("NB_CURL_NO_SUCH_VAR_8231") is None)
    os.environ["NB_CURL_EMPTY_VAR"] = ""
    try:
        check("_env_lookup 把空值当作不存在（与 curl 相同）",
              _env_lookup("NB_CURL_EMPTY_VAR") is None,
              repr(_env_lookup("NB_CURL_EMPTY_VAR")))
    finally:
        os.environ.pop("NB_CURL_EMPTY_VAR", None)
    if os.name == "nt":
        os.environ["nb_curl_case_probe"] = "found-me"
        try:
            check("Windows 上 _env_lookup 不分大小写（C 端就是这么查的）",
                  _env_lookup("NB_CURL_CASE_PROBE") == "found-me",
                  repr(_env_lookup("NB_CURL_CASE_PROBE")))
        finally:
            os.environ.pop("nb_curl_case_probe", None)

    # -- _proxy_in_use：显式优先；""= 显式禁用，连环境变量也不看 --
    check("空串 = 显式禁用，不报代理", _proxy_in_use("", "http://a.example/") is None)
    check("显式代理原样报出",
          _proxy_in_use("http://127.0.0.1:1", "http://a.example/")
          == "http://127.0.0.1:1")

    # -- 端到端：把 socks5 指向一个"其实是 HTTP"的端口 --
    #    libcurl 会在 SOCKS 握手第一步就发现版本号不对 -> 97 / CURLPX_BAD_VERSION
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    keep = [srv]

    def _serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            keep.append(conn)
            try:
                conn.settimeout(5)
                conn.recv(4096)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            except OSError:
                pass

    threading.Thread(target=_serve, daemon=True).start()
    time.sleep(0.3)

    proxy = "socks5://127.0.0.1:%d" % port
    try:
        nb_curl.get("http://example.com/", proxy=proxy, timeout=6)
        check("假 SOCKS 端口抛异常", False, "竟然没报错")
    except nb_curl.ProxyError as exc:
        check("代理握手失败抛 ProxyError（且仍是 RequestError）",
              isinstance(exc, nb_curl.RequestError))
        check("代理握手失败带错误码 97", exc.code == 97, repr(exc.code))
        check("代理握手失败文案含子原因符号名", "CURLPX_BAD_VERSION" in str(exc), str(exc))
        check("代理握手失败文案含实际代理地址", proxy in str(exc), str(exc))
    except nb_curl.NbCurlError as exc:
        check("代理握手失败抛 ProxyError", False, "抛了 %r" % exc)
    finally:
        for s in keep:
            try:
                s.close()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# 15. 公开 API 的参数声明（IDE 补全与跳转依赖它）
# --------------------------------------------------------------------------- #
def test_api_signatures():
    """第 15 节：公开入口的参数必须**静态可推断**，且不能静默吞掉拼错的参数名。

    这一节保护的是开发体验与参数表的完整性，不是运行时行为：

    * 参数只在 `nb_curl/params.py` 的 TypedDict 里声明一次，所有公开入口
      （`Session.get` / `nb_curl.get` / `AsyncSession.get` …）都用
      `**options: Unpack[...]` 接收。写成裸 `**kwargs` 就既没补全也没 Ctrl+P，
      所以这里逐个断言 Unpack 注解还在；
    * `**options` 会把拼错的参数名悄悄吞掉，所以必须自己校验并抛 TypeError；
    * 参数表与实现必须同步：`session.py` 里 `options.get("xxx")` / `_pick(options, "xxx")`
      用到的键，一个都不能漏出参数表；参数表里的键也不能有谁都没读的。
    """
    import inspect
    import re

    from nb_curl import params as P

    section("15. 公开 API 参数声明（IDE 补全与跳转依赖它）")

    check("请求级参数表有 30 项以上", len(P.REQUEST_KEYS) >= 30, str(len(P.REQUEST_KEYS)))
    check("http_version 在参数表里", "http_version" in P.REQUEST_KEYS)
    check("resolve 在参数表里", "resolve" in P.REQUEST_KEYS)
    check("tcp / ttl / timestamps / tcp_warn 在参数表里",
          {"tcp", "ttl", "timestamps", "tcp_warn"} <= P.REQUEST_KEYS)
    check("tcp 的 dict 形式声明了 window/order/mss/wscale",
          set(P.TcpShape.__annotations__) == {"window", "order", "mss", "wscale"},
          repr(sorted(P.TcpShape.__annotations__)))
    check("会话独有参数 5 项",
          P.SESSION_ONLY_KEYS == {"default_headers", "max_clients", "max_retries",
                                 "debug", "allow_dangerous_options"},
          repr(sorted(P.SESSION_ONLY_KEYS)))
    check("params 模块的说明能渲染出来",
          "http_version:" in P.describe("request") and "wscale:" in P.describe("tcp"))

    # 参数只在 params.py 声明一次，入口必须带 Unpack 注解（这就是 IDE 补全的来源）
    entries = []
    for name in ("request", "get", "post", "put", "patch", "delete", "head", "options"):
        entries.append(("Session.%s" % name, getattr(nb_curl.Session, name)))
        entries.append(("AsyncSession.%s" % name, getattr(nb_curl.AsyncSession, name)))
        entries.append(("nb_curl.%s" % name, getattr(nb_curl, name)))

    for label, fn in entries:
        annotation = str(inspect.signature(fn).parameters["options"].annotation)
        ok = ("Unpack[" in annotation
              and ("RequestOptions" in annotation or "SessionOptions" in annotation))
        check("%s 的参数带 Unpack 类型" % label, ok, annotation)

    check("_request 也走 options（不再复刻参数表）",
          list(inspect.signature(nb_curl.Session._request).parameters) ==
          ["self", "method", "url", "options"])

    # **options 吞掉的 TypeError 得自己补回来
    for label, call in (("Session.get", lambda: nb_curl.Session().get("https://x/", typo=1)),
                        ("Session()", lambda: nb_curl.Session(typo=1)),
                        ("nb_curl.get", lambda: nb_curl.get("https://x/", typo=1))):
        try:
            call()
            check("%s 传未知参数抛 TypeError" % label, False, "竟然没报错")
        except TypeError as exc:
            check("%s 传未知参数抛 TypeError" % label, "typo" in str(exc), str(exc))

    async def _async_typo():
        async with nb_curl.AsyncSession() as asession:
            await asession.get("https://x/", typo=1)

    try:
        asyncio.run(_async_typo())
        check("AsyncSession.get 传未知参数抛 TypeError", False, "竟然没报错")
    except TypeError as exc:
        check("AsyncSession.get 传未知参数抛 TypeError", "typo" in str(exc), str(exc))

    # 参数表 <-> 实现 的漂移守卫（ws_connect 另有 subprotocol 这个专用键）
    session_src = open(os.path.join(os.path.dirname(nb_curl.__file__), "session.py"),
                       encoding="utf-8").read()
    extra = {"subprotocol"}
    read_keys = set(re.findall(r'options\.get\("([a-z0-9_]+)"\)', session_src))
    read_keys |= set(re.findall(r'_pick\(options, "([a-z0-9_]+)"', session_src))
    read_keys |= set(re.findall(r'options\[["\']([a-z0-9_]+)["\']\]', session_src))
    read_keys -= extra
    check("实现里读的每个参数都在参数表里",
          not (read_keys - P.REQUEST_KEYS), repr(sorted(read_keys - P.REQUEST_KEYS)))
    check("参数表里没有谁都没读的键",
          not (P.REQUEST_KEYS - read_keys), repr(sorted(P.REQUEST_KEYS - read_keys)))
    check("会话独有参数都被真的读了",
          set(re.findall(r'_session_default\(options, "([a-z_]+)"\)', session_src))
          >= P.SESSION_ONLY_KEYS)

    check("异步入口是协程函数",
          inspect.iscoroutinefunction(nb_curl.AsyncSession.get))
    check("模块级没有 __getattr__（有会让 IDE 静态解析失效）",
          "__getattr__" not in vars(nb_curl))
    check("py.typed 标记存在（PEP 561）",
          os.path.exists(os.path.join(os.path.dirname(nb_curl.__file__), "py.typed")))


# --------------------------------------------------------------------------- #
# 16. 信任锚（trust_anchors 51764）
# --------------------------------------------------------------------------- #
# Chrome 内置根存储的 28 项 trust anchor ID（2026-09-22 从真实 Chrome 152 抓包
# 解出；与 Chromium net/data/ssl/chrome_root_store/root_store.textproto 的
# trust_anchor_id 字段一一对应）。
_CHROME_ANCHORS = frozenset((
    "52580.200109.1.10", "44947.2.1", "52580.200109.1.7", "11129.9.11",
    "44947.2.6", "11129.9.5", "11129.9.10", "44947.2.18",
    "52580.200109.1.13", "11129.9.8", "11129.9.13", "11129.9.12",
    "52580.200109.1.19", "52580.200109.1.12", "44947.2.19",
    "52580.200109.1.9", "11129.9.4", "11129.9.1", "52580.200109.1.18",
    "11129.9.15", "44947.2.13", "52580.200109.1.8", "44947.2.14",
    "11129.9.6", "44947.2.15", "52580.200109.1.11", "11129.9.7",
    "44947.2.20",
))

# 线上抓到的真载荷（Chrome 152 某次运行使用的排列，186 字节 / 28 项）
_TA_WIRE_HEX = (
    "00b804d67909040582df13020d08839a648c9b2d010908839a648c9b2d01120582df13020f"
    "08839a648c9b2d010704d679090504d679090a0582df1302120582df13020e0582df130213"
    "04d679090b04d679090c08839a648c9b2d010c08839a648c9b2d010804d679090d04d6790901"
    "04d679090f0582df13021408839a648c9b2d010d0582df13020108839a648c9b2d011304d679"
    "090704d679090608839a648c9b2d010a0582df13020604d679090808839a648c9b2d010b"
)


def _ta_decode(blob: bytes) -> list:
    """trust_anchors 线格式 -> OID 列表（u16 总长 + 若干 u8 长度 + RELATIVE-OID）。"""
    total = int.from_bytes(blob[:2], "big")
    body, pos, out = blob[2:2 + total], 0, []
    while pos < len(body):
        ln = body[pos]
        pos += 1
        arcs, value = [], 0
        for byte in body[pos:pos + ln]:
            value = (value << 7) | (byte & 0x7F)
            if not byte & 0x80:
                arcs.append(value)
                value = 0
        out.append(".".join(str(a) for a in arcs))
        pos += ln
    return out


def _ch_extensions(record: bytes) -> dict:
    """从一条 TLS 记录里解析 ClientHello 的扩展表 {ext_id: 原始载荷}。"""
    hs = record[5:]                                   # 去掉 TLS 记录头
    if hs[0] != 1:
        raise RuntimeError("第一条握手不是 ClientHello: type=%d" % hs[0])
    ch = hs[4:]                                       # 去掉握手头
    p = 2 + 32                                        # version + random
    p += 1 + ch[p]                                    # session_id
    p += 2 + int.from_bytes(ch[p:p + 2], "big")       # cipher_suites
    p += 1 + ch[p]                                    # compression_methods
    end = p + 2 + int.from_bytes(ch[p:p + 2], "big")
    p += 2
    exts = {}
    while p + 4 <= end:
        eid = int.from_bytes(ch[p:p + 2], "big")
        elen = int.from_bytes(ch[p + 2:p + 4], "big")
        exts[eid] = ch[p + 4:p + 4 + elen]
        p += 4 + elen
    return exts


def _grab_client_hello(**kwargs) -> dict:
    """只收不答的 TCP 监听，解析 nb_curl 发来的第一条 ClientHello 的扩展表。

    不需要证书、也不完成握手，因此既不依赖外网，也不依赖 xcctls 是否把
    51764 的载荷 dump 出来（它从来不 dump——这正是当初预设被写成空串的原因）。
    """
    import socket
    import threading

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    box = {}

    def _serve():
        try:
            conn, _ = srv.accept()
            conn.settimeout(8)
            buf = b""
            while len(buf) < 5:
                chunk = conn.recv(4096)
                if not chunk:
                    raise RuntimeError("客户端在发出握手前就断开了")
                buf += chunk
            need = 5 + int.from_bytes(buf[3:5], "big")
            while len(buf) < need:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
            box["record"] = buf[:need]
            conn.close()
        except Exception as exc:  # noqa: BLE001
            box["error"] = exc
        finally:
            try:
                srv.close()
            except OSError:
                pass

    th = threading.Thread(target=_serve, daemon=True)
    th.start()
    try:
        nb_curl.get("https://127.0.0.1:%d/" % port, verify=False, timeout=8, **kwargs)
    except Exception:  # noqa: BLE001
        pass                        # 只收不答，客户端必然失败，属预期
    th.join(10)
    if "record" not in box:
        raise RuntimeError("没拿到 ClientHello: %r" % (box.get("error"),))
    return _ch_extensions(box["record"])


def test_trust_anchors():
    section("16. 信任锚（trust_anchors 51764）")
    import warnings
    from nb_curl.xcctls import _decode_trust_anchors, parse_xcctls

    # --- 离线：线格式解码 ---
    decoded = _decode_trust_anchors(_TA_WIRE_HEX)
    check("线上真载荷解出 28 项", len(decoded.split(",")) == 28,
          str(len(decoded.split(","))))
    check("解码结果 = Chrome 内置根存储",
          set(decoded.split(",")) == _CHROME_ANCHORS,
          str(sorted(set(decoded.split(",")) ^ _CHROME_ANCHORS)))
    check("空列表编码 0000 解出 0 项", _decode_trust_anchors("0000") == "")

    def _snap(data_hex):
        return {"client_hello": {"cipher_suites": [], "extensions": [
            {"type": "trust_anchors (51764)", "data_hex": data_hex}]}, "http2": {}}

    # --- 离线：没载荷 != 空列表（这正是把预设写成空串的那个 bug） ---
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        fp_empty = parse_xcctls(_snap(""), base_impersonate=None)
    check("data_hex 为空时不覆盖 trust_anchors（只告警）",
          fp_empty.overrides.trust_anchors is None
          and any("trust_anchors" in str(w.message) for w in caught),
          repr(fp_empty.overrides.trust_anchors))
    check("data_hex 为 0000 时按空列表写入",
          parse_xcctls(_snap("0000"), base_impersonate=None)
          .overrides.trust_anchors == "")
    check("有载荷时按载荷写入",
          parse_xcctls(_snap(_TA_WIRE_HEX), base_impersonate=None)
          .overrides.trust_anchors == decoded)

    # --- 本机环回：预设真把 28 项发出去，且一次运行内排列固定 ---
    try:
        seen = [_grab_client_hello(impersonate="chrome152").get(51764)
                for _ in range(3)]
        check("chrome152 预设发出 trust_anchors(51764)",
              all(x is not None for x in seen),
              str([None if x is None else len(x) for x in seen]))
        check("预设信任锚不是空列表",
              all(x not in (None, b"\x00\x00") for x in seen),
              repr(seen[0]))
        orders = [_ta_decode(x) for x in seen if x]
        check("预设信任锚是完整 28 项", all(len(o) == 28 for o in orders),
              str([len(o) for o in orders]))
        check("预设信任锚集合 = Chrome 内置根存储",
              bool(orders) and all(set(o) == _CHROME_ANCHORS for o in orders))
        check("同一次运行内 3 条连接排列完全相同",
              len({tuple(o) for o in orders}) == 1,
              "种数=%d" % len({tuple(o) for o in orders}))
    except Exception as exc:  # noqa: BLE001
        check("chrome152 预设信任锚环回验证", False, repr(exc))




# --------------------------------------------------------------------------- #
# 17. TCP 层画像（JA4T，socket 级）
# --------------------------------------------------------------------------- #
def test_tcp():
    section("17. TCP 层画像（JA4T，socket 级设定）")
    import inspect
    import importlib
    import warnings as _w

    from nb_curl import tcp as tcpmod

    # --- 解析：JA4T 四段 ---
    p = tcpmod.parse_tcp_profile("64240_2-1-3-1-1-4_1400_8")
    check("JA4T 四段串解析正确",
          (p.window, p.order, p.mss, p.wscale) == (64240, "2-1-3-1-1-4", 1400, 8),
          repr(p))
    check("parse_tcp_profile 不带 ttl / timestamp",
          p.ttl is None and p.timestamp is None, repr(p))

    # --- 组合：三个参数全空 = 不启用 ---
    check("tcp / ttl / timestamps 全空 => 不启用（None）",
          tcpmod.build_tcp_profile() is None)

    # --- dict 形式：只给关心的字段 ---
    with _w.catch_warnings():
        _w.simplefilter("ignore")
        pd = tcpmod.build_tcp_profile({"window": 65535, "wscale": 8})
    check("dict 形式只给两个字段",
          (pd.window, pd.wscale, pd.order, pd.mss) == (65535, 8, None, None), repr(pd))

    # --- 只给 ttl / timestamps ---
    with _w.catch_warnings():
        _w.simplefilter("ignore")
        pt = tcpmod.build_tcp_profile(ttl=64, timestamps=False)
    check("只给 ttl / timestamps 也能建画像",
          pt is not None and pt.ttl == 64 and pt.timestamp == 0
          and pt.window is None, repr(pt))

    # --- 格式 / 越界 -> TCPShapeError（不是警告） ---
    bad_cases = [
        ("四段不足", "64240_2-1-3-1-1-4_1400"),
        ("段数过多", "64240_2-1-3-1-1-4_1400_8_9"),
        ("window 为 0", "0_2-1-3-1-1-4_1400_8"),
        ("window 超 65535", "65536_2-1-3-1-1-4_1400_8"),
        ("mss 低于 536", "65535_2-1-3-1-1-4_100_8"),
        ("wscale 超 14", "65535_2-1-3-1-1-4_1400_15"),
        ("order 非数字序列", "64240_a-b-c_1400_8"),
        ("window 非数字", "abc_2-1-3-1-1-4_1400_8"),
    ]
    for name, spec in bad_cases:
        try:
            tcpmod.parse_tcp_profile(spec)
            check("非法画像 %s 抛 TCPShapeError" % name, False, "竟然没抛")
        except nb_curl.TCPShapeError:
            check("非法画像 %s 抛 TCPShapeError" % name, True)
        except Exception as exc:  # noqa: BLE001
            check("非法画像 %s 抛 TCPShapeError" % name, False, "抛了 %r" % exc)

    for name, kwargs in (("ttl=0", {"ttl": 0}), ("ttl=256", {"ttl": 256}),
                         ("ttl 非整数", {"ttl": "64"}),
                         ("timestamps 非布尔", {"timestamps": 7}),
                         ("tcp 类型不对", {"tcp": 123})):
        try:
            tcpmod.build_tcp_profile(**kwargs)
            check("非法参数 %s 抛 TCPShapeError" % name, False, "竟然没抛")
        except nb_curl.TCPShapeError:
            check("非法参数 %s 抛 TCPShapeError" % name, True)
        except Exception as exc:  # noqa: BLE001
            check("非法参数 %s 抛 TCPShapeError" % name, False, "抛了 %r" % exc)

    # ------------------------------------------------------------------ #
    # 核心不变量：做不到的项**绝不下发**，本机默认窗口保持不变
    # （回归：旧实现会把 Windows 默认窗口 64240 偷偷改成 65535）
    # ------------------------------------------------------------------ #
    with _w.catch_warnings(record=True) as rec:
        _w.simplefilter("always")
        prof = tcpmod.build_tcp_profile("64240_2-1-3-1-1-4_1400_8", ttl=64)
        plan = tcpmod.plan_rcvbuf(prof)
    check("window/wscale 无法同时达成时 SO_RCVBUF 绝不下发（默认窗口不变）",
          plan is None, "plan=%r" % (plan,))
    check("该情况下给出了 TCPShapeWarning",
          any(issubclass(x.category, nb_curl.TCPShapeWarning) for x in rec),
          "收到 %d 条" % len(rec))

    # 能做到的组合必须能给出具体 rcvbuf
    with _w.catch_warnings():
        _w.simplefilter("ignore")
        prof_ok = tcpmod.build_tcp_profile({"window": 65535, "wscale": 8})
        plan_ok = tcpmod.plan_rcvbuf(prof_ok)
    check("window=65535 + wscale=8 能算出 rcvbuf",
          plan_ok == (1 << 23), "plan=%r" % (plan_ok,))

    # 只给 ttl / mss / timestamps 时绝不碰窗口
    with _w.catch_warnings():
        _w.simplefilter("ignore")
        plan_ttl = tcpmod.plan_rcvbuf(tcpmod.build_tcp_profile(ttl=64))
    check("只给 ttl 时不碰 SO_RCVBUF", plan_ttl is None, "plan=%r" % (plan_ttl,))

    # ------------------------------------------------------------------ #
    # 警告可关（三种关法）
    # ------------------------------------------------------------------ #
    target = "64240_2-1-3-1-1-4_1400_8"

    with _w.catch_warnings(record=True) as rec:
        _w.simplefilter("always")
        before = nb_curl.set_tcp_warnings(False)
        try:
            tcpmod.build_tcp_profile(target, ttl=64)
        finally:
            nb_curl.set_tcp_warnings(before)
    check("set_tcp_warnings(False) 全局关掉平台警告", len(rec) == 0,
          "仍有 %d 条" % len(rec))
    check("set_tcp_warnings 返回改之前的状态", before is True, repr(before))

    with _w.catch_warnings(record=True) as rec:
        _w.simplefilter("ignore", nb_curl.TCPShapeWarning)
        tcpmod.build_tcp_profile(target, ttl=64)
    check("warnings.simplefilter(ignore, TCPShapeWarning) 也能关",
          len(rec) == 0, "仍有 %d 条" % len(rec))

    with _w.catch_warnings(record=True) as rec:
        _w.simplefilter("always")
        tcpmod.build_tcp_profile(target, ttl=64, warn=False)
    check("单次 warn=False 只静音这一次", len(rec) == 0,
          "仍有 %d 条" % len(rec))

    # 关掉警告后，格式错误仍必须是异常（开关只影响"本机做不到"）
    ok_raise = False
    with _w.catch_warnings(record=True) as rec:
        _w.simplefilter("always")
        before = nb_curl.set_tcp_warnings(False)
        try:
            try:
                tcpmod.parse_tcp_profile("64240_2-1-3-1-1-4_1400_99")
            except nb_curl.TCPShapeError:
                ok_raise = True
        finally:
            nb_curl.set_tcp_warnings(before)
    check("警告开关不影响格式/越界异常（照样抛）", ok_raise)

    # ------------------------------------------------------------------ #
    # 自省
    # ------------------------------------------------------------------ #
    sup = tcpmod.tcp_support()
    need = {"platform", "native_order", "knobs", "verifiable",
            "mss_mechanism", "ts_mechanism", "interface_mtu", "warn_enabled"}
    check("tcp_support() 关键键齐全", need <= set(sup),
          "缺=%s" % sorted(need - set(sup)))
    check("tcp_support().warn_enabled 跟随全局开关", sup["warn_enabled"] is True,
          repr(sup.get("warn_enabled")))
    check("knobs 里 ttl 在 Windows / Linux 都可用",
          sup["knobs"].get("ttl") is True, repr(sup["knobs"]))
    check("nb_curl.tcp_support 与 nb_curl.tcp.tcp_support 一致",
          nb_curl.tcp_support()["platform"] == sup["platform"])

    # ------------------------------------------------------------------ #
    # Linux 分支：同样"绝不改默认窗口"，只是落点不同
    # （把平台指针与 /proc 读数打补丁，逻辑与真机逐行一致）
    # ------------------------------------------------------------------ #
    import unittest.mock as _mock
    import contextlib as _ctx

    def _linux_env(rmem=212992, ts=1, adv=1, mtu=1500):
        table = {
            "/proc/sys/net/core/rmem_max": rmem,
            "/proc/sys/net/ipv4/tcp_timestamps": ts,
            "/proc/sys/net/ipv4/tcp_adv_win_scale": adv,
        }
        stack = _ctx.ExitStack()
        stack.enter_context(
            _mock.patch("nb_curl.tcp._platform.system", return_value="Linux"))
        stack.enter_context(
            _mock.patch("nb_curl.tcp._read_int",
                        _mock.Mock(side_effect=lambda p: table.get(p))))
        stack.enter_context(
            _mock.patch("nb_curl.tcp.interface_mtu",
                        _mock.Mock(return_value={"eth0": mtu})))
        return stack

    target = "64240_2-1-3-1-1-4_1400_8"

    # 1) rmem_max 不够 wscale=8 -> 一个都不设
    with _linux_env(rmem=212992):
        with _w.catch_warnings(record=True) as rec:
            _w.simplefilter("always")
            pl = tcpmod.plan_rcvbuf(tcpmod.build_tcp_profile(target, ttl=64))
    check("Linux：rmem_max 不够时 SO_RCVBUF 不下发（默认窗口不变）",
          pl is None, "plan=%r" % (pl,))
    check("Linux：该情况给出 TCPShapeWarning",
          any("rmem_max" in str(x.message) for x in rec),
          "收到 %d 条" % len(rec))

    # 2) rmem_max 够 -> wscale=8 + window=65535 可达成
    with _linux_env(rmem=16777216):
        with _w.catch_warnings():
            _w.simplefilter("ignore")
            pl8 = tcpmod.plan_rcvbuf(
                tcpmod.build_tcp_profile({"window": 65535, "wscale": 8}))
    check("Linux：rmem_max 够时 window=65535+wscale=8 算出 rcvbuf",
          pl8 == (1 << 23), "plan=%r" % (pl8,))

    # 3) window=64240 + wscale=0 -> rcvbuf=64240
    #    MTU 1440（mss 1400）时 64240 不是整数倍 -> 另有一条"内核会压成多少"的提示
    with _linux_env(mtu=1440):
        with _w.catch_warnings(record=True) as rec:
            _w.simplefilter("always")
            pl_w = tcpmod.plan_rcvbuf(
                tcpmod.build_tcp_profile({"window": 64240, "wscale": 0}))
    check("Linux：window=64240+wscale=0 算出 rcvbuf=64240",
          pl_w == 64240, "plan=%r" % (pl_w,))
    check("Linux：window 不是 mss 整数倍会提示内核会压到多少",
          any("整数倍" in str(x.message) for x in rec),
          "收到 %s" % [str(x.message).splitlines()[0] for x in rec])
    check("Linux：取整提示给出实际会用的窗口值",
          any("63000" in str(x.message) for x in rec),
          "收到 %s" % [str(x.message).splitlines()[0] for x in rec])

    # 3b) MTU 1500（mss 1460）时 64240 = 44 × 1460，正好整除 -> 不该报警
    with _linux_env(mtu=1500):
        with _w.catch_warnings(record=True) as rec:
            _w.simplefilter("always")
            pl_w2 = tcpmod.plan_rcvbuf(
                tcpmod.build_tcp_profile({"window": 64240, "wscale": 0}))
    check("Linux：window 正好是 mss 整数倍时不误报",
          pl_w2 == 64240 and not any("整数倍" in str(x.message) for x in rec),
          "plan=%r 警告=%s" % (pl_w2, [str(x.message).splitlines()[0] for x in rec]))

    # 3c) 取整已被"提前预告"时，回读校验不重复报警
    with _linux_env(mtu=1440):
        with _w.catch_warnings(record=True) as rec:
            _w.simplefilter("always")
            prof7 = tcpmod.build_tcp_profile(
                {"window": 64240, "wscale": 0, "mss": 1400})
            pl7 = tcpmod.plan_rcvbuf(prof7)
            check("Linux：predicted_window 记为内核将压到的 63000",
                  prof7.predicted_window == 63000, repr(prof7.predicted_window))
            tcpmod.verify_actual(
                prof7,
                {"ttl": 64, "mss": 1400, "wscale": 0, "window": 63000,
                 "rcvbuf": pl7 * 2, "timestamp": 1},
                rcvbuf_set=pl7 is not None)
    check("Linux：取整已预告过，回读不重复报同一件事",
          not any("未达成" in str(x.message) for x in rec),
          "收到 %s" % [str(x.message).splitlines()[0] for x in rec])

    # 3d) 实际窗口既不是要求的也不是预告的 -> 仍然要报
    with _linux_env(mtu=1440):
        with _w.catch_warnings(record=True) as rec:
            _w.simplefilter("always")
            prof8 = tcpmod.build_tcp_profile(
                {"window": 64240, "wscale": 0, "mss": 1400})
            pl8 = tcpmod.plan_rcvbuf(prof8)
            tcpmod.verify_actual(
                prof8,
                {"ttl": 64, "mss": 1400, "wscale": 0, "window": 61600,
                 "rcvbuf": 2 * 62000, "timestamp": 1},
                rcvbuf_set=True)
    check("Linux：真实窗口既非要求值也非预告值时仍报警",
          any("未达成" in str(x.message) for x in rec),
          "收到 %s" % [str(x.message).splitlines()[0] for x in rec])

    # 4) adv_win_scale 不是 1 -> 换算表失效，一个都不设
    with _linux_env(adv=2):
        with _w.catch_warnings(record=True) as rec:
            _w.simplefilter("always")
            pl_adv = tcpmod.plan_rcvbuf(tcpmod.build_tcp_profile(
                {"window": 64240, "wscale": 0}))
    check("Linux：tcp_adv_win_scale != 1 时不下发 SO_RCVBUF",
          pl_adv is None, "plan=%r" % (pl_adv,))
    check("Linux：adv_win_scale 不匹配会提示 sysctl 改法",
          any("tcp_adv_win_scale" in str(x.message) for x in rec))

    # 5) option 顺序任何 OS 都改不了
    with _linux_env():
        with _w.catch_warnings(record=True) as rec:
            _w.simplefilter("always")
            tcpmod.build_tcp_profile(target, ttl=64)
    check("Linux：option 顺序改不了会警告",
          any("顺序" in str(x.message) for x in rec),
          "收到 %s" % [str(x.message).splitlines()[0] for x in rec])

    # 6) Linux 时间戳是全局 sysctl，与全局值不符要警告
    with _linux_env(ts=1):
        with _w.catch_warnings(record=True) as rec:
            _w.simplefilter("always")
            tcpmod.build_tcp_profile(timestamps=False)
    check("Linux：timestamps=False 但全局开着 -> 警告不生效",
          any("全局" in str(x.message) for x in rec),
          "收到 %s" % [str(x.message).splitlines()[0] for x in rec])

    # 7) 自省：Linux 多两个键，且 timestamp 不可回读
    with _linux_env(rmem=114514):
        with _w.catch_warnings():
            _w.simplefilter("ignore")
            sup_l = tcpmod.tcp_support()
    check("Linux：tcp_support() 带 tcp_timestamps / rmem_max",
          "tcp_timestamps" in sup_l and sup_l.get("rmem_max") == 114514,
          repr({k: sup_l.get(k) for k in ("tcp_timestamps", "rmem_max")}))
    check("Linux：时间戳标记为不可回读（全局 sysctl）",
          sup_l["verifiable"]["timestamp"] is False, repr(sup_l["verifiable"]))
    check("Linux：mss 落点 = socket",
          sup_l["mss_mechanism"] == "socket", repr(sup_l["mss_mechanism"]))

    # 8) Linux 时间戳关掉时本机 option 顺序会变
    with _linux_env(ts=0):
        with _w.catch_warnings():
            _w.simplefilter("ignore")
            sup_off = tcpmod.tcp_support()
    check("Linux：关掉时间戳后本机顺序变 2-1-1-4-1-3",
          sup_off["native_order"] == "2-1-1-4-1-3", repr(sup_off["native_order"]))

    # ------------------------------------------------------------------ #
    # DNS 代码必须已彻底移除（用户要求：全部删掉）
    # ------------------------------------------------------------------ #
    check("nb_curl.dns 模块已移除", not hasattr(nb_curl, "dns"))
    check("nb_curl.dns_servers 已移除", not hasattr(nb_curl, "dns_servers"))
    check("Session 不再接受 dns= 参数",
          "dns" not in nb_curl.params.SESSION_KEYS)
    try:
        importlib.import_module("nb_curl.dns")
        check("import nb_curl.dns 失败", False, "竟然导入成功")
    except ImportError:
        check("import nb_curl.dns 失败", True)

    # ------------------------------------------------------------------ #
    # 端到端：带 tcp= 的请求照常可用，且坏值在发请求前就报错
    # ------------------------------------------------------------------ #
    with _w.catch_warnings(record=True) as rec:
        _w.simplefilter("always")
        with LocalServer() as srv:
            # proxy="" = 显式禁用代理（画像与代理互斥，测试机常有 http_proxy）
            r = nb_curl.get(srv.url("/echo"), impersonate="chrome116", timeout=10,
                            proxy="", tcp="64240_2-1-3-1-1-4_1400_8", ttl=64)
            check("带 tcp= 的请求正常完成", r.status_code == 200, str(r.status_code))
    check("端到端过程中本机做不到的项只发警告、不中断请求",
          any(issubclass(x.category, nb_curl.TCPShapeWarning) for x in rec)
          or not rec)

    with LocalServer() as srv:
        try:
            nb_curl.get(srv.url("/echo"), timeout=10, proxy="",
                        tcp={"window": 99999})
            check("坏 tcp 画像在发请求前就抛 TCPShapeError", False, "竟然没抛")
        except nb_curl.TCPShapeError:
            check("坏 tcp 画像在发请求前就抛 TCPShapeError", True)

        with nb_curl.Session(proxy="", tcp="64240_2-1-3-1-1-4_1400_8",
                             tcp_warn=False) as s:
            with _w.catch_warnings(record=True) as rec2:
                _w.simplefilter("always")
                r = s.get(srv.url("/echo"), timeout=10)
            check("Session(tcp=..., tcp_warn=False) 请求正常且静音",
                  r.status_code == 200 and len(rec2) == 0,
                  "status=%s warnings=%d" % (r.status_code, len(rec2)))


# --------------------------------------------------------------------------- #
# 18. cookie 语义（只有一个通道，不重复、不串味）
# --------------------------------------------------------------------------- #
def _cookie_names(raw):
    return [p.split("=", 1)[0].strip() for p in (raw or "").split(";") if p.strip()]


def test_cookie_semantics():
    """第 18 节：cookie 只走 libcurl 内建引擎一条通道。

    回归背景：早先把同一份 jar 又用 ``CURLOPT_COOKIE`` 给了一遍，而 curl 的
    ``http_cookies()`` 会把「引擎里的 cookie」和「CURLOPT_COOKIE 的值」拼进同一个
    ``Cookie:`` 头 —— 于是 ``Set-Cookie: sid=x`` 发出去变成 ``sid=x; sid=x``。
    这既是功能 bug，也是一眼能认出客户端的指纹特征，所以这一节守死：

    * 引擎学到的 cookie 只发一份，同名更新后也只有一份；
    * 显式 ``Cookie`` 头 / 请求级 ``cookies=`` 不重复，且用完即弃、不进会话罐；
    * 手工写入与删除照常生效（`session.cookies` 表面仍是 dict）。
    """
    section("18. cookie 语义（单通道，不重复）")
    with LocalServer() as srv:
        with nb_curl.Session(impersonate="chrome116", proxy="") as s:
            s.get(srv.url("/cookies/set?sid=abc123"), timeout=10)
            raw = s.get(srv.url("/echo"), timeout=10).json()["headers"].get("cookie")
            check("Set-Cookie 学到的 cookie 只发一次",
                  _cookie_names(raw).count("sid") == 1, repr(raw))
            check("会话罐里有这条 cookie",
                  dict(s.cookies).get("sid") == "abc123", repr(dict(s.cookies)))

            raw = s.get(srv.url("/echo"), timeout=10).json()["headers"].get("cookie")
            check("同一连接第二次请求也只发一次",
                  _cookie_names(raw).count("sid") == 1, repr(raw))

            s.get(srv.url("/cookies/set?sid=updated"), timeout=10)
            raw = s.get(srv.url("/echo"), timeout=10).json()["headers"].get("cookie")
            check("同名 cookie 更新后不重复、值被服务端覆盖",
                  _cookie_names(raw).count("sid") == 1 and "sid=updated" in (raw or ""),
                  repr(raw))

        # 显式 Cookie 头：本次覆盖 + 用完即弃
        with nb_curl.Session(impersonate="chrome116", proxy="") as s:
            s.get(srv.url("/cookies/set?sid=abc123"), timeout=10)
            raw = s.get(srv.url("/echo"), headers={"Cookie": "sid=override; extra=1"},
                        timeout=10).json()["headers"].get("cookie")
            check("显式 Cookie 头不重复",
                  _cookie_names(raw).count("sid") == 1, repr(raw))
            check("显式 Cookie 头的值本次生效",
                  "sid=override" in (raw or "") and "extra=1" in (raw or ""), repr(raw))
            raw = s.get(srv.url("/echo"), timeout=10).json()["headers"].get("cookie")
            check("显式 cookie 不写进会话罐（extra 消失）",
                  "extra" not in (raw or ""), repr(raw))
            check("显式 cookie 不影响会话罐原值",
                  "sid=abc123" in (raw or ""), repr(raw))

        # 请求级 cookies=
        with nb_curl.Session(impersonate="chrome116", proxy="") as s:
            s.get(srv.url("/cookies/set?sid=abc123"), timeout=10)
            raw = s.get(srv.url("/echo"), cookies={"tmp": "42"},
                        timeout=10).json()["headers"].get("cookie")
            check("请求级 cookies 与会话 cookie 共存且不重复",
                  "tmp=42" in (raw or "") and "sid=abc123" in (raw or "")
                  and _cookie_names(raw).count("tmp") == 1, repr(raw))
            check("请求级 cookies 不写进会话罐", "tmp" not in dict(s.cookies),
                  repr(dict(s.cookies)))

        # 手工写入 / 删除
        with nb_curl.Session(impersonate="chrome116", proxy="") as s:
            s.cookies["manual"] = "7"
            raw = s.get(srv.url("/echo"), timeout=10).json()["headers"].get("cookie")
            check("手工写入的 cookie 只发一份",
                  _cookie_names(raw).count("manual") == 1, repr(raw))
            del s.cookies["manual"]
            raw = s.get(srv.url("/echo"), timeout=10).json()["headers"].get("cookie")
            check("删掉后不再发出", "manual" not in (raw or ""), repr(raw))
            check("cookie 罐类型是 CookieJar", isinstance(s.cookies, nb_curl.CookieJar))
            s.cookies.update({"a": "1", "b": "2"})
            check("dict 接口仍可用（update / dict()）",
                  dict(s.cookies) == {"a": "1", "b": "2"}, repr(dict(s.cookies)))
            s.cookies.clear()
            check("clear() 清空", dict(s.cookies) == {}, repr(dict(s.cookies)))


# --------------------------------------------------------------------------- #
# 19. 流式下载（stream=True 真增量）
# --------------------------------------------------------------------------- #
def test_streaming():
    """第 19 节：``stream=True`` 是真增量，不是把整体读完之后再切片。

    回归背景：``Response.iter_content()`` 原本在**已经完整缓冲**的 ``content`` 上切片，
    内存占用等于整个响应体 —— 大文件、SSE 这类场景等于没有流式。

    这一节用本地 ``/drip/<块数>/<字节>?interval=`` 端点（分多次、带间隔地发）证明：

    * ``get(stream=True)`` 不等整个响应体，返回时 ``status_code`` / ``headers`` 已可用；
    * 首块远早于整体结束（真·边收边给）；
    * 读取是游标：中途 ``break`` 不丢数据，``content`` 只给剩余部分；
    * 队列有高水位（内存有界，靠 TCP 背压）；
    * 提前 ``close()`` 能中止传输且会话照常可用；
    * 非流式路径一字未改。
    """
    import threading
    import time

    section("19. 流式下载（stream=True 真增量）")
    with LocalServer() as srv:
        # 服务端 5 块 x 200 字节，每块间隔 0.3s（整体约 1.2s）
        t0 = time.perf_counter()
        r = nb_curl.Session(impersonate="chrome116", proxy="").get(
            srv.url("/drip/5/200"), timeout=20, stream=True)
        t_ret = time.perf_counter() - t0
        check("stream=True 返回时状态码已可用", r.status_code == 200, str(r.status_code))
        check("stream=True 返回时响应头已可用",
              r.headers.get("content-length") == "1000",
              repr(r.headers.get("content-length")))
        check("返回没等整个响应体（整体约 1.2s）", t_ret < 0.6, "%.2fs" % t_ret)
        check("返回时 is_stream 为 True", r.is_stream)

        marks = []
        for chunk in r.iter_content(64):
            marks.append((time.perf_counter() - t0, len(chunk)))
        first = marks[0][0] if marks else -1
        check("首块远早于整体结束", 0 < first < 0.3, "%.2fs" % first)
        check("逐块产出而不是一次性给完", len(marks) > 1, "%d 块" % len(marks))
        check("数据完整", sum(m[1] for m in marks) == 1000, str(sum(m[1] for m in marks)))
        check("读完后 is_stream 变 False", not r.is_stream)
        check("stream_consumed 为 True", r.stream_consumed)
        r.close()

        # 游标语义：break 之后 content 只给剩余部分
        r = nb_curl.Session(impersonate="chrome116", proxy="").get(
            srv.url("/drip/4/100"), timeout=20, stream=True)
        got = 0
        for chunk in r.iter_content(100):
            got += len(chunk)
            break
        rest = r.content
        check("content 只给还没读的部分（%d + %d = 400）" % (got, len(rest)),
              got + len(rest) == 400, "%d + %d" % (got, len(rest)))
        r.close()

        r = nb_curl.Session(impersonate="chrome116", proxy="").get(
            srv.url("/drip/4/100"), timeout=20, stream=True)
        a = next(iter(r.iter_content(100)), b"")
        b = next(iter(r.iter_content(100)), b"")
        c = r.content
        check("分多次 iter_content 接着读，累计完整",
              len(a) + len(b) + len(c) == 400, "%d+%d+%d" % (len(a), len(b), len(c)))
        r.close()

        # content 读完后再 iter_content：在缓存内容上切片（与非流式一致）
        r = nb_curl.Session(impersonate="chrome116", proxy="").get(
            srv.url("/binary/1000"), timeout=20, stream=True)
        full = r.content
        check("content 之后 iter_content 切缓存",
              b"".join(r.iter_content(256)) == full and len(full) == 1000,
              "%d 字节" % len(full))
        r.close()

        # 内存有界：40 x 256KB = 10MB 全速发，队列峰值不应超过高水位
        session = nb_curl.Session(impersonate="chrome116", proxy="")
        r = session.get(srv.url("/drip/40/262144?interval=0"), timeout=60, stream=True)
        peak = [0]
        stop = threading.Event()

        def watch():
            while not stop.is_set():
                with r._stream._cond:
                    peak[0] = max(peak[0], r._stream._buffered)
                time.sleep(0.002)

        watcher = threading.Thread(target=watch, daemon=True)
        watcher.start()
        total = sum(len(c) for c in r.iter_content(65536))
        stop.set()
        watcher.join(0.5)
        check("大响应体字节数完整", total == 40 * 262144, str(total))
        check("队列峰值不超过高水位（内存有界）",
              0 < peak[0] <= (1 << 20), "%.1f KB" % (peak[0] / 1024.0))
        session.close()

        # 提前 close 能中止传输，会话照常可用
        session = nb_curl.Session(impersonate="chrome116", proxy="")
        t0 = time.perf_counter()
        r = session.get(srv.url("/drip/20/1000"), timeout=30, stream=True)
        nxt = next(iter(r.iter_content(100)), None)
        r.close()
        t_close = time.perf_counter() - t0
        check("提前 close 拿得到首块", nxt is not None)
        check("close 没等整个响应体（整体约 6s）", t_close < 1.5, "%.2fs" % t_close)
        check("close 后会话仍可继续用",
              session.get(srv.url("/echo"), timeout=10).json()["method"] == "GET")
        session.close()

        # 与非流式逐字节一致（二进制、gzip 两条路）
        s = nb_curl.Session(impersonate="chrome116", proxy="")
        plain = s.get(srv.url("/binary/5000"), timeout=10).content
        streamed = s.get(srv.url("/binary/5000"), timeout=10, stream=True).content
        check("与 /binary/ 非流式结果一致", plain == streamed,
              "%d vs %d" % (len(plain), len(streamed)))
        gz_plain = s.get(srv.url("/gzip"), timeout=10).content
        gz_stream = s.get(srv.url("/gzip"), timeout=10, stream=True).content
        check("gzip 解压结果与非流式一致", gz_plain == gz_stream,
              "%d vs %d" % (len(gz_plain), len(gz_stream)))
        s.close()

        # 模块级一次性入口也支持 stream=True（临时会话跟着响应走）
        with nb_curl.get(srv.url("/drip/3/100"), impersonate="chrome116", proxy="",
                         timeout=20, stream=True) as r:
            first_chunk = next(iter(r.iter_content(100)), b"")
            check("nb_curl.get(stream=True) 可用（with 语法）",
                  len(first_chunk) == 100 and r.status_code == 200,
                  "首块=%d status=%s" % (len(first_chunk), r.status_code))
        check("退出 with 后流已关闭", not r.is_stream, "is_stream=%s" % r.is_stream)

        # 非流式路径一字未改
        r = nb_curl.get(srv.url("/binary/3000"), impersonate="chrome116",
                        proxy="", timeout=10)
        check("非流式 is_stream 为 False", not r.is_stream)
        check("非流式 stream_consumed 为 True", r.stream_consumed)
        check("非流式 iter_content 仍可切片",
              len(b"".join(r.iter_content(1000))) == 3000)
        check("非流式 json() 正常",
              nb_curl.get(srv.url("/echo"), impersonate="chrome116", proxy="",
                          timeout=10).json()["method"] == "GET")

        # stream + tcp= 同用：只提醒一次"事后回读校验本次跳过"
        import warnings as _warnings

        with nb_curl.Session(impersonate="chrome116", proxy="",
                             tcp="64240_2-1-3-1-1-4_1400_8") as s:
            with _warnings.catch_warnings(record=True) as rec:
                _warnings.simplefilter("always")
                for _ in range(2):
                    r = s.get(srv.url("/drip/2/50?interval=0"), timeout=20, stream=True)
                    b"".join(r.iter_content(50))
                r.close()
            hits = [x for x in rec if "事后回读校验" in str(x.message)]
            check("stream + tcp= 时只提醒一次（连发两次请求）",
                  len(hits) == 1, "命中 %d 次" % len(hits))
        with nb_curl.Session(impersonate="chrome116", proxy="",
                             tcp="64240_2-1-3-1-1-4_1400_8", tcp_warn=False) as s:
            with _warnings.catch_warnings(record=True) as rec:
                _warnings.simplefilter("always")
                r = s.get(srv.url("/drip/2/50?interval=0"), timeout=20, stream=True)
                b"".join(r.iter_content(50))
                r.close()
            check("tcp_warn=False 时 stream 提醒也静音",
                  not [x for x in rec if "事后回读校验" in str(x.message)],
                  str([str(x.message)[:40] for x in rec]))


# --------------------------------------------------------------------------- #
def main() -> int:
    print("nb_curl 功能自测")
    print("  backend = %s" % nb_curl.backend_name())
    print("  native  = %s" % nb_curl.native_version())
    print("  library = %s" % nb_curl.backend_info()["native_lib"])

    test_builtin_fingerprints()
    test_platform_is_windows()
    test_header_persistence()
    test_custom_fingerprint()
    test_pool_isolation()
    test_http_semantics()
    test_reuse_resilience()
    test_backend_parity()
    test_async()
    test_param_validation()
    test_snapshot_and_presets()
    test_proxy_params()
    test_resolve()
    test_curl_error_codes()
    test_proxy_error_detail()
    test_api_signatures()
    test_trust_anchors()
    test_tcp()
    test_cookie_semantics()
    test_streaming()

    print("\n" + "=" * 60)
    print("通过 %d / 失败 %d" % (PASSES, len(FAILS)))
    if FAILS:
        print("失败项:")
        for name in FAILS:
            print("  - %s" % name)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
