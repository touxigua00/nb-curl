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
        except nb_curl.Timeout:
            check("超时抛 Timeout", True)
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
               ("2", 20), ("2tls", 21), ("2_prior_knowledge", 22), (0, 0)]
    for value, expect in ok_vals:
        try:
            got = resolve_http_version(value)
            check("http_version %r -> %r" % (value, expect), got == expect, str(got))
        except ValueError as exc:
            check("http_version %r -> %r" % (value, expect), False, repr(exc))
    for bad in ("3", "3only", "4", "h2c", 30, 99):
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

    # 不设代理时为 None
    s6 = Session()
    check("默认无代理", s6._proxy_for(url_https, None) is None)
    check("空字符串代理视为无代理", s6._proxy_for(url_https, "") is None)

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
