"""nb_curl.xcctls —— 把 https://www.xcctls.top/all 的响应解析成完整指纹

用法一（最省事，配合 ``fp_file`` 参数）::

    # 浏览器访问 https://www.xcctls.top/all -> 全选复制 -> 粘贴存成 snap.json
    r = nb_curl.get("https://example.com", fp_file="snap.json")

用法二（编程式）::

    from nb_curl.xcctls import parse_xcctls
    fp = parse_xcctls(response.text)          # -> nb_curl.Fingerprint
    r = nb_curl.get("https://example.com", impersonate=fp)

解析器做的事：

* 从 ``client_hello`` 提取套件 / 曲线 / 签名算法 / 证书压缩 / 扩展顺序 /
  ALPN / 最小 TLS 版本，全部对照 ``nb_curl.tls`` 权威表校验（后端不支持
  的值会在这里报 ``FingerprintError``，而不是建连时报 CURLE_SSL_CIPHER）；
* 从 ``http2`` 提取 akamai 指纹与浏览器请求头（伪头自动剔除）；
* 按 User-Agent 自动挑一个同族、版本不高于捕获版本的**内置预设作底座**
  （``base_impersonate="auto"``，默认开）。底座负责 diy_fp 控制不了的
  行为（ECH、H2 帧时序等），套件/曲线等可控制字段会被快照覆盖。
  不想要底座就传 ``base_impersonate=None``。

已知差异（诚实声明）：

* 真实 Chrome 的 TLS 扩展顺序是**每次连接随机排列**的。想复刻这一行为
  传 ``permute_extensions=True``（此时不固定扩展顺序，由后端随机排列），
  否则按快照里的顺序固定下发。
* 套件/扩展/版本里的 GREASE 值会被过滤，由 ``tls_grease`` 开关统一控制；
* 签名算法列表里的 GREASE 条目会转成 ``tls_grease_sigalgs`` 开关
  （后端在列表头部插入随机 GREASE 值，与真实 Chrome 行为一致）。
* ``trust_anchors (51764)`` 只在捕获结果真的带 ``data_hex`` 时才覆盖；
  xcctls 目前不给这段载荷，此时沿用底座预设自带的信任锚列表，并给一条
  ``UserWarning``。
"""

from __future__ import annotations

import json
import os
import re
import threading
import warnings
from collections import OrderedDict
from typing import Any, Mapping

from .const import CURL_SSLVERSION_MAX_TLSv1_3
from .exceptions import FingerprintError
from .fingerprint import Fingerprint, FingerprintOverrides, parse_akamai
from .impersonate import BUILTIN_TARGETS, is_available, resolve_target
from .tls import (
    ALL_CIPHER_SUITES,
    JA3_VERSION_TO_SSLVERSION,
    SIGNATURE_ALGORITHMS,
    SUPPORTED_GROUPS,
    TLS13_CIPHER_SUITES,
    is_grease,
    validate_cert_compression,
    validate_extension_ids,
)

__all__ = [
    "parse_xcctls",
    "load_fp_snapshot",
    "pick_base_impersonate",
]

# "name (123)" 形式的字符串 -> (name, 123)
_NAME_ID_RE = re.compile(r"^(.*?)\s*\(([0-9]+)\)$")


def _split_named(text: Any) -> tuple[str, int] | None:
    """'TLS_AES_128_GCM_SHA256 (4865)' -> ('TLS_AES_128_GCM_SHA256', 4865)。"""
    m = _NAME_ID_RE.match(str(text).strip())
    if not m:
        return None
    return m.group(1).strip(), int(m.group(2))


def _as_data(data: Any) -> dict:
    """接受 dict / JSON 文本（可被 <pre> 包裹、可带 BOM）。"""
    if isinstance(data, Mapping):
        return dict(data)
    if isinstance(data, (bytes, bytearray)):
        data = bytes(data).decode("utf-8", "replace")
    if isinstance(data, str):
        text = data.strip().lstrip("﻿")
        # 浏览器整页复制时会带上 <html><body><pre> 包裹，剥掉
        m = re.search(r"<pre[^>]*>(.*?)</pre>", text, re.S)
        if m:
            text = m.group(1).strip()
        try:
            parsed = json.loads(text)
        except ValueError as exc:
            raise FingerprintError(
                "无法把输入解析成 JSON（期望是 xcctls.top/all 的响应）。"
                "前 80 字符: %r；错误: %s" % (text[:80], exc)
            ) from None
        if not isinstance(parsed, dict):
            raise FingerprintError("xcctls 响应必须是 JSON 对象，收到 %s" % type(parsed).__name__)
        return parsed
    raise FingerprintError(
        "xcctls 响应必须是 dict 或 JSON 文本，收到 %s" % type(data).__name__)


def _ext_id(ext: Mapping[str, Any]) -> int | None:
    """扩展条目 -> 扩展 id（'signature_algorithms (13)' -> 13）。"""
    ni = _split_named(ext.get("type", ""))
    return ni[1] if ni else None


def _find_ext(extensions: list, ext_id: int) -> Mapping[str, Any] | None:
    for ext in extensions:
        if _ext_id(ext) == ext_id:
            return ext
    return None


def _ext_name(ext: Mapping[str, Any]) -> str:
    ni = _split_named(ext.get("type", ""))
    return (ni[0] if ni else str(ext.get("type", ""))).lower()


def _decode_trust_anchors(data_hex: Any) -> str:
    """trust_anchors (51764) 载荷 -> 逗号分隔的信任锚 OID 列表。

    线格式：``u16 总长`` 后跟若干「``u8`` 长度 + ASN.1 RELATIVE-OID」条目，
    每个数按 base-128 编码、字节高位置 1 表示还有后续字节。
    例：``00b8 08 83 9a 64 8c 9b 2d 01 0a ...`` -> ``52580.200109.1.10,...``
    """
    raw = re.sub(r"[^0-9a-fA-F]", "", str(data_hex))
    if not raw or len(raw) % 2:
        raise FingerprintError(
            "trust_anchors 载荷不是合法十六进制: %r" % (data_hex,))
    blob = bytes.fromhex(raw)
    if len(blob) < 2:
        raise FingerprintError("trust_anchors 载荷至少要有 2 字节总长字段")
    total = int.from_bytes(blob[:2], "big")
    body = blob[2:]
    if len(body) != total:
        raise FingerprintError(
            "trust_anchors 载荷长度不符：声明 %d 字节，实际 %d 字节"
            % (total, len(body)))
    out: list[str] = []
    pos = 0
    while pos < len(body):
        ln = body[pos]
        pos += 1
        chunk = body[pos:pos + ln]
        if len(chunk) != ln:
            raise FingerprintError("trust_anchors 载荷被截断")
        pos += ln
        arcs: list[int] = []
        value = 0
        for byte in chunk:
            value = (value << 7) | (byte & 0x7F)
            if not byte & 0x80:
                arcs.append(value)
                value = 0
        if not arcs:
            raise FingerprintError("trust_anchors 含空条目")
        out.append(".".join(str(a) for a in arcs))
    return ",".join(out)


# --------------------------------------------------------------------------- #
# 底座选择
# --------------------------------------------------------------------------- #
def pick_base_impersonate(user_agent: str) -> str | None:
    """按 User-Agent 挑一个同族、版本不高于 UA 主版本的内置 C 预设。

    返回 ``None`` 表示没有合适的底座。底座（impersonate 底层）负责
    diy_fp 控制不了的行为：ECH、H2 帧时序、连接行为等。
    """
    ua = (user_agent or "").lower()
    if not ua:
        return None

    if "edg/" in ua:
        family, major = "edge", _ua_major(ua, r"edg(?:e|a|ios)?/(\d+)")
    elif "firefox/" in ua or "fxios/" in ua:
        family, major = "firefox", _ua_major(ua, r"(?:firefox|fxios)/(\d+)")
    elif "chrome/" in ua or "headlesschrome/" in ua or "chromium" in ua:
        family, major = "chrome", _ua_major(ua, r"(?:headless)?chrome(?:rium)?/(\d+)")
    elif "safari/" in ua:
        family, major = "safari", _safari_number(ua)
    else:
        return None
    if major is None:
        return None

    best: str | None = None
    best_num = -1
    for target in BUILTIN_TARGETS:
        if not target.startswith(family):
            continue
        m = re.match(r"[a-z]+(\d+)", target)
        if not m:
            continue
        num = int(m.group(1))
        # ios 变体（chrome131_android / safari170_ios）不当底座，行为有差异
        if target.endswith("_android") or target.endswith("_ios"):
            continue
        if num <= major and num > best_num:
            best, best_num = target, num
    if best and is_available(best):
        return best
    return None


def _ua_major(ua: str, pattern: str) -> int | None:
    m = re.search(pattern, ua)
    return int(m.group(1)) if m else None


def _safari_number(ua: str) -> int | None:
    m = re.search(r"version/(\d+)\.(\d+)", ua)
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    return major * 10 + min(minor, 9)


# --------------------------------------------------------------------------- #
# 主解析
# --------------------------------------------------------------------------- #
def parse_xcctls(
    data: Any,
    *,
    permute_extensions: bool = False,
    base_impersonate: str | bool | None = "auto",
) -> Fingerprint:
    """把 xcctls.top/all 的响应（dict / JSON 文本）解析成完整指纹。

    :param permute_extensions: True 时不固定扩展顺序，改为每次连接随机
        排列（真实 Chrome 的行为）；默认按快照顺序固定下发。
    :param base_impersonate: ``"auto"``（默认）按 UA 自动挑同族内置预设
        作底座；``None`` / ``False`` 不用底座；也可显式指定内置预设名。
    """
    d = _as_data(data)
    ch = d.get("client_hello")
    if not isinstance(ch, Mapping):
        raise FingerprintError(
            "这不是 xcctls.top/all 的响应：缺少 client_hello 字段。"
            "请确认复制的是 /all 接口的完整 JSON。")
    h2 = d.get("http2") or {}
    extensions = list(ch.get("extensions") or [])

    ov = FingerprintOverrides()

    # --- cipher suites（GREASE 过滤；TLS1.3 套件单独放 tls13_ciphers） ---
    c12: list[str] = []
    c13: list[str] = []
    for entry in ch.get("cipher_suites") or []:
        ni = _split_named(entry)
        if ni is None:
            raise FingerprintError("cipher_suites 条目无法解析: %r" % (entry,))
        name, cid = ni
        if name.lower() == "grease":
            continue
        if cid in TLS13_CIPHER_SUITES:
            c13.append(TLS13_CIPHER_SUITES[cid])
        elif cid in ALL_CIPHER_SUITES:
            c12.append(ALL_CIPHER_SUITES[cid])
        else:
            raise FingerprintError(
                "捕获的 cipher suite %s (0x%04X) 不被后端 BoringSSL 支持，"
                "无法复刻该指纹。允许的取值用 nb_curl.tls.supported_ciphers() 查询"
                % (name, cid))
    if c12:
        ov.ciphers = ":".join(c12)
    if c13:
        ov.tls13_ciphers = ":".join(c13)

    # --- supported_groups ---
    groups_ext = _find_ext(extensions, 10)  # supported_groups
    group_names: list[str] = []
    if groups_ext:
        for entry in groups_ext.get("groups") or []:
            ni = _split_named(entry)
            if ni is None:
                raise FingerprintError("supported_groups 条目无法解析: %r" % (entry,))
            name, gid = ni
            if name.lower() == "grease" or is_grease(gid):
                continue
            if gid not in SUPPORTED_GROUPS:
                raise FingerprintError(
                    "捕获的协商组 %s (%d) 不被后端 BoringSSL 支持。"
                    "允许的取值用 nb_curl.tls.supported_groups() 查询" % (name, gid))
            group_names.append(SUPPORTED_GROUPS[gid])
    if group_names:
        ov.curves = ":".join(group_names)

    # --- signature_algorithms ---
    sig_ext = _find_ext(extensions, 13)
    sig_names: list[str] = []
    if sig_ext:
        for entry in sig_ext.get("algorithms") or []:
            ni = _split_named(entry)
            if ni is None:
                raise FingerprintError("signature_algorithms 条目无法解析: %r" % (entry,))
            name, sid = ni
            if name.lower() == "grease" or is_grease(sid):
                continue
            if sid not in SIGNATURE_ALGORITHMS:
                raise FingerprintError(
                    "捕获的浏览器使用了后端不支持的签名算法 %s (0x%04X)。"
                    "允许的取值用 nb_curl.tls.supported_signature_algorithms() 查询"
                    % (name, sid))
            sig_names.append(SIGNATURE_ALGORITHMS[sid])
    if sig_names:
        ov.sig_hash_algs = ":".join(sig_names)

    # --- compress_certificate ---
    comp_ext = _find_ext(extensions, 27)
    if comp_ext:
        algs: list[str] = []
        for entry in comp_ext.get("algorithms") or []:
            ni = _split_named(entry)
            alg = (ni[0] if ni else str(entry)).strip().lower()
            if alg and alg != "grease":
                algs.append(alg)
        if algs:
            validate_cert_compression(algs, param="xcctls/compress_certificate")
            ov.cert_compression = ",".join(algs)

    # --- record_size_limit ---
    rsl_ext = _find_ext(extensions, 28)
    if rsl_ext:
        value = rsl_ext.get("record_size_limit", rsl_ext.get("value"))
        if value is None:
            ni = _split_named(rsl_ext.get("type", ""))
            value = ni
        if isinstance(value, str):
            ni = _split_named(value)
            value = ni[1] if ni else None
        if value is not None:
            try:
                ov.record_size_limit = int(value)
            except (TypeError, ValueError):
                pass

    # --- ALPS（application_settings 17613 新码点 / 17513 旧码点） ---
    if _find_ext(extensions, 17613):
        ov.enable_alps = True
        ov.use_new_alps_codepoint = True
    elif _find_ext(extensions, 17513):
        ov.enable_alps = True
        ov.use_new_alps_codepoint = False

    # --- SCT / OCSP ---
    if _find_ext(extensions, 18):
        ov.signed_cert_timestamps = True
    if _find_ext(extensions, 5):
        ov.status_request = True

    # --- trust_anchors (51764) ---
    # xcctls.top/all 对 51764 只给 ``{'type': 'trust_anchors (51764)',
    # 'data_hex': ''}``：扩展存在，但载荷没被 dump 出来。空串**不代表**
    # 捕获端发的是空列表（真实的空列表编码是 ``0000``，也就是 data_hex
    # 应为 "0000"），所以这里不能把"没数据"当成"空列表"写下去——内置预设
    # 之前就是这么被写成空串的。只有真拿到载荷才覆盖，否则留给底座预设。
    ta_ext = _find_ext(extensions, 51764)
    if ta_ext:
        ta_hex = _as_data(ta_ext).get("data_hex")
        if isinstance(ta_hex, str) and ta_hex.strip():
            ov.trust_anchors = _decode_trust_anchors(ta_hex)
        else:
            warnings.warn(
                "捕获结果里 trust_anchors(51764) 没有载荷（data_hex 为空），"
                "无法得知捕获端发的是哪一份信任锚列表，因此不覆盖该字段，"
                "继续沿用底座预设自带的列表。", stacklevel=2)

    # --- supported_versions -> 最小 TLS 版本 ---
    sv_ext = _find_ext(extensions, 43)
    if sv_ext:
        versions: list[int] = []
        for entry in sv_ext.get("versions") or []:
            ni = _split_named(entry)
            if ni and not is_grease(ni[1]):
                versions.append(ni[1])
        if versions:
            low = min(versions)
            if low in JA3_VERSION_TO_SSLVERSION:
                ov.ssl_version = JA3_VERSION_TO_SSLVERSION[low] | CURL_SSLVERSION_MAX_TLSv1_3

    # --- 扩展顺序 ---
    if permute_extensions:
        ov.permute_extensions = True
    else:
        # 显式关掉底座自带的随机排列（chrome110+ 预设默认开），兑现
        # "按快照顺序固定下发"；否则不设此项时排列随底座走。
        ov.permute_extensions = False
        raw_ids = [i for i in (_ext_id(e) for e in extensions) if i is not None]
        ext_ids = validate_extension_ids(raw_ids, param="xcctls/extension_order")
        if ext_ids:
            ov.extension_order = "-".join(str(e) for e in ext_ids)

    # --- akamai（H2 设置 / 窗口 / 伪头顺序） ---
    akamai_str = h2.get("akamai")
    if akamai_str:
        ov = parse_akamai(str(akamai_str)).merge(ov)

    # --- 浏览器请求头（去掉 H2 伪头） ---
    raw_headers = h2.get("headers") or {}
    header_items: list[tuple[str, str]] = []
    for name, value in raw_headers.items():
        if str(name).startswith(":"):
            continue
        header_items.append((str(name), str(value)))

    # --- 底座（impersonate）选择 ---
    user_agent = ""
    for name, value in header_items:
        if name.lower() == "user-agent":
            user_agent = value
    base: str | None = None
    if base_impersonate in (None, False, "", "no", "none", "off"):
        base = None
        if _find_ext(extensions, 65037):
            warnings.warn(
                "捕获的浏览器发送了 ECH 扩展，但 diy_fp 无法直接控制 ECH。"
                "建议保留 base_impersonate=\"auto\"（默认），用同族内置预设"
                "作底座来获得 ECH 行为。", stacklevel=2)
    elif base_impersonate is True or base_impersonate == "auto":
        base = pick_base_impersonate(user_agent)
    else:
        base = resolve_target(str(base_impersonate))
        if not is_available(base):
            raise FingerprintError(
                "base_impersonate=%r 不是可用的内置预设。"
                "可用示例见 nb_curl.impersonate.RECOMMENDED_TARGETS" % (base_impersonate,))

    ja3_obj = ch.get("ja3")
    ja3_str = ja3_obj.get("ja3") if isinstance(ja3_obj, Mapping) else None

    return Fingerprint(
        impersonate=base,
        default_headers=not header_items,
        ja3=ja3_str,
        akamai=str(akamai_str) if akamai_str else None,
        diy_fp=None,
        overrides=ov,
        headers=header_items or None,
    )


# --------------------------------------------------------------------------- #
# fp_file 的加载入口（带缓存）
# --------------------------------------------------------------------------- #
_cache_lock = threading.Lock()
# key -> (stat 签名, Fingerprint)。LRU，防无限增长。
_fp_cache: "OrderedDict[Any, tuple[tuple, Fingerprint]]" = OrderedDict()
_FP_CACHE_MAX = 32


def _cache_get(key: Any, sig: tuple) -> Fingerprint | None:
    with _cache_lock:
        hit = _fp_cache.get(key)
        if hit is not None and hit[0] == sig:
            _fp_cache.move_to_end(key)
            return hit[1]
        return None


def _cache_put(key: Any, sig: tuple, fp: Fingerprint) -> None:
    with _cache_lock:
        _fp_cache[key] = (sig, fp)
        _fp_cache.move_to_end(key)
        while len(_fp_cache) > _FP_CACHE_MAX:
            _fp_cache.popitem(last=False)


def load_fp_snapshot(value: Any) -> Fingerprint:
    """从文件路径 / JSON 文本 / dict 加载指纹快照（fp_file 参数的后端）。

    * ``str`` 且是存在的文件路径 -> 读文件（UTF-8，容忍 BOM / <pre> 包裹）；
    * ``str`` 不是路径 -> 当作 JSON 文本；
    * ``dict`` -> 直接用；
    * ``Fingerprint`` -> 原样返回。

    **缓存策略**：同一个文件路径只解析一次，之后每次请求只做一次
    ``stat()``（微秒级）比对 (mtime, size)——文件被更新会自动重新解析，
    没更新直接复用解析好的 ``Fingerprint``。JSON 文本按内容哈希缓存。
    返回的是共享的只读对象（内部不会改动它），介意的话自行 ``copy``。
    """
    if isinstance(value, Fingerprint):
        return value
    if isinstance(value, Mapping):
        # dict 可能被调用方复用/改动，不进缓存
        return parse_xcctls(value)
    if isinstance(value, (str, os.PathLike)):
        text = os.fspath(value)
        if os.path.isfile(text):
            path = os.path.abspath(text)
            try:
                st = os.stat(path)
            except OSError as exc:
                raise FingerprintError("读取指纹快照文件失败 %r: %s" % (path, exc)) from None
            sig = (st.st_mtime_ns, st.st_size)
            cached = _cache_get(path, sig)
            if cached is not None:
                return cached
            try:
                with open(path, "r", encoding="utf-8-sig") as fh:
                    content = fh.read()
            except OSError as exc:
                raise FingerprintError("读取指纹快照文件失败 %r: %s" % (path, exc)) from None
            fp = parse_xcctls(content)
            _cache_put(path, sig, fp)
            return fp
        # 不是文件路径 -> 当作 JSON 文本，按内容哈希缓存
        key = ("text", hash(text))
        cached = _cache_get(key, ())
        if cached is not None:
            return cached
        fp = parse_xcctls(text)
        _cache_put(key, (), fp)
        return fp
    raise FingerprintError(
        "fp_file 只接受文件路径、JSON 文本或 dict，收到 %s" % type(value).__name__)
