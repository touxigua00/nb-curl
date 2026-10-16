"""nb_curl.fingerprint —— ja3 / akamai / diy_fp 的解析与下发

设计原则（对齐 curl_cffi，但只实现用到的部分）：
* 解析放在 Python（简单、可离线、可热更新），C 层只做通用字段接收。
* 所有自定义项都汇聚到一个 ``FingerprintOverrides``，一次调用
  ``easy_apply_fingerprint`` 下发，避免几十次跨语言调用。
* GREASE 值一律过滤掉 —— GREASE 由 C 层的 tls_grease 开关单独控制；
  签名算法列表例外：GREASE 条目转成 grease_sigalgs 开关（后端在列表
  头部插入随机 GREASE 值，与真实 Chrome 152+ 行为一致）。
* **取值范围校验**：所有枚举型参数（套件/曲线/签名算法/扩展…）在解析时
  就对照 ``nb_curl.tls`` 的权威表校验，非法值抛 ``FingerprintError``，
  不会等到建连时才在 C 层报一个难懂的 CURLE_SSL_CIPHER(59)。
  表的取值来自 BoringSSL / libcurl 的实际实现，见 ``nb_curl.tls`` 模块头。
* **数据类型**：diy_fp 每个键的类型与取值范围见 ``nb_curl.diy_fp_fields()``
  （即本模块的 ``DIY_FP_SPEC``）。
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field, fields
from typing import Any, Mapping, Sequence

from .const import (
    CURL_SSLVERSION_MAX_DEFAULT,
    CURL_SSLVERSION_MAX_TLSv1_3,
)
from .exceptions import FingerprintError
from .tls import (
    ALL_CIPHER_SUITES,
    JA3_VERSION_TO_SSLVERSION,
    SUPPORTED_GROUPS,
    TLS_VERSIONS,
    is_grease,
    split_list,
    validate_cert_compression,
    validate_cipher_names,
    validate_extension_ids,
    validate_group_names,
    validate_sigalg_names,
    validate_tls13_ciphers,
)

__all__ = [
    "FingerprintOverrides",
    "parse_ja3",
    "parse_akamai",
    "parse_diy_fp",
    "build_overrides",
    "is_grease",
    "Fingerprint",
]

# TLS 扩展 21 = padding，由 TLS 引擎按 ClientHello 长度决定是否发送
_PADDING_EXTENSION = 21

# CURL_SSLVERSION 的合法低 16 位（不含 MAX 位）
_SSLVERSION_MIN, _SSLVERSION_MAX = 4, 7

# HTTP/2 SETTINGS 帧 id -> (名称, 取值范围)
_HTTP2_SETTINGS_SPEC: dict[int, tuple[str, int, int]] = {
    1: ("HEADER_TABLE_SIZE", 0, 0xFFFFFFFF),
    2: ("ENABLE_PUSH", 0, 1),
    3: ("MAX_CONCURRENT_STREAMS", 0, 0xFFFFFFFF),
    4: ("INITIAL_WINDOW_SIZE", 0, 0x7FFFFFFF),
    5: ("MAX_FRAME_SIZE", 16384, 16777215),
    6: ("MAX_HEADER_LIST_SIZE", 0, 0xFFFFFFFF),
}

# diy_fp 的合法键（同时用于拼写检查，避免静默写错字段名）
_DIY_FP_KEYS = {
    "tls_signature_algorithms",
    "tls_min_version",
    "tls_grease",
    "tls_grease_sigalgs",
    "tls_permute_extensions",
    "tls_cert_compression",
    "tls_delegated_credential",
    "tls_trust_anchors",
    "tls_record_size_limit",
    "tls_key_shares_limit",
    "tls_extension_order",
    "tls_signed_cert_timestamps",
    "tls_status_request",
    "tls13_ciphers",
    "http2_stream_weight",
    "http2_stream_exclusive",
    "http2_no_priority",
    "http2_headers_priority",
    "header_order",
    "split_cookies",
    "enable_alps",
    "use_new_alps_codepoint",
}

# diy_fp 每个 key 的数据类型与取值范围说明（key -> (类型, 说明)）。
# 给用户看的权威文档；diy_fp_fields() 原样返回。
DIY_FP_SPEC: dict[str, tuple[str, str]] = {
    "tls_signature_algorithms": (
        "list[str] 或 ':'/',' 分隔的 str",
        "TLS 签名算法，按序下发。合法名用 nb_curl.tls.supported_signature_algorithms() 查询"),
    "tls_min_version": (
        "str '1.0'~'1.3' 或 int CURL_SSLVERSION(4-7)",
        "最小 TLS 版本（上限固定为 1.3）"),
    "tls_grease": (
        "bool",
        "是否在套件/扩展/版本等处插入 GREASE 值（真实浏览器的行为）"),
    "tls_grease_sigalgs": (
        "bool",
        "是否在签名算法列表头部插入 GREASE 值（Chrome 152+ 的行为）；"
        "在 tls_signature_algorithms 里写 GREASE 条目效果相同"),
    "tls_permute_extensions": (
        "bool",
        "是否每次连接随机排列 TLS 扩展顺序（Chrome 110+ 的行为）"),
    "tls_cert_compression": (
        "str（逗号分隔）或 list[str]",
        "证书压缩算法，只能是 brotli / zlib / zstd"),
    "tls_delegated_credential": (
        "list[str] 或 str",
        "委托凭据签名算法列表（合法名同 tls_signature_algorithms）"),
    "tls_trust_anchors": (
        "str（逗号分隔）",
        "trust_anchors(51764) 扩展要携带的信任锚 OID 列表（十进制点分，如 "
        "'52580.200109.1.10'）；空串 '' 表示发送空列表。与 tls_signature_algorithms "
        "一样是逐字段覆盖：给了就以它为准，连内置预设的那份也能整份换掉。列表按"
        "你给的顺序原样发出，不做任何重排（内置 chrome155 用的就是真 Chrome 155 "
        "的顺序）"),
    "tls_record_size_limit": (
        "int (1-65535)",
        "record_size_limit 扩展的值"),
    "tls_key_shares_limit": (
        "int (0-255)",
        "key_share 里预生成份额的协商组数量"),
    "tls_extension_order": (
        "str（'-' 分隔的扩展 id）或 list[int]",
        "扩展发送顺序；合法 id 用 nb_curl.tls.supported_extensions() 查询"),
    "tls_signed_cert_timestamps": (
        "bool",
        "是否请求 SCT（signed_certificate_timestamp 扩展）"),
    "tls_status_request": (
        "bool",
        "是否请求 OCSP stapling（status_request 扩展）"),
    "tls13_ciphers": (
        "str（':'/',' 分隔）或 list[str]",
        "TLS 1.3 套件，仅 TLS_AES_128_GCM_SHA256 / TLS_AES_256_GCM_SHA384 /"
        " TLS_CHACHA20_POLY1305_SHA256"),
    "http2_stream_weight": (
        "int (0-256)",
        "HTTP/2 流优先级权重"),
    "http2_stream_exclusive": (
        "int 0/1 或 bool",
        "HTTP/2 流优先级独占标志"),
    "http2_no_priority": (
        "bool",
        "是否不发送 HTTP/2 PRIORITY 信息（Safari 的行为）"),
    "http2_headers_priority": (
        "bool",
        "是否在 H2 HEADERS 帧里带上已废弃的 RFC 7540 优先级字段"
        "（E=1 / 依赖=0 / 权重=256），即 Chrome 的 HEADERS flags=0x25；"
        "默认跟随 impersonate 预设（Chrome 开、Safari 关），"
        "与 http2_no_priority=True 互斥。权重用 http2_stream_weight 改"),
    "header_order": (
        "str 或 list[str]（'a,b' 与 ['a','b'] 等价）",
        "普通请求头的发送顺序（头名，大小写不敏感）。列出的头按你给的顺序排到最前，"
        "未列出的保持原相对顺序追加在后；HTTP/1.1 与 HTTP/2 都生效。"
        "**host 永远排在最前**：名单里没写会自动补在最前，写在别处会被提上来，重复项只留一份"),
    "split_cookies": (
        "bool",
        "是否按浏览器风格把 Cookie 头拆成多行发送"),
    "enable_alps": (
        "bool",
        "是否启用 ALPS（application_settings）扩展"),
    "use_new_alps_codepoint": (
        "bool",
        "ALPS 用新码点 17613（True）还是旧码点 17513（False）"),
}


def diy_fp_fields() -> dict[str, tuple[str, str]]:
    """diy_fp 可用键 -> (数据类型, 取值范围说明)。

    >>> import nb_curl
    >>> nb_curl.diy_fp_fields()["tls_cert_compression"]
    ('str（逗号分隔）或 list[str]', '证书压缩算法，只能是 brotli / zlib / zstd')
    """
    return dict(DIY_FP_SPEC)


def _split_ints(text: str, what: str) -> list[int]:
    out: list[int] = []
    for token in text.split("-"):
        token = token.strip()
        if not token:
            continue
        try:
            out.append(int(token))
        except ValueError:
            raise FingerprintError("无法解析 %s 中的数值: %r" % (what, token)) from None
    return out


def _int_field(value: Any, what: str, lo: int, hi: int) -> int:
    """把 value 转成 int 并检查范围。"""
    try:
        iv = int(value)
    except (TypeError, ValueError):
        raise FingerprintError("%s 必须是整数，收到 %r" % (what, value)) from None
    if not lo <= iv <= hi:
        raise FingerprintError("%s 超出范围 [%d, %d]，收到 %r" % (what, lo, hi, value))
    return iv


def _normalize_sigalgs(value: Any, param: str) -> tuple[str, bool]:
    """签名算法：接受 list/tuple 或 ':'/',' 分隔的字符串。

    返回 ``(joined, grease)``：``grease`` 为 True 表示列表里有 GREASE 条目
    （如 ``GREASE`` / ``GREASE (31354)``）。GREASE 不进下发的名单——
    后端由 tls_grease_sigalgs 开关控制在列表头部插入**随机** GREASE 值
    （真实 Chrome 152 的行为，每次连接随机），这与浏览器一致。
    """
    if isinstance(value, str):
        names = split_list(value, ":,")
    elif isinstance(value, (list, tuple)):
        names = [str(v) for v in value]
    else:
        raise FingerprintError("%s 必须是列表或字符串，收到 %r" % (param, value))
    if not names:
        raise FingerprintError("%s 不能为空" % param)
    real: list[str] = []
    grease = False
    for name in names:
        token = name.strip()
        if token.lower() == "grease" or token.lower().startswith("grease "):
            grease = True
            continue
        real.append(token)
    if real:
        validate_sigalg_names(real, param=param)
    elif not grease:
        raise FingerprintError("%s 不能为空" % param)
    return ":".join(real), grease


def _normalize_header_order(value: Any, param: str = "header_order") -> str:
    """普通请求头顺序：接受 ``"a,b"`` 字符串或 ``["a", "b"]`` 列表。

    统一成 C 层要的逗号分隔串（``CURLOPT_HTTPHEADER_ORDER`` 就是"名单里的头
    按序排到最前，其余保持原相对顺序追加在后"）。

    两条硬规则：

    * **host 永远排在最前**：名单里没写就补在最前，写在别处会被提上来
      —— 否则 host 会掉到"其余"那一组（真实浏览器与 curl 默认都是 Host 在第一位）；
    * 同名（大小写不敏感）只保留第一次出现的那份，避免 C 层判成重复名单而报错。
    """
    if isinstance(value, str):
        names = [p for p in value.replace(";", ",").split(",")]
    elif isinstance(value, (list, tuple)):
        names = [str(v) for v in value]
    else:
        raise FingerprintError(
            "%s 必须是列表或逗号分隔的字符串，收到 %r" % (param, value))

    out: list[str] = []
    seen: set[str] = set()
    for name in names:
        token = name.strip()
        if not token or token.lower() in seen:
            continue
        seen.add(token.lower())
        out.append(token)
    if not out:
        raise FingerprintError("%s 不能为空" % param)
    lowered = [n.lower() for n in out]
    if "host" in lowered:
        idx = lowered.index("host")
        if idx:
            out.insert(0, out.pop(idx))
    else:
        out.insert(0, "host")
    return ",".join(out)


def _validate_http2_settings(settings: str, param: str = "akamai/SETTINGS") -> None:
    """校验 "1:65536;2:0;4:6291456" 格式的 HTTP/2 SETTINGS。"""
    for pair in settings.split(";"):
        pair = pair.strip()
        if not pair:
            continue
        if ":" not in pair:
            raise FingerprintError("%s 每段必须是 id:value，收到 %r" % (param, pair))
        sid_raw, value_raw = pair.split(":", 1)
        try:
            sid = int(sid_raw.strip())
            svalue = int(value_raw.strip())
        except ValueError:
            raise FingerprintError("%s 每段必须是 id:value 整数，收到 %r" % (param, pair)) from None
        spec = _HTTP2_SETTINGS_SPEC.get(sid)
        if spec is None:
            raise FingerprintError(
                "%s: HTTP/2 设置项 %d 不存在。允许的 id: %s"
                % (param, sid, ", ".join("%d(%s)" % (k, v[0]) for k, v in _HTTP2_SETTINGS_SPEC.items()))
            )
        _, lo, hi = spec
        if not lo <= svalue <= hi:
            raise FingerprintError(
                "%s: %s(%d) 的值 %d 超出范围 [%d, %d]"
                % (param, spec[0], sid, svalue, lo, hi)
            )


@dataclass
class FingerprintOverrides:
    """可选的指纹覆盖项。``None`` 表示不覆盖（保留 impersonate 预设或库默认值）。

    每个字段的合法取值范围见 ``nb_curl.tls``（``help(nb_curl.tls)``），
    或在请求前调用 ``validate()`` 主动检查。
    """

    ciphers: str | None = None
    tls13_ciphers: str | None = None
    curves: str | None = None
    sig_hash_algs: str | None = None
    extension_order: str | None = None
    cert_compression: str | None = None
    delegated_credentials: str | None = None
    trust_anchors: str | None = None
    ssl_version: int | None = None
    tls_grease: bool | None = None
    grease_sigalgs: bool | None = None
    permute_extensions: bool | None = None
    signed_cert_timestamps: bool | None = None
    status_request: bool | None = None
    enable_alps: bool | None = None
    use_new_alps_codepoint: bool | None = None
    record_size_limit: int | None = None
    key_shares_limit: int | None = None
    http2_settings: str | None = None
    http2_window_update: int | None = None
    http2_pseudo_headers_order: str | None = None
    http2_streams: str | None = None
    http2_no_priority: bool | None = None
    stream_weight: int | None = None
    stream_exclusive: int | None = None
    header_order: str | Sequence[str] | None = None
    split_cookies: bool | None = None
    # H2 HEADERS 帧里是否带已废弃的 RFC 7540 优先级字段（Chrome flags=0x25）
    http2_headers_priority: bool | None = None

    # ------------------------------------------------------------------ #
    def merge(self, other: "FingerprintOverrides") -> "FingerprintOverrides":
        """other 中非 None 的字段覆盖 self（other 优先级更高）。"""
        merged = FingerprintOverrides(**self.as_dict())
        for key, value in other.as_dict().items():
            if value is not None:
                setattr(merged, key, value)
        return merged

    def as_dict(self) -> dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    def is_empty(self) -> bool:
        return all(v is None for v in self.as_dict().values())

    def cache_key(self) -> tuple:
        return tuple(sorted(
            (k, v) for k, v in self.as_dict().items() if v is not None
        ))

    # ------------------------------------------------------------------ #
    def validate(self) -> "FingerprintOverrides":
        """校验所有已设置的字段（直接构造本对象时用；parse_* 已自动校验）。

        非法值抛 ``FingerprintError``，消息里写明字段、值、允许的取值范围。
        """
        if self.ciphers is not None:
            validate_cipher_names(split_list(self.ciphers, ":"), param="ciphers")
        if self.tls13_ciphers is not None:
            validate_tls13_ciphers(split_list(self.tls13_ciphers, ":"))
        if self.curves is not None:
            validate_group_names(split_list(self.curves, ":"))
        if self.sig_hash_algs is not None:
            validate_sigalg_names(split_list(self.sig_hash_algs, ":,"),
                                  param="sig_hash_algs")
        if self.extension_order is not None:
            if not isinstance(self.extension_order, str):
                raise FingerprintError("extension_order 必须是 '-' 分隔的字符串")
            validate_extension_ids(_split_ints(self.extension_order, "extension_order"))
        if self.cert_compression is not None:
            validate_cert_compression(self.cert_compression)
        if self.header_order is not None:
            # 字符串 / 列表两种写法都合法；这里只做一次归一化与早失败
            _normalize_header_order(self.header_order)
        if self.delegated_credentials is not None:
            validate_sigalg_names(split_list(self.delegated_credentials, ":,"),
                                  param="delegated_credentials")
        if self.ssl_version is not None:
            low = int(self.ssl_version) & 0xFFFF
            if not _SSLVERSION_MIN <= low <= _SSLVERSION_MAX:
                raise FingerprintError(
                    "ssl_version 低 16 位必须是 %d-%d（CURL_SSLVERSION），收到 %r"
                    % (_SSLVERSION_MIN, _SSLVERSION_MAX, self.ssl_version)
                )
        if self.record_size_limit is not None:
            _int_field(self.record_size_limit, "tls_record_size_limit", 1, 0xFFFF)
        if self.key_shares_limit is not None:
            _int_field(self.key_shares_limit, "tls_key_shares_limit", 0, 255)
        if self.http2_settings is not None:
            _validate_http2_settings(self.http2_settings, param="http2_settings")
        if self.http2_window_update is not None:
            _int_field(self.http2_window_update, "http2_window_update", 0, 0x7FFFFFFF)
        if self.http2_pseudo_headers_order is not None:
            order = str(self.http2_pseudo_headers_order).replace(",", "").replace(" ", "").lower()
            if sorted(order) != ["a", "m", "p", "s"]:
                raise FingerprintError(
                    "http2 伪头顺序必须是 m/a/s/p 四个字母的排列，收到 %r"
                    % self.http2_pseudo_headers_order
                )
        if self.stream_weight is not None:
            _int_field(self.stream_weight, "http2_stream_weight", 0, 256)
        if self.stream_exclusive is not None:
            _int_field(self.stream_exclusive, "http2_stream_exclusive", 0, 1)
        if self.http2_headers_priority is not None and self.http2_no_priority:
            raise FingerprintError(
                "http2_headers_priority 与 http2_no_priority 互斥："
                "http2_no_priority=True 表示不发优先级，不能再要求带上优先级字段"
            )
        return self

    # ------------------------------------------------------------------ #
    def to_values(self) -> dict[str, Any]:
        """转成 backend 可直接下发的字段字典。

        ``None`` 表示"不覆盖"。真正的 struct 构造由 FFI 后端负责
        （``lib.apply_fingerprint``），这样 ctypes/CFFI 两种布局约定
        都收敛在后端里，本模块不再依赖任何 FFI 细节。

        注意：本构建的 BoringSSL 没有 ``SSL_CTX_set_ciphersuites``
        （curl 的 ``CURLOPT_TLS13_CIPHERS`` 会报 CURLE_NOT_BUILT_IN），
        TLS 1.3 套件名并入 ``ciphers`` 一起走 ``SSL_CTX_set_cipher_list``
        —— BoringSSL 对两类名字同管，与 C 侧 impersonate 预设的拼法
        一致（1.3 名在前、1.2 名在后）。
        """
        values = self.as_dict()
        tls13 = values.pop("tls13_ciphers", None)
        if tls13:
            ciphers = values.get("ciphers")
            values["ciphers"] = "%s:%s" % (tls13, ciphers) if ciphers else tls13
        # header_order 两种写法都收（字符串 / 列表），并在这里统一成 C 层的逗号串、
        # 顺带把 host 提到最前 —— 直接构造 FingerprintOverrides 也走同一条路。
        if values.get("header_order") is not None:
            values["header_order"] = _normalize_header_order(values["header_order"])
        # Python 字段名 grease_sigalgs -> C 结构体字段名 tls_grease_sigalgs
        grease = values.pop("grease_sigalgs", None)
        if grease is not None:
            values["tls_grease_sigalgs"] = grease
        return values

    def apply_to(self, handle) -> int:
        """把覆盖项下发到某个 native handle，返回 CURLcode。"""
        from ._native import lib

        return lib.apply_fingerprint(handle, self.to_values())


# --------------------------------------------------------------------------- #
# ja3
# --------------------------------------------------------------------------- #
def parse_ja3(ja3: str, *, warn_padding: bool = True) -> FingerprintOverrides:
    """把 JA3 字符串解析成可下发的字段。

    JA3 格式: ``TLSVersion,CipherSuites,Extensions,SupportedGroups,ECPointFormats``

    套件/曲线/扩展都在解析时对照 ``nb_curl.tls`` 的权威表校验，
    不被后端 BoringSSL 支持的值直接抛 ``FingerprintError``。
    """
    if not ja3:
        raise FingerprintError("ja3 不能为空")

    parts = [p.strip() for p in ja3.split(",")]
    if len(parts) != 5:
        raise FingerprintError(
            "ja3 必须是 5 段（TLSVersion,Ciphers,Extensions,Groups,ECPointFormats），"
            "实际 %d 段: %r" % (len(parts), ja3)
        )
    tls_version_raw, ciphers_raw, extensions_raw, curves_raw, formats_raw = parts

    try:
        tls_version = int(tls_version_raw)
    except ValueError:
        raise FingerprintError("ja3 版本号非法: %r" % tls_version_raw) from None

    if tls_version not in JA3_VERSION_TO_SSLVERSION:
        raise FingerprintError(
            "不支持的 ja3 TLS 版本 %d。后端 BoringSSL 支持的版本: %s"
            % (tls_version, ", ".join("%s(%d)" % (k, v) for k, v in TLS_VERSIONS.items()))
        )

    # --- cipher suites（GREASE 过滤；id 必须在 nb_curl.tls 的套件表里） ---
    cipher_names: list[str] = []
    for cid in _split_ints(ciphers_raw, "cipher suites"):
        if is_grease(cid):
            continue
        name = ALL_CIPHER_SUITES.get(cid)
        if not name:
            raise FingerprintError(
                "cipher suite 0x%04X 不被后端 BoringSSL 支持。"
                "允许的取值用 nb_curl.tls.supported_ciphers() 查询"
                % (cid,)
            )
        cipher_names.append(name)
    if not cipher_names:
        raise FingerprintError("ja3 中没有可用的 cipher suite")

    # --- extensions（顺序本身就是指纹；只允许后端认识的 id） ---
    raw_ext_ids = _split_ints(extensions_raw, "extensions")
    if _PADDING_EXTENSION in raw_ext_ids:
        raw_ext_ids = [e for e in raw_ext_ids if e != _PADDING_EXTENSION]
        if warn_padding:
            warnings.warn(
                "ja3 含 padding(21) 扩展，已移除：是否发送该扩展应由 TLS 引擎"
                "按 ClientHello 长度决定。",
                stacklevel=2,
            )
    ext_ids = validate_extension_ids(raw_ext_ids, param="ja3 extensions")

    # --- supported groups ---
    curve_names: list[str] = []
    for cid in _split_ints(curves_raw, "supported groups"):
        if is_grease(cid):
            continue
        name = SUPPORTED_GROUPS.get(cid)
        if not name:
            raise FingerprintError(
                "supported group %d 不被后端 BoringSSL 支持。"
                "允许的取值用 nb_curl.tls.supported_groups() 查询（共 %d 个）"
                % (cid, len(SUPPORTED_GROUPS))
            )
        curve_names.append(name)

    # --- ec point formats ---
    try:
        formats = [int(x) for x in formats_raw.split("-") if x.strip() != ""]
    except ValueError:
        raise FingerprintError("ec_point_formats 非法: %r" % formats_raw) from None
    if formats and any(f != 0 for f in formats):
        raise FingerprintError(
            "只支持 ec_point_formats == 0（uncompressed），实际 %r" % formats
        )

    return FingerprintOverrides(
        ssl_version=JA3_VERSION_TO_SSLVERSION[tls_version] | CURL_SSLVERSION_MAX_DEFAULT,
        ciphers=":".join(cipher_names),
        curves=":".join(curve_names) if curve_names else None,
        extension_order="-".join(str(e) for e in ext_ids) if ext_ids else None,
    )


# --------------------------------------------------------------------------- #
# akamai
# --------------------------------------------------------------------------- #
def parse_akamai(akamai: str) -> FingerprintOverrides:
    """解析 Akamai HTTP/2 指纹。

    格式: ``SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER``
    例: ``1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p``
    """
    if not akamai:
        raise FingerprintError("akamai 不能为空")

    parts = [p.strip() for p in akamai.split("|")]
    if len(parts) != 4:
        raise FingerprintError(
            "akamai 必须是 4 段（SETTINGS|WINDOW_UPDATE|STREAMS|ORDER），"
            "实际 %d 段: %r" % (len(parts), akamai)
        )
    settings_raw, window_update_raw, streams_raw, order_raw = parts

    # 兼容 tls.peet.ws 用逗号分隔 settings 的写法
    settings = settings_raw.replace(",", ";")
    _validate_http2_settings(settings, param="akamai/SETTINGS")

    window_update = _int_field(window_update_raw, "akamai/WINDOW_UPDATE", 0, 0x7FFFFFFF)

    order = order_raw.replace(",", "").replace(" ", "").lower()
    if sorted(order) != ["a", "m", "p", "s"]:
        raise FingerprintError(
            "akamai 伪头顺序必须是 m/a/s/p 四个字母的排列，实际 %r" % order_raw
        )

    overrides = FingerprintOverrides(
        http2_settings=settings,
        http2_window_update=window_update,
        http2_pseudo_headers_order=order,
    )
    if streams_raw not in ("0", "-", ""):
        overrides.http2_streams = streams_raw
    return overrides


# --------------------------------------------------------------------------- #
# diy_fp
# --------------------------------------------------------------------------- #
def parse_diy_fp(diy_fp: Mapping[str, Any] | None) -> FingerprintOverrides:
    """把 diy_fp 字典转成覆盖项（所有枚举型字段都会校验取值范围）。

    每个键的类型与合法取值用 ``nb_curl.diy_fp_fields()`` 查询。
    """
    if not diy_fp:
        return FingerprintOverrides()

    unknown = set(diy_fp) - _DIY_FP_KEYS
    if unknown:
        raise FingerprintError(
            "diy_fp 含未知键 %s；可用键及类型用 nb_curl.diy_fp_fields() 查询（共 %d 个）"
            % (sorted(unknown), len(_DIY_FP_KEYS))
        )

    ov = FingerprintOverrides()

    sig = diy_fp.get("tls_signature_algorithms")
    if sig is not None:
        joined, grease = _normalize_sigalgs(sig, "tls_signature_algorithms")
        if joined:
            ov.sig_hash_algs = joined
        if grease:
            ov.grease_sigalgs = True

    min_version = diy_fp.get("tls_min_version")
    if min_version is not None:
        # 接受 "1.0"~"1.3"，或已是 CURL_SSLVERSION(4-7) 的整数
        if isinstance(min_version, str):
            key = min_version.strip()
            if key not in TLS_VERSIONS:
                raise FingerprintError(
                    "tls_min_version 不支持 %r。允许: %s"
                    % (min_version, ", ".join(TLS_VERSIONS))
                )
            code = JA3_VERSION_TO_SSLVERSION[TLS_VERSIONS[key]]
        else:
            code = _int_field(min_version, "tls_min_version", 4, 7)
        ov.ssl_version = code | CURL_SSLVERSION_MAX_TLSv1_3

    if diy_fp.get("tls_grease") is not None:
        ov.tls_grease = bool(diy_fp["tls_grease"])
    if diy_fp.get("tls_grease_sigalgs") is not None:
        ov.grease_sigalgs = bool(diy_fp["tls_grease_sigalgs"])
    if diy_fp.get("tls_permute_extensions") is not None:
        ov.permute_extensions = bool(diy_fp["tls_permute_extensions"])
    if diy_fp.get("tls_cert_compression") is not None:
        value = diy_fp["tls_cert_compression"]
        if isinstance(value, str):
            items = split_list(value, ",")
        else:
            items = [str(v) for v in value]
        validate_cert_compression(items)
        ov.cert_compression = ",".join(i.lower() for i in items)
    if diy_fp.get("tls_delegated_credential"):
        joined, _ = _normalize_sigalgs(
            diy_fp["tls_delegated_credential"], "tls_delegated_credential")
        if joined:
            ov.delegated_credentials = joined
    if diy_fp.get("tls_trust_anchors") is not None:
        anchors = diy_fp["tls_trust_anchors"]
        if not isinstance(anchors, str):
            raise FingerprintError(
                "tls_trust_anchors 必须是逗号分隔的字符串（空串表示发送空列表），"
                "收到 %r" % (anchors,))
        ov.trust_anchors = anchors
    if diy_fp.get("tls_record_size_limit"):
        ov.record_size_limit = _int_field(
            diy_fp["tls_record_size_limit"], "tls_record_size_limit", 1, 0xFFFF)
    if diy_fp.get("tls_key_shares_limit") is not None:
        ov.key_shares_limit = _int_field(
            diy_fp["tls_key_shares_limit"], "tls_key_shares_limit", 0, 255)

    if diy_fp.get("tls_extension_order") is not None:
        raw = diy_fp["tls_extension_order"]
        if isinstance(raw, str):
            ids = _split_ints(raw, "tls_extension_order")
        else:
            try:
                ids = [int(v) for v in raw]
            except (TypeError, ValueError):
                raise FingerprintError(
                    "tls_extension_order 必须是 '-' 分隔字符串或整数列表，收到 %r" % (raw,)
                ) from None
        ids = validate_extension_ids(ids, param="tls_extension_order")
        ov.extension_order = "-".join(str(e) for e in ids) if ids else None

    if diy_fp.get("tls_signed_cert_timestamps") is not None:
        ov.signed_cert_timestamps = bool(diy_fp["tls_signed_cert_timestamps"])
    if diy_fp.get("tls_status_request") is not None:
        ov.status_request = bool(diy_fp["tls_status_request"])

    if diy_fp.get("tls13_ciphers") is not None:
        raw = diy_fp["tls13_ciphers"]
        if isinstance(raw, str):
            items = split_list(raw, ":,")
        else:
            items = [str(v) for v in raw]
        validate_tls13_ciphers(items)
        ov.tls13_ciphers = ":".join(items)

    if diy_fp.get("enable_alps") is not None:
        ov.enable_alps = bool(diy_fp["enable_alps"])
    if diy_fp.get("use_new_alps_codepoint") is not None:
        ov.use_new_alps_codepoint = bool(diy_fp["use_new_alps_codepoint"])

    if diy_fp.get("http2_stream_weight") is not None:
        ov.stream_weight = _int_field(
            diy_fp["http2_stream_weight"], "http2_stream_weight", 0, 256)
    if diy_fp.get("http2_stream_exclusive") is not None:
        ov.stream_exclusive = _int_field(
            diy_fp["http2_stream_exclusive"], "http2_stream_exclusive", 0, 1)
    if diy_fp.get("http2_no_priority") is not None:
        ov.http2_no_priority = bool(diy_fp["http2_no_priority"])

    if diy_fp.get("header_order") is not None:
        ov.header_order = _normalize_header_order(diy_fp["header_order"])
    if diy_fp.get("split_cookies") is not None:
        ov.split_cookies = bool(diy_fp["split_cookies"])

    return ov


# --------------------------------------------------------------------------- #
# 汇总
# --------------------------------------------------------------------------- #
def build_overrides(
    *,
    ja3: str | None = None,
    akamai: str | None = None,
    diy_fp: Mapping[str, Any] | None = None,
) -> FingerprintOverrides:
    """按 ja3 -> akamai -> diy_fp 的顺序合并（后者优先级更高）。"""
    merged = FingerprintOverrides()
    if ja3:
        merged = merged.merge(parse_ja3(ja3))
    if akamai:
        merged = merged.merge(parse_akamai(akamai))
    merged = merged.merge(parse_diy_fp(diy_fp))
    return merged


@dataclass
class Fingerprint:
    """一份完整指纹描述：可只含 impersonate，也可完全自定义。

    * ``impersonate``：内置预设名（C 内核 40 个，含 ``chrome155``，
      见 :data:`nb_curl.impersonate.ImpersonateTarget`）；
    * ``ja3`` / ``akamai`` / ``diy_fp``：自定义指纹三件套，解析后汇入
      ``overrides``；
    * ``headers``：该指纹自带的默认请求头（如 fp_file 快照里的浏览器头），
      优先级低于 Session/请求级 headers。
    """

    impersonate: str | None = None
    default_headers: bool = True
    ja3: str | None = None
    akamai: str | None = None
    diy_fp: Mapping[str, Any] | None = None
    headers: list[tuple[str, str]] | None = None
    overrides: FingerprintOverrides = field(default_factory=FingerprintOverrides, repr=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Fingerprint":
        """从配置字典构造（对应实现文档里的指纹配置驱动方案）。

        支持的键：impersonate / default_headers / ja3 / akamai / diy_fp /
        headers / fp_file。
        """
        if not isinstance(data, Mapping):
            raise FingerprintError("指纹配置必须是字典")
        allowed = {"impersonate", "default_headers", "ja3", "akamai",
                   "diy_fp", "headers", "fp_file"}
        unknown = set(data) - allowed
        if unknown:
            raise FingerprintError("指纹配置含未知键: %s" % sorted(unknown))
        headers = data.get("headers")
        if headers is not None:
            headers = [(str(k), str(v)) for k, v in dict(headers).items()]
        fp_file = data.get("fp_file")
        if fp_file is not None:
            if any(data.get(k) is not None for k in ("impersonate", "ja3", "akamai", "diy_fp")):
                raise FingerprintError("fp_file 不能与 impersonate/ja3/akamai/diy_fp 混用")
            from .xcctls import load_fp_snapshot
            return load_fp_snapshot(fp_file)
        fp = cls(
            impersonate=data.get("impersonate"),
            default_headers=bool(data.get("default_headers", True)),
            ja3=data.get("ja3"),
            akamai=data.get("akamai"),
            diy_fp=data.get("diy_fp"),
            headers=headers or None,
        )
        fp.overrides = build_overrides(ja3=fp.ja3, akamai=fp.akamai, diy_fp=fp.diy_fp)
        return fp

    def cache_key(self) -> tuple:
        return (
            self.impersonate or "",
            int(bool(self.default_headers)),
            self.overrides.cache_key(),
        )

    def force_http2(self) -> bool:
        """akamai 指纹隐含 HTTP/2。"""
        return bool(self.akamai) or self.overrides.http2_settings is not None
