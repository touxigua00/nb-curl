"""nb_curl.tls —— 自定义指纹参数的权威取值范围与校验

**取值来自 libcurl / BoringSSL 的实际实现，不是公网资料**，逐表核对过：

==========================================================  =====================
表                                                              源码出处
==========================================================  =====================
TLS 套件（34 个，TLS1.2 及以下；另有 3 个 TLS1.3 套件）              BoringSSL ssl/ssl_cipher.cc kCiphers[]
TLS 1.3 套件（3 个，无 CCM）                                    同上（0x1301-0x1303）
椭圆曲线 / 密钥协商组（9 个）                                   BoringSSL ssl/ssl_key_share.cc kNamedGroups[]
签名算法（16 个，C 层实际接受的名字）                           curl lib/vtls/openssl.c kSignatureAlgorithmNames[]
TLS 扩展（32 个，extension_order 只认这些 id）                  BoringSSL ssl/extensions.cc kExtensions[]
TLS 版本（1.0/1.1/1.2/1.3，默认下限 1.2）                      BoringSSL ssl/ssl_versions.cc
证书压缩算法（brotli/zlib/zstd）                                curl lib/vtls/openssl.c cert_compress_algs[]
==========================================================  =====================

升级 BoringSSL / curl 后若表变了，**必须同步改这里**（逐项对照两者实现里的定义）。

用法（自省，看支持哪些值）::

    import nb_curl
    nb_curl.tls.supported_ciphers()               # {0x1301: "TLS_AES_128_GCM_SHA256", ...}
    nb_curl.tls.supported_tls13_ciphers()
    nb_curl.tls.supported_groups()                # {23: "P-256", 29: "X25519", ...}
    nb_curl.tls.supported_signature_algorithms()
    nb_curl.tls.supported_extensions()            # {0: "server_name", 51: "key_share", ...}
    nb_curl.tls.supported_tls_versions()          # {"1.0","1.1","1.2","1.3"}
    nb_curl.tls.supported_cert_compression()      # ("brotli","zlib","zstd")

给错值会在**请求发出之前**抛 ``nb_curl.FingerprintError``，消息里写明
是哪个参数、哪个值不合法、允许的取值在哪查。
C 层（curl/BoringSSL）仍是最后防线：漏网之鱼会在建连时得到
CURLE_SSL_CIPHER(59) 等标准 CURLcode，见
https://curl.se/libcurl/c/libcurl-errors.html
"""

from __future__ import annotations

from typing import Iterable, Sequence

from .exceptions import FingerprintError

__all__ = [
    # 权威表（id -> 名称）
    "CIPHER_SUITES",
    "TLS13_CIPHER_SUITES",
    "ALL_CIPHER_SUITES",
    "SUPPORTED_GROUPS",
    "SIGNATURE_ALGORITHMS",
    "TLS_EXTENSIONS",
    "TLS_VERSIONS",
    "CERT_COMPRESSION_ALGORITHMS",
    # 自省
    "supported_ciphers",
    "supported_tls13_ciphers",
    "supported_groups",
    "supported_signature_algorithms",
    "supported_extensions",
    "supported_tls_versions",
    "supported_cert_compression",
    "cipher_name_to_id",
    "group_name_to_id",
    "sigalg_name_to_id",
    # 校验
    "validate_cipher_names",
    "validate_tls13_ciphers",
    "validate_group_names",
    "validate_sigalg_names",
    "validate_extension_ids",
    "validate_cert_compression",
    "is_grease",
    "split_list",
]

# --------------------------------------------------------------------------- #
# 1. TLS 套件（TLS 1.2 及以下，34 个）+ TLS 1.3 套件（3 个，无 CCM）
#    BoringSSL ssl/ssl_cipher.cc kCiphers[]。
#    注意：SSL_CTX_set_cipher_list 对 TLS1.3 套件名同样接受，
#    所以 ja3 解析用 ALL_CIPHER_SUITES（34+3 联合表）。
# --------------------------------------------------------------------------- #
CIPHER_SUITES: dict[int, str] = {
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x008C: "TLS_PSK_WITH_AES_128_CBC_SHA",
    0x008D: "TLS_PSK_WITH_AES_256_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC035: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
    0xC036: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCAB: "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
}

# --------------------------------------------------------------------------- #
# 2. TLS 1.3 套件（BoringSSL 只有这 3 个，没有 CCM 系列）
# --------------------------------------------------------------------------- #
TLS13_CIPHER_SUITES: dict[int, str] = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}

# 联合表（37 个）：ja3 的 cipher 列表同时含 TLS1.3 与 TLS1.2 套件
ALL_CIPHER_SUITES: dict[int, str] = {**CIPHER_SUITES, **TLS13_CIPHER_SUITES}

# --------------------------------------------------------------------------- #
# 3. 椭圆曲线 / 密钥协商组
#    BoringSSL ssl/ssl_key_share.cc kNamedGroups[]，共 9 个。
#    注意：P-192/P-224 等未收录——后端不支持，给了会报错。
# --------------------------------------------------------------------------- #
SUPPORTED_GROUPS: dict[int, str] = {
    23:    "P-256",                       # 0x0017 secp256r1 / prime256v1
    24:    "P-384",                       # 0x0018 secp384r1
    25:    "P-521",                       # 0x0019 secp521r1
    29:    "X25519",                      # 0x001d
    0x11EC: "X25519MLKEM768",             # 4588，Chrome 124+ 默认带
    0x6399: "X25519Kyber768Draft00",      # 25497，旧版 Chrome/Edge 用
    0x0202: "MLKEM1024",                  # 514
    0x0100: "ffdhe2048",                  # 256，BoringSSL 亦接受别名 dhe2048
    0x0101: "ffdhe3072",                  # 257，同上
}

# --------------------------------------------------------------------------- #
# 4. 签名算法（signature_algorithms 扩展）
#    与 curl lib/vtls/openssl.c kSignatureAlgorithmNames[] 一字不差——
#    这是 C 层 parse_sig_algs() 实际接受的名字集合。
# --------------------------------------------------------------------------- #
SIGNATURE_ALGORITHMS: dict[int, str] = {
    0x0201: "rsa_pkcs1_sha1",
    0x0401: "rsa_pkcs1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    0x0203: "ecdsa_sha1",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519",
    0x0904: "mldsa44",
    0x0905: "mldsa65",
    0x0906: "mldsa87",
    0xFF01: "rsa_pkcs1_md5_sha1",         # TLS1.0 内部值，一般用不到
}

# --------------------------------------------------------------------------- #
# 5. TLS 扩展（extension_order 允许出现的 id）
#    BoringSSL ssl/extensions.cc kExtensions[]，共 32 个。
#    ssl_parse_extension_order() 对不在表里的 id 直接判非法。
#    注意：标准 padding(21) 不在表里（由 TLS 引擎自行决定），
#    GREASE 值也不在表里（下发前会被过滤，由 tls_grease 开关控制）。
# --------------------------------------------------------------------------- #
TLS_EXTENSIONS: dict[int, str] = {
    0:     "server_name",
    5:     "status_request",                 # OCSP stapling
    10:    "supported_groups",
    11:    "ec_point_formats",
    13:    "signature_algorithms",
    14:    "use_srtp",
    16:    "application_layer_protocol_negotiation",
    18:    "signed_certificate_timestamp",
    19:    "client_cert_type",
    20:    "server_cert_type",
    23:    "extended_master_secret",
    27:    "compress_certificate",
    28:    "record_size_limit",
    34:    "delegated_credential",
    35:    "session_ticket",
    42:    "early_data",
    43:    "supported_versions",
    44:    "cookie",
    45:    "psk_key_exchange_modes",
    47:    "certificate_authorities",
    51:    "key_share",
    57:    "quic_transport_parameters",
    4832:  "server_padding",                 # BoringSSL 私有
    13172: "next_proto_neg",                 # NPN
    17513: "application_settings_old",       # ALPS 旧码点
    17613: "application_settings",           # ALPS
    30032: "channel_id",                     # BoringSSL 私有
    35387: "pake",                           # 0x8a3b
    51764: "trust_anchors",                  # 0xca34
    65037: "encrypted_client_hello",         # 0xfe0d
    65281: "renegotiation_info",             # 0xff01
    65445: "quic_transport_parameters_legacy",  # 0xffa5
}

# --------------------------------------------------------------------------- #
# 6. TLS 版本（ja3 第一段的合法值 -> CURL_SSLVERSION）
#    BoringSSL 支持 TLS 1.0-1.3（默认下限 1.2）。
# --------------------------------------------------------------------------- #
TLS_VERSIONS: dict[str, int] = {
    "1.0": 769,   # 0x0301 -> CURL_SSLVERSION_TLSv1_0 (4)
    "1.1": 770,   # 0x0302 -> CURL_SSLVERSION_TLSv1_1 (5)
    "1.2": 771,   # 0x0303 -> CURL_SSLVERSION_TLSv1_2 (6)
    "1.3": 772,   # 0x0304 -> CURL_SSLVERSION_TLSv1_3 (7)
}

# ja3 版本号 -> CURL_SSLVERSION（不含 MAX 位）
JA3_VERSION_TO_SSLVERSION: dict[int, int] = {
    769: 4,
    770: 5,
    771: 6,
    772: 7,
}

# --------------------------------------------------------------------------- #
# 7. 证书压缩算法（CURLOPT_SSL_CERT_COMPRESSION）
# --------------------------------------------------------------------------- #
CERT_COMPRESSION_ALGORITHMS: tuple[str, ...] = ("brotli", "zlib", "zstd")

# --------------------------------------------------------------------------- #
# 反查表（名称 -> id，名称统一小写；ffdhe 接受 dhe 别名）
# --------------------------------------------------------------------------- #
_CIPHER_NAME_TO_ID: dict[str, int] = {v.lower(): k for k, v in CIPHER_SUITES.items()}
_ALL_CIPHER_NAME_TO_ID: dict[str, int] = {v.lower(): k for k, v in ALL_CIPHER_SUITES.items()}
_TLS13_NAME_TO_ID: dict[str, int] = {v.lower(): k for k, v in TLS13_CIPHER_SUITES.items()}
_GROUP_NAME_TO_ID: dict[str, int] = {v.lower(): k for k, v in SUPPORTED_GROUPS.items()}
_GROUP_NAME_TO_ID["dhe2048"] = 0x0100
_GROUP_NAME_TO_ID["dhe3072"] = 0x0101
_SIGALG_NAME_TO_ID: dict[str, int] = {v.lower(): k for k, v in SIGNATURE_ALGORITHMS.items()}

# 展示用最多列多少个，防止错误消息刷屏
_SHOW_LIMIT = 12


def _fmt_ids(table: dict[int, str], accessor: str) -> str:
    items = sorted(table)
    shown = ", ".join("0x%04X(%s)" % (i, table[i]) for i in items[:_SHOW_LIMIT])
    if len(items) > _SHOW_LIMIT:
        shown += ", …（共 %d 个，用 nb_curl.tls.%s() 查完整列表）" % (len(table), accessor)
    return shown


def _fmt_names(name_to_id: dict[str, int], accessor: str) -> str:
    names = sorted(name_to_id)
    shown = ", ".join(names[:_SHOW_LIMIT])
    if len(names) > _SHOW_LIMIT:
        shown += ", …（共 %d 个，用 nb_curl.tls.%s() 查完整列表）" % (len(names), accessor)
    return shown


def is_grease(value: int) -> bool:
    """判断一个 TLS 码点是不是 GREASE（形如 0x?A?A）。"""
    return (value >> 8) == (value & 0xFF) and (value & 0x0F) == 0x0A


def split_list(text: str, seps: str = ":,") -> list[str]:
    """按分隔符拆列表，去空白、去空段。"""
    for sep in seps:
        text = text.replace(sep, "\x00")
    return [t.strip() for t in text.split("\x00") if t.strip()]


# --------------------------------------------------------------------------- #
# 自省 API
# --------------------------------------------------------------------------- #
def supported_ciphers() -> dict[int, str]:
    """TLS 1.2 及以下 cipher 套件（id -> IANA 名称），共 34 个。"""
    return dict(CIPHER_SUITES)


def supported_tls13_ciphers() -> dict[int, str]:
    """TLS 1.3 套件（id -> 名称）。BoringSSL 只有 3 个，无 CCM。"""
    return dict(TLS13_CIPHER_SUITES)


def supported_groups() -> dict[int, str]:
    """椭圆曲线 / 密钥协商组（id -> 名称），共 9 个。"""
    return dict(SUPPORTED_GROUPS)


def supported_signature_algorithms() -> dict[int, str]:
    """签名算法（id -> 名称），共 16 个，与 C 层接受的名字一致。"""
    return dict(SIGNATURE_ALGORITHMS)


def supported_extensions() -> dict[int, str]:
    """extension_order 允许的 TLS 扩展（id -> 名称），共 32 个。"""
    return dict(TLS_EXTENSIONS)


def supported_tls_versions() -> tuple[str, ...]:
    """支持的 TLS 版本："1.0" / "1.1" / "1.2" / "1.3"。"""
    return tuple(TLS_VERSIONS)


def supported_cert_compression() -> tuple[str, ...]:
    """证书压缩算法：brotli / zlib / zstd。"""
    return CERT_COMPRESSION_ALGORITHMS


def cipher_name_to_id(name: str) -> int | None:
    """套件名（大小写不敏感）-> id；未知返回 None。"""
    return _CIPHER_NAME_TO_ID.get(name.strip().lower())


def group_name_to_id(name: str) -> int | None:
    """组名（大小写不敏感，接受 dhe2048/ffdhe2048 两种写法）-> id。"""
    return _GROUP_NAME_TO_ID.get(name.strip().lower())


def sigalg_name_to_id(name: str) -> int | None:
    """签名算法名（大小写不敏感）-> id。"""
    return _SIGALG_NAME_TO_ID.get(name.strip().lower())


# --------------------------------------------------------------------------- #
# 校验 API（全部抛 FingerprintError，消息格式统一）
# --------------------------------------------------------------------------- #
def validate_cipher_names(names: Sequence[str], *, param: str = "ciphers") -> None:
    """校验套件名列表（TLS1.2 + TLS1.3 联合表，BoringSSL 的
    SSL_CTX_set_cipher_list 对两类名字都接受）；非法即抛错。"""
    for name in names:
        if not isinstance(name, str) or _ALL_CIPHER_NAME_TO_ID.get(name.strip().lower()) is None:
            raise FingerprintError(
                "%s: 套件 %r 不被后端 BoringSSL 支持。"
                "允许的取值: %s" % (param, name, _fmt_names(_ALL_CIPHER_NAME_TO_ID, "supported_ciphers"))
            )


def validate_tls13_ciphers(items: Sequence[str], *, param: str = "tls13_ciphers") -> None:
    """校验 TLS1.3 套件列表；接受 IANA 名称或 0x1301 十六进制/十进制 id。"""
    valid = set(TLS13_CIPHER_SUITES)
    for item in items:
        token = str(item).strip()
        if token.lower() in _TLS13_NAME_TO_ID:
            continue
        try:
            cid = int(token, 0)
        except ValueError:
            cid = -1
        if cid not in valid:
            raise FingerprintError(
                "%s: TLS 1.3 套件 %r 不被支持。BoringSSL 只支持 %s"
                % (param, item,
                   ", ".join("%s(0x%04X)" % (v, k) for k, v in TLS13_CIPHER_SUITES.items()))
            )


def validate_group_names(names: Sequence[str], *, param: str = "curves") -> None:
    """校验曲线/协商组名列表；非法即抛错。"""
    for name in names:
        if not isinstance(name, str) or group_name_to_id(name) is None:
            raise FingerprintError(
                "%s: 曲线/组 %r 不被后端 BoringSSL 支持。"
                "允许的取值: %s" % (param, name, _fmt_names(_GROUP_NAME_TO_ID, "supported_groups"))
            )


def validate_sigalg_names(names: Sequence[str], *, param: str = "tls_signature_algorithms") -> None:
    """校验签名算法名列表（与 curl C 层 parse_sig_algs 同一集合）。"""
    for name in names:
        if not isinstance(name, str) or sigalg_name_to_id(name) is None:
            raise FingerprintError(
                "%s: 签名算法 %r 不被支持。"
                "允许的取值: %s" % (param, name, _fmt_names(_SIGALG_NAME_TO_ID, "supported_signature_algorithms"))
            )


def validate_extension_ids(ids: Iterable[int], *, param: str = "extension_order") -> list[int]:
    """校验扩展 id 序列（GREASE 与 padding(21) 会被过滤，其余必须合法且不重复）。

    返回过滤后的 id 列表。
    """
    out: list[int] = []
    seen: set[int] = set()
    for value in ids:
        try:
            ext_id = int(value)
        except (TypeError, ValueError):
            raise FingerprintError("%s: 扩展编号 %r 不是整数" % (param, value)) from None
        if is_grease(ext_id) or ext_id == 21:
            # GREASE 由 tls_grease 开关控制；padding(21) 由 TLS 引擎自行决定
            continue
        if ext_id not in TLS_EXTENSIONS:
            raise FingerprintError(
                "%s: 扩展 %d(%s) 不被后端 BoringSSL 支持，无法控制其顺序。"
                "允许的取值: %s"
                % (param, ext_id, _ext_hint(ext_id),
                   _fmt_ids(TLS_EXTENSIONS, "supported_extensions"))
            )
        if ext_id in seen:
            raise FingerprintError(
                "%s: 扩展 %d(%s) 重复出现" % (param, ext_id, TLS_EXTENSIONS[ext_id])
            )
        seen.add(ext_id)
        out.append(ext_id)
    if len(out) > len(TLS_EXTENSIONS):
        raise FingerprintError(
            "%s: 扩展数 %d 超过后端上限 %d" % (param, len(out), len(TLS_EXTENSIONS))
        )
    return out


def validate_cert_compression(value: str | Iterable[str], *,
                              param: str = "tls_cert_compression") -> None:
    """校验证书压缩算法（字符串逗号分隔或列表）。"""
    if isinstance(value, str):
        items = split_list(value, ",")
    else:
        items = [str(v) for v in value]
    for item in items:
        if item.lower() not in CERT_COMPRESSION_ALGORITHMS:
            raise FingerprintError(
                "%s: 算法 %r 不支持。允许的取值: %s"
                % (param, item, ", ".join(CERT_COMPRESSION_ALGORITHMS))
            )


def _ext_hint(ext_id: int) -> str:
    """对常见但不被支持的扩展给出提示名。"""
    hints = {
        21: "padding",
        24: "token_binding",
        26: "tls_lts",
        29: "pwd_protect",
        32: "ticket_pinning",
        50: "signature_algorithms_cert",
        52: "transparency_info",
        54: "connection_id",
        2570: "GREASE",
    }
    return hints.get(ext_id, "IANA 未收录或后端未实现")
