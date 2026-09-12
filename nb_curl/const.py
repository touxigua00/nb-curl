"""nb_curl.const —— 用到的 libcurl 常量

只列出本项目真正使用的部分，数值取自本仓库的 curl-8.22.0 头文件（含 curl-impersonate 扩展）。

注意：curl-impersonate 的自定义 option 号（1000+）与 curl_cffi 上游的编号并不相同，
本库一律以 C 层 curl.h 为准（见 内置指纹_C层实现梳理_v0.1.md §5）。
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
# CURLOPT 基类型（决定参数怎么传）
# --------------------------------------------------------------------------- #
CURLOPTTYPE_LONG = 0
CURLOPTTYPE_OBJECTPOINT = 10000
CURLOPTTYPE_FUNCTIONPOINT = 20000
CURLOPTTYPE_OFF_T = 30000
CURLOPTTYPE_BLOB = 40000

# --------------------------------------------------------------------------- #
# CURL_SSLVERSION
# --------------------------------------------------------------------------- #
CURL_SSLVERSION_DEFAULT = 0
CURL_SSLVERSION_TLSv1 = 1
CURL_SSLVERSION_TLSv1_0 = 4
CURL_SSLVERSION_TLSv1_1 = 5
CURL_SSLVERSION_TLSv1_2 = 6
CURL_SSLVERSION_TLSv1_3 = 7
CURL_SSLVERSION_MAX_DEFAULT = CURL_SSLVERSION_TLSv1 << 16
CURL_SSLVERSION_MAX_TLSv1_2 = CURL_SSLVERSION_TLSv1_2 << 16
CURL_SSLVERSION_MAX_TLSv1_3 = CURL_SSLVERSION_TLSv1_3 << 16

# --------------------------------------------------------------------------- #
# CURLINFO（easy_getinfo_* 用）
# --------------------------------------------------------------------------- #
CURLINFO_STRING = 0x100000
CURLINFO_LONG = 0x200000
CURLINFO_DOUBLE = 0x300000
CURLINFO_SLIST = 0x400000
CURLINFO_OFF_T = 0x600000

CURLINFO_EFFECTIVE_URL = CURLINFO_STRING + 1
CURLINFO_RESPONSE_CODE = CURLINFO_LONG + 2
CURLINFO_TOTAL_TIME = CURLINFO_DOUBLE + 3
CURLINFO_NAMELOOKUP_TIME = CURLINFO_DOUBLE + 4
CURLINFO_CONNECT_TIME = CURLINFO_DOUBLE + 5
CURLINFO_SIZE_DOWNLOAD_T = CURLINFO_OFF_T + 8
CURLINFO_STARTTRANSFER_TIME = CURLINFO_DOUBLE + 17
CURLINFO_CONTENT_TYPE = CURLINFO_STRING + 18
CURLINFO_REDIRECT_COUNT = CURLINFO_LONG + 20
CURLINFO_COOKIELIST = CURLINFO_SLIST + 28
CURLINFO_PRIMARY_IP = CURLINFO_STRING + 32
CURLINFO_HTTP_VERSION = CURLINFO_LONG + 46

# CURLINFO_HTTP_VERSION 的取值
CURL_HTTP_VERSION_NONE = 0
CURL_HTTP_VERSION_1_0 = 1
CURL_HTTP_VERSION_1_1 = 2
CURL_HTTP_VERSION_2_0 = 3
CURL_HTTP_VERSION_2TLS = 4
CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE = 5
CURL_HTTP_VERSION_3 = 30
CURL_HTTP_VERSION_3ONLY = 31

_HTTP_VERSION_NAMES = {
    CURL_HTTP_VERSION_NONE: "0",
    CURL_HTTP_VERSION_1_0: "1.0",
    CURL_HTTP_VERSION_1_1: "1.1",
    CURL_HTTP_VERSION_2_0: "2",
    CURL_HTTP_VERSION_2TLS: "2",
    CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: "2",
    CURL_HTTP_VERSION_3: "3",
    CURL_HTTP_VERSION_3ONLY: "3",
}


def http_version_name(value: int) -> str:
    return _HTTP_VERSION_NAMES.get(value, "0")


# 用户友好的 http_version 入参 -> easy_set_http_version 的内部编号
HTTP_VERSION_ALIASES = {
    None: None,
    0: 0,
    "1": 11,
    "1.0": 10,
    "1.1": 11,
    "2": 20,
    "2.0": 20,
    "2tls": 21,
    "2_prior_knowledge": 22,
    "default": None,
}

# 本构建未启用 HTTP/3（无 ngtcp2/quiche）——传 3 系列会在 C 层被
# setopt_HTTP_VERSION 拒绝（CURLE_NOT_BUILT_IN），这里提前给出可读报错
_HTTP3_INPUTS = frozenset({"3", "3.0", "3only", 30, 31})

# easy_set_http_version 的合法内部编号（与 C 层实现对应）
_VALID_HTTP_VERSION_CODES = frozenset({0, 10, 11, 20, 21, 22})

_ALLOWED_HINT = (
    "None/\"default\"（自动）、\"1\"/\"1.0\"/\"1.1\"、"
    "\"2\"/\"2.0\"、\"2tls\"、\"2_prior_knowledge\""
)


def resolve_http_version(value):
    """把用户输入的 http_version 解析成 easy_set_http_version 的内部编号。

    非法值抛 ``ValueError``（HTTP/3 会提示本构建未启用）。
    这是 http_version 的唯一合法入口校验，session/aio 都走这里。
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(
            "http_version 不接受布尔值。允许: %s" % _ALLOWED_HINT)
    if isinstance(value, str):
        key = value.strip().lower()
        if key in _HTTP3_INPUTS:
            raise ValueError(
                "http_version=%r: 本构建未启用 HTTP/3（未编译 ngtcp2/quiche）。"
                "允许: %s" % (value, _ALLOWED_HINT))
        if key in HTTP_VERSION_ALIASES:
            return HTTP_VERSION_ALIASES[key]
        raise ValueError(
            "http_version=%r 无法识别。允许: %s" % (value, _ALLOWED_HINT))
    # 数字：允许 0（默认）与桥接层内部编号
    code = int(value)
    if code in _HTTP3_INPUTS:
        raise ValueError(
            "http_version=%r: 本构建未启用 HTTP/3（未编译 ngtcp2/quiche）。"
            "允许: %s" % (value, _ALLOWED_HINT))
    if code in _VALID_HTTP_VERSION_CODES:
        return code
    raise ValueError(
        "http_version=%r 无法识别（若想传内部编号，合法值为 "
        "0/10/11/20/21/22；推荐用字符串别名）。允许: %s"
        % (value, _ALLOWED_HINT))
