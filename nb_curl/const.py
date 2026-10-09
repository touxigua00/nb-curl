"""nb_curl.const —— 用到的 libcurl 常量

只列出本项目真正使用的部分，数值与所链接的 libcurl（含 curl-impersonate 扩展）保持一致。

注意：curl-impersonate 的自定义 option 号（1000+）与 curl_cffi 上游的编号并不相同，
本库一律以 C 层实际实现为准。
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
CURLINFO_PROXY_ERROR = CURLINFO_LONG + 59

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


# --------------------------------------------------------------------------- #
# CURLINFO_PROXY_ERROR 的取值（CURLproxycode）
#
# 只有 CURLcode == CURLE_PROXY（97）时才被填充，用来区分"代理到底是哪一步坏的"
# —— 否则 97 的文案只有一句笼统的 proxy handshake error，分不清是端口不对、
# 认证没过还是被代理拒绝。下标即取值，名字沿用 libcurl 的叫法。
# --------------------------------------------------------------------------- #
CURLPX_NAMES = (
    "CURLPX_OK",                              # 0
    "CURLPX_BAD_ADDRESS_TYPE",                # 1
    "CURLPX_BAD_VERSION",                     # 2
    "CURLPX_CLOSED",                          # 3
    "CURLPX_GSSAPI",                          # 4
    "CURLPX_GSSAPI_PERMSG",                   # 5
    "CURLPX_GSSAPI_PROTECTION",               # 6
    "CURLPX_IDENTD",                          # 7
    "CURLPX_IDENTD_DIFFER",                   # 8
    "CURLPX_LONG_HOSTNAME",                   # 9
    "CURLPX_LONG_PASSWD",                     # 10
    "CURLPX_LONG_USER",                       # 11
    "CURLPX_NO_AUTH",                         # 12
    "CURLPX_RECV_ADDRESS",                    # 13
    "CURLPX_RECV_AUTH",                       # 14
    "CURLPX_RECV_CONNECT",                    # 15
    "CURLPX_RECV_REQACK",                     # 16
    "CURLPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED",  # 17
    "CURLPX_REPLY_COMMAND_NOT_SUPPORTED",     # 18
    "CURLPX_REPLY_CONNECTION_REFUSED",        # 19
    "CURLPX_REPLY_GENERAL_SERVER_FAILURE",    # 20
    "CURLPX_REPLY_HOST_UNREACHABLE",          # 21
    "CURLPX_REPLY_NETWORK_UNREACHABLE",       # 22
    "CURLPX_REPLY_NOT_ALLOWED",               # 23
    "CURLPX_REPLY_TTL_EXPIRED",               # 24
    "CURLPX_REPLY_UNASSIGNED",                # 25
    "CURLPX_REQUEST_FAILED",                  # 26
    "CURLPX_RESOLVE_HOST",                    # 27
    "CURLPX_SEND_AUTH",                       # 28
    "CURLPX_SEND_CONNECT",                    # 29
    "CURLPX_SEND_REQUEST",                    # 30
    "CURLPX_UNKNOWN_FAIL",                    # 31
    "CURLPX_UNKNOWN_MODE",                    # 32
    "CURLPX_USER_REJECTED",                   # 33
)


def proxy_error_name(value: int) -> str:
    """CURLINFO_PROXY_ERROR 的数值 -> 符号名；越界回退 ``CURLPX_<n>``。"""
    try:
        return CURLPX_NAMES[int(value)]
    except (IndexError, TypeError, ValueError):
        return "CURLPX_%s" % (value,)


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
    "3": 30,
    "3.0": 30,
    "3only": 31,
    "default": None,
}

# easy_set_http_version 的合法内部编号（与 C 层实现对应，30/31 = HTTP/3）
_VALID_HTTP_VERSION_CODES = frozenset({0, 10, 11, 20, 21, 22, 30, 31})

_ALLOWED_HINT = (
    "None/\"default\"（自动）、\"1\"/\"1.0\"/\"1.1\"、"
    "\"2\"/\"2.0\"、\"2tls\"、\"2_prior_knowledge\"、"
    "\"3\"/\"3.0\"/\"3only\"（HTTP/3）"
)


def resolve_http_version(value):
    """把用户输入的 http_version 解析成 easy_set_http_version 的内部编号。

    非法值抛 ``ValueError``。HTTP/3 需要编译时启用 ngtcp2+nghttp3
    （官方预编译轮子已启用）；若本构建未含 H3，curl 会在 setopt 时返回
    CURLE_NOT_BUILT_IN。
    这是 http_version 的唯一合法入口校验，session/aio 都走这里。
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(
            "http_version 不接受布尔值。允许: %s" % _ALLOWED_HINT)
    if isinstance(value, str):
        key = value.strip().lower()
        if key in HTTP_VERSION_ALIASES:
            return HTTP_VERSION_ALIASES[key]
        raise ValueError(
            "http_version=%r 无法识别。允许: %s" % (value, _ALLOWED_HINT))
    # 数字：先按字符串别名认一遍（3 -> "3"、3.0 -> "3.0"，与字符串写法等价），
    # 再兜底接受桥接层内部编号
    key = str(value).strip().lower()
    if key in HTTP_VERSION_ALIASES:
        return HTTP_VERSION_ALIASES[key]
    code = int(value)
    if code in _VALID_HTTP_VERSION_CODES:
        return code
    raise ValueError(
        "http_version=%r 无法识别（数值写法支持 1 / 1.0 / 1.1 / 2 / 2.0 / 3 / 3.0；"
        "若想传内部编号，合法值为 0/10/11/20/21/22/30/31；推荐用字符串别名）。"
        "允许: %s" % (value, _ALLOWED_HINT))
