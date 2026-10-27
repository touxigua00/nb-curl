"""nb_curl 异常体系（对齐 requests / curl_cffi 的习惯叫法）。"""

from __future__ import annotations

from .const import CURLINFO_PROXY_ERROR, proxy_error_name

__all__ = [
    "NbCurlError",
    "RequestError",
    "ImpersonateError",
    "FingerprintError",
    "HTTPError",
    "Timeout",
    "ConnectTimeout",
    "ProxyError",
    "TooManyRedirects",
    "UnsupportedError",
    "TCPShapeError",
    "TCPShapeWarning",
    "CURL_ERROR_DOC",
    "CURLINFO_PROXY_ERROR",
    "curl_hint",
    "curl_proxy_hint",
    "curl_error_detail",
]

#: libcurl 官方错误码手册（所有 *Error 报错都会带上它，方便直接对照排查）
CURL_ERROR_DOC = "https://curl.se/libcurl/c/libcurl-errors.html"

# 常见 CURLcode 的中文一句话说明。只收最常撞到的那些；没收录的回退到符号名。
# 加条目时注意别用括号，避免和外层 "(curl 60 ...)" 的括号打架。
_CURL_HINT = {
    1: "不支持的协议",
    2: "初始化失败",
    3: "URL 格式错误",
    5: "代理解析失败",
    6: "域名解析失败，可检查 DNS / 代理 / resolve=",
    7: "连接失败：网络不可达、端口未开或被拒绝",
    16: "HTTP/2 协议层错误",
    18: "只收到部分数据",
    23: "写响应数据失败",
    26: "读取上传数据失败",
    27: "内存不足",
    28: "操作超时，可放大 timeout=",
    35: "TLS 握手失败：密码套件 / 协议版本 / 指纹不被服务端接受",
    47: "重定向次数超限，可放大 max_redirects=",
    51: "对端证书或公钥指纹校验失败",
    52: "服务器无任何响应",
    55: "发送请求数据失败",
    56: "接收响应数据失败：连接被中途关闭",
    58: "读取本地证书文件失败",
    60: "对端证书校验失败：自签 / 过期 / 域名不匹配 / 缺中间证书，可检查 verify= 与 CA 配置",
    77: "读取本地 CA 证书库失败：CA 文件路径或权限有问题",
    97: "代理握手失败：代理地址或协议配错、代理服务没在跑，或该端口其实不是代理；"
        '可传 proxy="" 显式禁用代理',
}

# CURLE_PROXY（97）的细粒度子原因（CURLINFO_PROXY_ERROR）中文说明。
# 97 本身只有一句笼统的 proxy handshake error，靠它才能说清是哪一步坏的。
_PROXY_PX_HINT = {
    "CURLPX_BAD_ADDRESS_TYPE": "对端回的地址类型不认识，多半不是 SOCKS 代理",
    "CURLPX_BAD_VERSION": "对端回的版本号不是 SOCKS4/5，该端口多半不是代理或代理类型配错了",
    "CURLPX_CLOSED": "代理在握手途中关掉了连接",
    "CURLPX_GSSAPI": "代理 GSSAPI 认证失败",
    "CURLPX_GSSAPI_PERMSG": "GSSAPI 逐消息保护失败",
    "CURLPX_GSSAPI_PROTECTION": "GSSAPI 保护级别协商失败",
    "CURLPX_IDENTD": "identd 认证失败",
    "CURLPX_IDENTD_DIFFER": "identd 返回的用户名与请求不一致",
    "CURLPX_LONG_HOSTNAME": "主机名超过代理能接受的长度",
    "CURLPX_LONG_PASSWD": "代理密码过长",
    "CURLPX_LONG_USER": "代理用户名过长",
    "CURLPX_NO_AUTH": "代理要求认证但没给凭据，或它不接受这种认证方式",
    "CURLPX_RECV_ADDRESS": "读代理回的地址失败",
    "CURLPX_RECV_AUTH": "读代理的认证应答失败",
    "CURLPX_RECV_CONNECT": "读代理的连接应答失败",
    "CURLPX_RECV_REQACK": "读代理的请求应答失败",
    "CURLPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED": "代理不支持这种地址类型",
    "CURLPX_REPLY_COMMAND_NOT_SUPPORTED": "代理不支持这条命令",
    "CURLPX_REPLY_CONNECTION_REFUSED": "代理连不上目标站点",
    "CURLPX_REPLY_GENERAL_SERVER_FAILURE": "代理自身故障",
    "CURLPX_REPLY_HOST_UNREACHABLE": "代理到目标主机不可达",
    "CURLPX_REPLY_NETWORK_UNREACHABLE": "代理到目标网段不可达",
    "CURLPX_REPLY_NOT_ALLOWED": "代理规则不允许访问该目标",
    "CURLPX_REPLY_TTL_EXPIRED": "代理侧 TTL 过期",
    "CURLPX_REPLY_UNASSIGNED": "代理回了未分配的应答码",
    "CURLPX_REQUEST_FAILED": "代理请求失败",
    "CURLPX_RESOLVE_HOST": "代理侧域名解析失败",
    "CURLPX_SEND_AUTH": "向代理发认证信息失败",
    "CURLPX_SEND_CONNECT": "向代理发连接请求失败",
    "CURLPX_SEND_REQUEST": "向代理发请求失败",
    "CURLPX_UNKNOWN_FAIL": "代理未报告具体原因",
    "CURLPX_UNKNOWN_MODE": "代理模式不对",
    "CURLPX_USER_REJECTED": "代理拒绝了这次请求",
}


def curl_hint(code: int) -> str:
    """常见 CURLcode 的中文说明；没收录的错误码返回空串。"""
    return _CURL_HINT.get(int(code), "")


def curl_proxy_hint(proxy_error: int) -> str:
    """CURLINFO_PROXY_ERROR 子原因码的中文说明；没收录的返回空串。"""
    return _PROXY_PX_HINT.get(proxy_error_name(proxy_error), "")


def _one_line(text: str) -> str:
    """压成一行：换行 / 制表 / 连续空白统一折叠成一个空格。

    报错文案是给日志看的：带换行时会撑成好几行，把上下文挤走（一行 ERROR
    变成"一大坨"）。细节一个字不删，只是不再换行 —— 需要细看的人顺着看下去
    即可，不需要的人也不受影响。
    """
    return " ".join(str(text).split())


def curl_error_detail(code: int, message: str, *,
                      proxy_error: int | None = None,
                      proxy_in_use: str | None = None) -> str:
    """统一的报错文案：原始信息 + CURLcode 数值/符号名 + 中文说明 + 官方手册链接。

    **整条文案保证是单行**（换行会被折叠成空格），形如::

        SSL peer certificate ... (curl 60 CURLE_PEER_FAILED_VERIFICATION，对端证书校验失败：...，错误码说明请参考：https://curl.se/libcurl/c/libcurl-errors.html)

    代理相关的错误再在同一行里补两段，因为 97 的原文只说"代理握手失败"，既看不出
    是哪一步坏（``proxy_error`` = ``CURLINFO_PROXY_ERROR``），也看不出走的是哪个
    代理（``proxy_in_use``）—— 没配过代理却看到 97 时，这两段就是破案线索。
    """
    from ._curle_generated import curl_error_name

    hint = curl_hint(code)
    tail = "%d %s" % (code, curl_error_name(code))
    if hint:
        tail += "，" + hint
    detail = "%s (curl %s，错误码说明请参考：%s)" % (message, tail, CURL_ERROR_DOC)

    extra = []
    if proxy_error:
        name = proxy_error_name(proxy_error)
        part = "代理子原因 %d %s" % (int(proxy_error), name)
        px_hint = _PROXY_PX_HINT.get(name)
        if px_hint:
            part += "，" + px_hint
        extra.append(part)
    if proxy_in_use:
        extra.append(
            '本次请求走了代理 %s；若不是本意，传 proxy="" 显式禁用，'
            "或清掉 http_proxy / https_proxy / all_proxy 环境变量后重试" % proxy_in_use)
    if extra:
        detail += "；" + "；".join(extra)
    return _one_line(detail)


class NbCurlError(Exception):
    """所有 nb_curl 异常的基类。"""


class RequestError(NbCurlError):
    """请求执行失败（对应 CURLcode != CURLE_OK）。

    ``code`` 是 libcurl 的 CURLcode 数值，``curl_name`` 是其符号名
    （如 ``56`` / ``"CURLE_RECV_ERROR"``），完整表见
    https://curl.se/libcurl/c/libcurl-errors.html
    """

    def __init__(self, message: str, code: int | None = None):
        super().__init__(message)
        self.code = code

    @property
    def curl_name(self) -> str | None:
        if self.code is None:
            return None
        from ._curle_generated import curl_error_name

        return curl_error_name(self.code)

    def __repr__(self) -> str:
        if self.code is None:
            return "%s(%r)" % (type(self).__name__, str(self))
        return "%s(curl=%d %s, %r)" % (
            type(self).__name__, self.code, self.curl_name, str(self))


class ImpersonateError(NbCurlError):
    """impersonate target 不存在或不可用。"""


class FingerprintError(NbCurlError):
    """ja3 / akamai / diy_fp / fp_file 解析或下发失败。"""


class HTTPError(NbCurlError):
    """HTTP 状态码异常（raise_for_status 抛出）。"""

    def __init__(self, message: str, response=None):
        super().__init__(message)
        self.response = response


class Timeout(RequestError):
    """请求超时。"""


class ConnectTimeout(Timeout):
    """连接超时。"""


class ProxyError(RequestError):
    """代理相关失败。"""


class TooManyRedirects(RequestError):
    """重定向次数超限。"""


class UnsupportedError(NbCurlError):
    """使用了本库尚未支持的特性。"""


class TCPShapeError(NbCurlError):
    """TCP 画像参数本身不合法（格式 / 类型 / 取值越界）。

    "本机做不到"（option 顺序改不了、wscale 上不去、MSS 压不下来…）**不抛异常**，
    只发 :class:`TCPShapeWarning`，请求照常发出。
    """


class TCPShapeWarning(UserWarning):
    """TCP 画像里"本机做不到"的项：请求照发，但那一项不会生效。

    关掉它的两种办法::

        import warnings, nb_curl
        warnings.simplefilter("ignore", nb_curl.TCPShapeWarning)   # 标准做法
        nb_curl.set_tcp_warnings(False)                            # 本库快捷开关
    """
