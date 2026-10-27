"""nb_curl.options —— curl_options 直通（对标 curl_cffi 的 curl_options 参数）

把 libcurl 的 ``curl_easy_setopt`` 以"option 编号 + 值"的形式直接暴露给用户，
自定义程度拉满。所有 option 编号与类型标记由 ``_curlopt_generated.py`` 自动从 curl.h
提取，避免手抄出错。

**怎么导入**：``nb_curl`` 包里的 ``options`` 这个名字是 HTTP 的 OPTIONS **函数**
（requests 习惯，见 :mod:`nb_curl.session`），它会遮蔽同名子模块，所以
``nb_curl.options.CurlOpt`` / ``import nb_curl.options as opt`` 都拿不到本模块。
按名字导入即可，两种写法都行::

    from nb_curl.options import CurlOpt, SAFE_OPTIONS     # 推荐
    from nb_curl import CurlOpt                            # 顶层也导出了 CurlOpt

安全模型（重要）：

* 每个 option 的值类型（long/string/slist/off_t/回调/blob）由 curl.h 的
  ``CURLOPTTYPE_*`` 决定，Python 侧据此调用对应的后端方法（``set_option_long`` 等），
  类型传错后果自负（libcurl 会返回 ``CURLE_BAD_FUNCTION_ARGUMENT``）。
* 回调函数指针 / 回调 data 指针 / blob / 二进制 object point **永远拒绝**——
  Python 没法构造合法的 C 函数指针或对象指针，传了会崩或行为未定义。
* 剩下的 option 分三档：
  - ``SAFE_OPTIONS``：不影响指纹/连接池/回调契约，默认允许；
  - ``DANGEROUS_OPTIONS``：会破坏指纹或与专用参数冲突（如 ``HTTP_VERSION``、
    ``SSL_CIPHER_LIST``、``HTTPHEADER``、``POSTFIELDS``…），需 ``allow_dangerous=True``；
  - 其他合法 vtype 的 option：``allow_dangerous=True`` 时放行，否则报错列出。

示例：

    import nb_curl
    s = nb_curl.Session(impersonate="chrome155")
    s.get(url, curl_options={
        nb_curl.CurlOpt.DOH_URL: "https://1.1.1.1/dns-query",
        nb_curl.CurlOpt.INTERFACE: "192.0.2.10",
        nb_curl.CurlOpt.MAX_RECV_SPEED_LARGE: 1024 * 1024,  # 1 MB/s
    })
"""
from __future__ import annotations

from ._curlopt_generated import CurlOpt, _VTYPE

__all__ = ["CurlOpt", "apply_curl_options", "SAFE_OPTIONS", "DANGEROUS_OPTIONS",
           "CURLWS_TEXT", "CURLWS_BINARY", "CURLWS_CONT", "CURLWS_CLOSE",
           "CURLWS_PING", "CURLWS_PONG", "CURLWS_OFFSET",
           "CURLWS_RAW_MODE", "CURLWS_NOAUTOPONG",
           "CURLE_AGAIN", "CURLE_GOT_NOTHING"]

# 帧类型 flag（WebSocket 用，与 curl 的 CURLWS_* 一致；见 curl/websockets.h）
CURLWS_TEXT = 1
CURLWS_BINARY = 2
CURLWS_CONT = 4
CURLWS_CLOSE = 8
CURLWS_PING = 0x10
# recv meta 里的"这是帧内偏移片段"位（不是 PONG！）
CURLWS_OFFSET = 0x20
# 真正的 PONG 发送位（1<<6）。旧值 0x20 是 CURLWS_OFFSET，
# 用它发 PONG 会被 curl 抹成 0 -> CURLE_BAD_FUNCTION_ARGUMENT(43)。
CURLWS_PONG = 0x40

# CURLOPT_WS_OPTIONS 的取值位（curl/websockets.h）
CURLWS_RAW_MODE = 1
# 关掉 libcurl 自动回 PONG；置上后必须由应用自己回 PONG。
# 必须在 **握手前** 设：libcurl 的自动 PONG 在纯 curl_ws_recv 轮询下不会被 flush。
CURLWS_NOAUTOPONG = 2

# CURLE_AGAIN：ws_recv / ws_send 无数据可读（不可写）时返回
CURLE_AGAIN = 81
# CURLE_GOT_NOTHING：对端没发 CLOSE 就直接断开
CURLE_GOT_NOTHING = 52
# 桥接层自定义：option 编号不在该类型区间
_BAD_OPTION_RANGE = -2


# 不影响指纹/连接池/回调契约，默认允许。
# 注意：RESOLVE / FRESH_CONNECT / VERBOSE / TIMEOUT_MS 等已有专用参数，
#       这里允许是为了"高级用户想绕过 Session 装配直接设"的场景。
SAFE_OPTIONS = frozenset({
    CurlOpt.RESOLVE,
    CurlOpt.DOH_URL,
    CurlOpt.INTERFACE,
    CurlOpt.DNS_INTERFACE,
    CurlOpt.PINNEDPUBLICKEY,
    CurlOpt.PROXY_PINNEDPUBLICKEY,
    CurlOpt.DNS_CACHE_TIMEOUT,
    CurlOpt.MAX_RECV_SPEED_LARGE,
    CurlOpt.MAX_SEND_SPEED_LARGE,
    CurlOpt.BUFFERSIZE,
    CurlOpt.UPLOAD_BUFFERSIZE,
    CurlOpt.TCP_KEEPALIVE,
    CurlOpt.TCP_KEEPIDLE,
    CurlOpt.TCP_KEEPINTVL,
    CurlOpt.IPRESOLVE,
    CurlOpt.HAPPY_EYEBALLS_TIMEOUT_MS,
    CurlOpt.EXPECT_100_TIMEOUT_MS,
    CurlOpt.MAXCONNECTS,
    # 源端口绑定：只影响本地端口选择，不动任何指纹字段
    CurlOpt.LOCALPORT,
    CurlOpt.LOCALPORTRANGE,
    CurlOpt.FORBID_REUSE,
    CurlOpt.FRESH_CONNECT,
    CurlOpt.UNIX_SOCKET_PATH,
    CurlOpt.ABSTRACT_UNIX_SOCKET,
    CurlOpt.WS_OPTIONS,
    CurlOpt.WS_HTTPHEADER,
    CurlOpt.WS_HTTPHEADER_ORDER,
    CurlOpt.WS_SSL_DISABLE_TICKET,
    CurlOpt.WS_SSL_CERT_COMPRESSION,
    CurlOpt.ECH,
    CurlOpt.DOH_SSL_VERIFYPEER,
    CurlOpt.DOH_SSL_VERIFYHOST,
    CurlOpt.DOH_SSL_VERIFYSTATUS,
})

# 会破坏指纹、或与 Session 专用参数冲突。allow_dangerous=True 才放行。
DANGEROUS_OPTIONS = frozenset({
    # 协议/TLS 版本 —— 改变指纹
    CurlOpt.HTTP_VERSION,
    CurlOpt.SSLVERSION,
    CurlOpt.SSL_CIPHER_LIST,
    CurlOpt.TLS13_CIPHERS,
    CurlOpt.SSL_EC_CURVES,
    CurlOpt.SSL_SIGNATURE_ALGORITHMS,
    # curl-impersonate 的 TLS/H2 扩展 —— 直接动指纹，应走 diy_fp/ja3/akamai
    CurlOpt.TLS_EXTENSION_ORDER,
    CurlOpt.SSL_CERT_COMPRESSION,
    CurlOpt.TLS_DELEGATED_CREDENTIALS,
    CurlOpt.TLS_TRUST_ANCHORS,
    CurlOpt.TLS_GREASE,
    CurlOpt.TLS_GREASE_SIGALGS,
    CurlOpt.SSL_PERMUTE_EXTENSIONS,
    CurlOpt.HTTP2_SETTINGS,
    CurlOpt.HTTP2_WINDOW_UPDATE,
    CurlOpt.HTTP2_PSEUDO_HEADERS_ORDER,
    CurlOpt.HTTP2_STREAMS,
    CurlOpt.HTTP2_NO_PRIORITY,
    CurlOpt.HTTPHEADER_ORDER,
    CurlOpt.HTTPHEADER,
    CurlOpt.HTTPBASEHEADER,
    # 请求体/方法 —— 与 Session 装配冲突
    CurlOpt.POSTFIELDS,
    CurlOpt.POSTFIELDSIZE,
    CurlOpt.COPYPOSTFIELDS,
    CurlOpt.CUSTOMREQUEST,
    CurlOpt.HTTPGET,
    CurlOpt.NOBODY,
    CurlOpt.MIMEPOST,
    CurlOpt.URL,
    CurlOpt.COOKIE,
    CurlOpt.COOKIELIST,
    CurlOpt.COOKIEFILE,
    CurlOpt.COOKIEJAR,
    # 连接/复用 —— 与专用参数冲突
    CurlOpt.CONNECT_ONLY,
    CurlOpt.PROXY,
    CurlOpt.SSL_VERIFYPEER,
    CurlOpt.SSL_VERIFYHOST,
    CurlOpt.CAINFO,
    CurlOpt.FOLLOWLOCATION,
    CurlOpt.MAXREDIRS,
    CurlOpt.TIMEOUT_MS,
    CurlOpt.CONNECTTIMEOUT_MS,
})


def apply_curl_options(lib, handle, options, *, allow_dangerous: bool = False) -> None:
    """把 ``{CurlOpt: value}`` 逐项下发到 handle。

    :param lib: nb_curl._native.lib（后端实例）
    :param handle: native easy handle（``_Handle.ptr``）
    :param options: ``{CurlOpt|int: value}``，value 为 long/string/list[str]/int(off_t)
    :param allow_dangerous: True 时放行 ``DANGEROUS_OPTIONS`` 与未在白名单的合法 vtype option
    :raises ValueError: option 类型不支持直传（回调/blob/二进制指针），或在
        ``allow_dangerous=False`` 时使用了危险/未知 option
    """
    if not options:
        return
    items = options.items() if hasattr(options, "items") else options
    for opt, value in items:
        # 接受 CurlOpt 枚举或裸 int
        opt_int = int(opt)
        opt_name = opt.name if hasattr(opt, "name") else "option %d" % opt_int
        vtype = _VTYPE_VALUES.get(opt_int)
        if vtype is None:
            raise ValueError("%s 不是已知的 curl option（不在 curl.h 的 CURLOPT 表里）。"
                             % opt_name)

        if vtype in ("f", "c", "b", "p"):
            raise ValueError(
                "%s 的值类型（%s）不支持直传：回调/blob/二进制指针类 option "
                "无法从 Python 安全传递。" % (opt_name, vtype))

        if opt_int in _SAFE_INT:
            pass
        elif opt_int in _DANGEROUS_INT:
            if not allow_dangerous:
                raise ValueError(
                    "%s 会破坏指纹或与专用参数冲突，需 curl_options(..., "
                    "allow_dangerous=True) 才能使用。" % opt_name)
        else:
            if not allow_dangerous:
                raise ValueError(
                    "%s 不在白名单内。如确需设置，传 curl_options(..., "
                    "allow_dangerous=True)；白名单见 from nb_curl.options import "
                    "SAFE_OPTIONS。" % opt_name)

        code = _dispatch(lib, handle, opt_int, vtype, value)
        if code != 0:
            from .exceptions import RequestError, curl_error_detail
            raise RequestError(
                curl_error_detail(
                    code, "设置 %s 失败: %s" % (opt_name, lib.strerror(code))),
                code)


# 预计算 int 集合，避免每次请求都重新 frozenset().__contains__ 枚举对象
_SAFE_INT = frozenset(int(o) for o in SAFE_OPTIONS)
_DANGEROUS_INT = frozenset(int(o) for o in DANGEROUS_OPTIONS)
_VTYPE_VALUES = {int(k): v for k, v in _VTYPE.items()}


def _dispatch(lib, handle, opt_int: int, vtype: str, value) -> int:
    if vtype == "i":
        return lib.set_option_long(handle, opt_int, int(value))
    if vtype == "s":
        if value is None:
            return lib.set_option_string(handle, opt_int, None)
        if isinstance(value, bytes):
            return lib.set_option_string(handle, opt_int, value)
        return lib.set_option_string(handle, opt_int, str(value).encode("utf-8"))
    if vtype == "l":
        if value is None:
            return lib.set_option_slist(handle, opt_int, [])
        if isinstance(value, (str, bytes)):
            entries = [value if isinstance(value, bytes) else value.encode("utf-8")]
        elif isinstance(value, str):
            entries = [value.encode("utf-8")]
        else:
            entries = [
                v if isinstance(v, bytes) else str(v).encode("utf-8")
                for v in value
            ]
        return lib.set_option_slist(handle, opt_int, entries)
    if vtype == "o":
        return lib.set_option_off(handle, opt_int, int(value))
    # 不该到这里（f/c/b/p 已在调用前拒绝）
    raise ValueError("未知 vtype: %r" % vtype)
