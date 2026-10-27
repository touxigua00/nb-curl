"""nb_curl.params —— 所有公开参数的声明与说明（唯一事实来源）。

公开入口（``nb_curl.get`` / ``Session.get`` / ``Session(...)``）不再各自重复一遍参数表：
参数在本模块用 TypedDict 声明一次，各入口用 ``**options`` 接收。
所以「有哪些参数、什么类型、怎么给」只有这一处答案，加参数也只改这一个文件。

运行时就能查（不用翻源码）：

    from nb_curl import params
    help(params.RequestOptions)     # 请求级参数（get/post/… 通用）
    help(params.SessionOptions)     # Session(...) 的参数
    help(params.TcpShape)           # tcp= 传 dict 时可用哪些键
    print(params.describe("request"))   # 同上，输出纯文本表

常用组合速查：

    指纹    impersonate="chrome155" / ja3="…" / akamai="…" / diy_fp={…} / fp_file="x.json"
    协议    http_version="2" | "3" | "1.1"
    证书    verify=False / ca_path="ca.pem" / pinned_key="sha256//…"
    代理    proxy="socks5h://127.0.0.1:1080" / proxies={"https": "…"}；proxy="" 屏蔽环境代理
    解析    resolve={"example.com:443": "1.2.3.4"} / doh="https://1.1.1.1/dns-query"
    链路    interface="eth0" / tcp="64240_2-1-3-1-1-4_1400_8" / ttl=64 / timestamps=True
    逃生口  curl_options={CurlOpt.MAX_RECV_SPEED_LARGE: 102400}
"""

from __future__ import annotations

import ast as _ast
import inspect as _inspect
import sys as _sys
import textwrap as _textwrap
from typing import Any, Mapping, Sequence, TypedDict

from .fingerprint import Fingerprint
from .impersonate import ImpersonateTarget

if _sys.version_info >= (3, 11):
    from typing import Unpack
else:  # 3.9 / 3.10：注解在运行时不求值，Unpack 只给类型检查器看
    try:
        from typing_extensions import Unpack
    except ImportError:  # pragma: no cover - 没有 typing_extensions 也能跑

        class Unpack:  # type: ignore[no-redef]
            """占位符：``from __future__ import annotations`` 下注解不会被求值。"""

            def __class_getitem__(cls, item: Any) -> Any:
                return item


__all__ = [
    "TcpShape",
    "RequestOptions",
    "SessionOptions",
    "REQUEST_KEYS",
    "SESSION_KEYS",
    "SESSION_ONLY_KEYS",
    "SESSION_DEFAULTS",
    "check_options",
    "describe",
]


# --------------------------------------------------------------------------- #
# tcp= 的 dict 形式
# --------------------------------------------------------------------------- #
class TcpShape(TypedDict, total=False):
    """``tcp=`` 传 dict 时的可用键（只给关心的字段，其余跟随本机）。

    整数段的范围与 JA4T 串一致，越界抛 :class:`nb_curl.TCPShapeError`；
    本机做不到的项只发 :class:`nb_curl.TCPShapeWarning`，请求照发。
    """

    window: int
    """初始通告窗口（1-65535），就是 JA4T 第一段。"""

    order: str
    """TCP option kind 序列，如 ``"2-1-3-1-1-4"``（JA4T 第二段）。
    任何操作系统都改不了，只能填本机原生值：Windows ``2-1-3-1-1-4``、
    Linux ``2-4-8-1-3``（关掉全局时间戳后是 ``2-1-1-4-1-3``）、macOS ``2-1-3-1-1-8-4-0``。
    填别的只发警告。本机原值用 ``nb_curl.tcp_support()`` 查。"""

    mss: int
    """最大报文段（536-65535），JA4T 第三段。Linux 走 ``TCP_MAXSEG`` 逐 socket 生效；
    Windows 上只能改网卡 MTU（``nb_curl.set_interface_mtu()``，需管理员）。"""

    wscale: int
    """窗口缩放（0-14），JA4T 第四段。与 ``window`` 共用 ``SO_RCVBUF``，
    两者无法同时精确达成时**两个都不设**（不改本机默认窗口）。"""


# --------------------------------------------------------------------------- #
# 请求级参数（Session.get / post / … 通用）
# --------------------------------------------------------------------------- #
class RequestOptions(TypedDict, total=False):
    """请求级参数。会话级（``Session(...)``）默认值可被这里的同名参数逐次覆盖。

    一共分五组：请求内容、网络与传输、指纹、协议与连接、TCP 层画像。
    每个参数下面的说明就是它的合法取值；也可以 ``print(nb_curl.params.describe("request"))``。
    """

    # -- 请求内容 ---------------------------------------------------------- #
    params: Any
    """追加到 URL 的查询参数。dict 或 ``(k, v)`` 序列；与 URL 里已有的 query 合并。"""

    headers: Mapping[str, Any] | None
    """本次请求头。覆盖会话级与预设浏览器头里的同名项（位置保持在原处），
    新头追加在末尾。值给 ``None`` 表示删掉该默认头。

    ``Cookie`` 也在这张表里：**写在哪就发在哪**、值原样、只发一条
    （不会被改写到最前面，也不会在 HTTP/2 下被拆成多条）。"""

    cookies: Mapping[str, Any] | None
    """本次请求的 cookie（dict），叠加在 ``session.cookies`` 之上；
    发送顺序就是 dict 的顺序（显式给的在前，会话罐里命中该主机 / 路径 / Secure 的
    按罐内顺序跟在后面，同名不重复），整体拼成**一条** ``Cookie:`` 头、追加在
    你自己那些头的末尾。响应的 Set-Cookie 会自动记回会话。"""

    data: Any
    """请求体。dict → ``application/x-www-form-urlencoded``；
    str/bytes → 原样发送（不自动加 Content-Type）。"""

    json: Any
    """JSON 请求体，自动带 ``Content-Type: application/json``。"""

    files: Mapping[str, Any] | None
    """multipart/form-data 上传：``{"字段名": (文件名, 内容)}`` 或
    ``{"字段名": (文件名, 内容, MIME)}``；值也可以是带 ``.name`` 的文件对象。
    与 ``data`` 同时给时，``data`` 的键作为普通表单字段一起发。"""

    # -- 网络与传输 -------------------------------------------------------- #
    proxy: str | Mapping[str, str] | None
    """单个代理 URL，对所有协议生效，如 ``"socks5h://user:pass@127.0.0.1:1080"``。
    传 ``""`` = **显式禁用代理**（连环境变量里的 http_proxy 都不读）。"""

    proxies: Mapping[str, str] | str | None
    """按协议选代理：``{"http": url, "https": url, "all": url}``。
    与 ``proxy`` 同时给时 ``proxy`` 优先。"""

    resolve: Mapping[str, Any] | Sequence[str] | None
    """DNS 覆盖（等价 curl ``--resolve``）：``{"example.com:443": "1.2.3.4"}``，
    一个域名可给多个地址（``["1.2.3.4", "5.6.7.8"]``）；也可直接给
    ``["example.com:443:1.2.3.4"]`` 这样的原始条目，或 curl 的
    ``"+host:port:addr"``（追加）/ ``"-host:port"``（删除）。
    命中后不再走 DNS。走 http / socks5h 代理时解析由代理做，此项无效。"""

    verify: bool | None
    """是否校验服务端证书。会话级默认 ``True``。"""

    ca_path: str | None
    """CA bundle 路径；不传则自动找：环境变量 ``NB_CURL_CA_BUNDLE`` > certifi > 包内自带。"""

    timeout: float | None
    """整个请求的超时秒数（含传输）。"""

    connect_timeout: float | None
    """仅 TCP/TLS 建连阶段的超时秒数。"""

    allow_redirects: bool | None
    """是否自动跟随重定向。会话级默认 ``True``。"""

    max_redirects: int | None
    """最大重定向次数。会话级默认 30。"""

    credentials: str | None
    """cookie 的携带策略，语义对齐浏览器 ``fetch(..., {credentials})``：

    * ``None`` / ``"include"`` / ``"same-origin"`` —— 正常发 cookie、记住响应里的
      ``Set-Cookie``（裸 HTTP 客户端没有"页面来源"，所以这两档等价）；
    * ``"omit"`` —— 本次请求**既不发也不记** cookie。"""

    auth: Any
    """HTTP 基本认证：``("user", "password")`` 或 ``"user:password"``。"""

    # -- 指纹 -------------------------------------------------------------- #
    impersonate: ImpersonateTarget | str | Fingerprint | None
    """内置浏览器预设名，如 ``"chrome155"`` / ``"firefox147"``；
    家族别名（``"chrome"``）自动取该家族最新版；也可直接传
    ``Fingerprint`` 对象（``parse_xcctls()`` 的结果）。
    完整清单：``nb_curl.available_targets()``。
    加 ``":no"`` 后缀（``"chrome155:no"``）= 不带该预设的浏览器默认请求头。"""

    ja3: str | None
    """JA3 串 ``TLS版本,套件,扩展,group,EC点格式``，覆盖预设的 TLS 层。
    合法取值与写法见 ``nb_curl.tls``。"""

    akamai: str | None
    """Akamai H2 串 ``SETTINGS|WINDOW_UPDATE|STREAMS|伪头顺序``，覆盖预设的 H2 层
    （隐含启用 HTTP/2）。"""

    diy_fp: Mapping[str, Any] | None
    """字段级覆盖（最细的一档），如 ``{"tls_grease": True, "tls_trust_anchors": ""}``。
    HTTP/2 帧可以整帧换：``{"http2_frames": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"}``
    或 ``{"http2_frames": {"settings": {...}, "window_updates": {"0": ...}, "order": "m,a,s,p"}}``。
    可用键与取值范围用 ``nb_curl.diy_fp_fields()`` 查。"""

    fp_file: str | _os.PathLike | Mapping[str, Any] | None
    """指纹快照：浏览器访问 ``https://www.xcctls.top/all`` 拿到的 JSON
    （文件路径、JSON 文本或 dict）。一键复刻整个指纹，含浏览器默认头。
    可与 impersonate/ja3/akamai/diy_fp 叠加，显式参数优先。"""

    # -- 协议与连接 -------------------------------------------------------- #
    http_version: Any
    """强制 HTTP 版本。

    字符串别名：``"1.0"`` / ``"1.1"`` / ``"2"``（等价 2TLS）/ ``"2tls"``（仅 HTTPS 协商
    H2，默认）/ ``"2_prior_knowledge"`` / ``"3"``（HTTP/3）/ ``"3only"``（强制 H3，
    不支持就报错）/ ``"3.0"``（同 ``"3"``）；``None`` 或 ``"default"`` = 按指纹自动。

    数值写法同样认：``1`` / ``1.0`` / ``1.1`` / ``2`` / ``2.0`` / ``3`` / ``3.0``。
    即 ``http_version="3"``、``http_version=3``、``http_version=3.0`` 三者等价，
    都表示走 HTTP/3（服务端不支持时回退到 H2/TLS）。

    给别的值抛 ``ValueError``。
    """

    h2_priority: bool | None
    """HTTP/2 的 HEADERS 帧要不要带已废弃的 RFC 7540 优先级字段
    （Chrome 是 ``0x25``，不带是 ``0x05``）。``None`` = 跟随预设
    （Chrome 系开、Safari 系关），``True`` / ``False`` = 强制。"""

    header_order: str | Sequence[str] | None
    """请求头**发送顺序**（与 ``impersonate`` 同级的显式参数，会话级/请求级都收）。

    写法：``"Host,Connection,sec-ch-ua,..."`` 逗号分隔串，或
    ``["Host", "Connection", "sec-ch-ua", ...]`` 列表（大小写不敏感，重复名只留第一个）。

    语义（C 层 ``CURLOPT_HTTPHEADER_ORDER``）：**名单里的头按给定顺序排到最前，
    名单外的头保持原有相对顺序追加在后**——所以想完全对齐某个模板，要把它发的
    每个头都列进去。``host`` 会被强制提到第一位（浏览器与 curl 默认都是 Host 第一）。

    ``None`` = 跟随 ``impersonate`` 预设（浏览器预设自带顺序）；显式传值则**压过**
    预设与 ``diy_fp={"header_order": …}``。典型用途：按资源类型切模板（导航 vs
    XHR/子资源），见 Chrome 155 实测的两套顺序。"""

    http3_permute_extensions: bool | None
    """HTTP/3 的 QUIC ClientHello 要不要**逐连接随机打乱 TLS 扩展顺序**
    （``CURLOPT_HTTP3_SSL_PERMUTE_EXTENSIONS``）。``None`` = 跟随预设
    （Chrome 系开、其余关），``True`` / ``False`` = 强制。"""

    ech: str | bool | None
    """ECH（Encrypted ClientHello）。``True`` = 尽力（配合 ``doh`` 从 HTTPS RR 取配置），
    ``False`` = 关，或直接给 curl 原值 ``"grease"`` / ``"hard"`` / ``"ecl:<base64>"`` /
    ``"pn:<名字>"``。"""

    doh: str | None
    """DNS-over-HTTPS 服务器 URL，如 ``"https://1.1.1.1/dns-query"``。"""

    dns_cache_ttl: int | None
    """DNS 缓存秒数（默认 60）。"""

    interface: str | None
    """绑定出口网卡 / IP（``CURLOPT_INTERFACE``），如 ``"eth0"`` / ``"192.0.2.10"``。
    多出口、住宅代理轮换用。"""

    pinned_key: str | None
    """证书公钥固定（``CURLOPT_PINNEDPUBLICKEY``），``"sha256//base64…"``。"""

    max_download_speed: int | None
    """下载限速，bytes/s。"""

    max_upload_speed: int | None
    """上传限速，bytes/s。"""

    stream: bool | None
    """流式下载。``True`` 时请求返回时响应体**还在传来**：``iter_content()`` /
    ``iter_lines()`` 边收边给，峰值内存与响应体大小无关（大文件、SSE 类持续输出用它）。
    返回时 ``status_code`` / ``headers`` 已经解析好，可据此决定要不要继续读。

    用完（或半途不要了）要 ``close()`` 释放连接；``content`` / ``text`` / ``json()``
    会把**还没读的部分**整体读完，与非流式语义一致。判断状态看
    :attr:`nb_curl.Response.is_stream` / :attr:`nb_curl.Response.stream_consumed`。

    模块级 ``nb_curl.get(url, stream=True)`` 也支持：内部的临时会话会跟着响应走，
    由 ``response.close()`` 一起关掉（也可以写 ``with nb_curl.get(..., stream=True) as r:``）。"""

    curl_options: Mapping[Any, Any] | None
    """逃生口：``{CurlOpt.X: value}`` 直接 setopt。``CurlOpt`` 从顶层拿即可
    （``nb_curl.CurlOpt``）；白名单用 ``from nb_curl.options import SAFE_OPTIONS`` 看。
    会破坏指纹或与专用参数冲突的项默认被拦，要放行得配 ``allow_dangerous_options=True``。"""

    # -- TCP 层画像（JA4T） ------------------------------------------------ #
    tcp: str | Mapping[str, Any] | None
    """TCP 层画像，就是检测站输出的那串 JA4T 原样：
    ``"64240_2-1-3-1-1-4_1400_8"``（``window_order_mss_wscale``）。
    也可传 dict 只给关心的键，键与取值范围见 :class:`nb_curl.params.TcpShape`。

    本机做不到的项只发 :class:`nb_curl.TCPShapeWarning`、不报错，请求照发；
    只有参数本身写错（格式 / 范围）才抛 :class:`nb_curl.TCPShapeError`。
    走代理时画像无效（目标站看到的是代理机的 SYN），会直接报错。"""

    ttl: int | None
    """IP TTL（1-255），独立参数，不必配 ``tcp``。检测站按 TTL 判 OS ——
    想换 OS 画像，这一项最有效。"""

    timestamps: bool | None
    """TCP 时间戳选项（``True`` 开 / ``False`` 关）。Windows 逐 socket 生效；
    Linux 只有全局 sysctl（``nb_curl.set_tcp_timestamps()``，需 root）。"""

    tcp_warn: bool | None
    """是否发 TCP 画像的「本机做不到」警告。``None`` = 跟随
    ``nb_curl.set_tcp_warnings()`` 的全局开关（默认开）。"""


# --------------------------------------------------------------------------- #
# 会话级参数（在 RequestOptions 之外）
# --------------------------------------------------------------------------- #
class SessionOptions(RequestOptions, total=False):
    """``Session(...)`` / 模块级 ``nb_curl.get(...)`` 的参数。

    = 全部请求级参数（作为会话默认值）+ 下面这些只属于会话的参数。
    """

    default_headers: bool
    """impersonate 预设是否附带浏览器默认请求头。默认 ``True``。"""

    max_clients: int
    """同一指纹下并发的 native handle 上限。默认 1（``AsyncSession`` 默认 20），
    线程并发场景调大。"""

    max_retries: int
    """幂等请求遇到「连接复用失败」时的重试次数。默认 2。"""

    graceful_close: bool
    """``close()`` 是否等驱动把 keep-alive 连接按 libcurl 的正常顺序关完。默认 ``True``。

    打开时 ``close()`` 等连接真的发完 FIN 才返回（浏览器式：服务端先关、客户端再回
    FIN），代价是空闲连接要等对端 FIN，最多几百毫秒 —— 与旧版阻塞式实现一致。
    关掉它 ``close()`` 立刻返回、残留连接交给驱动线程后台释放：更快，但连接可能以
    RST 收尾。只影响 ``AsyncSession`` 的 ``close()``（同步版关连接走的是 easy 句柄
    自己的收尾路径，本来就是优雅的），与普通请求的耗时无关。"""

    debug: bool
    """``True`` 时把 libcurl 的 verbose 输出打到 stderr。默认 ``False``。"""

    allow_dangerous_options: bool
    """允许 ``curl_options`` 里设置会破坏指纹 / 与会用参数冲突的 option。默认 ``False``。"""


# --------------------------------------------------------------------------- #
# 键集合、默认值、校验
# --------------------------------------------------------------------------- #
def _all_keys(cls: type) -> dict[str, str]:
    """收集 TypedDict 的自己 + 继承键（注解在运行时不求值，值就是类型字符串）。"""
    merged: dict[str, str] = {}
    for base in reversed(getattr(cls, "__mro__", ())):
        merged.update(getattr(base, "__annotations__", None) or {})
    return merged


REQUEST_KEYS: frozenset[str] = frozenset(_all_keys(RequestOptions))
SESSION_KEYS: frozenset[str] = frozenset(_all_keys(SessionOptions))
SESSION_ONLY_KEYS: frozenset[str] = SESSION_KEYS - REQUEST_KEYS

#: 模块级便捷函数的会话级参数：这些转交给临时 Session，其余给请求层。
#: ``proxy`` / ``proxies`` 也归会话级（与旧行为一致，代理天然是会话属性）。
MODULE_SESSION_KEYS: frozenset[str] = SESSION_ONLY_KEYS | {"proxy", "proxies"}

#: 会话级参数的默认值；不在表里的默认 ``None``。
SESSION_DEFAULTS: dict[str, Any] = {
    "verify": True,
    "allow_redirects": True,
    "max_redirects": 30,
    "default_headers": True,
    "max_clients": 1,
    "max_retries": 2,
    "graceful_close": True,
    "debug": False,
    "allow_dangerous_options": False,
}


def check_options(where: str, options: Mapping[str, Any], allowed: frozenset[str]) -> None:
    """参数名写错时立刻报错 —— 把 ``**options`` 丢掉的 ``TypeError`` 补回来。

    顺带猜一下最接近的合法参数，拼错时不用去翻文档。
    """
    unknown = sorted(k for k in options if k not in allowed)
    if not unknown:
        return
    import difflib

    hints = []
    for name in unknown:
        close = difflib.get_close_matches(name, sorted(allowed), n=1, cutoff=0.6)
        hints.append("%r（是不是想写 %r？）" % (name, close[0]) if close else repr(name))
    target = "SessionOptions" if allowed is SESSION_KEYS else "RequestOptions"
    raise TypeError(
        "%s 收到不认识的参数 %s；可用参数见 nb_curl.params.%s（help() 可看说明）"
        % (where, "、".join(hints), target))


# --------------------------------------------------------------------------- #
# 参数说明的渲染
# --------------------------------------------------------------------------- #
def _key_docs() -> dict[str, dict[str, str]]:
    """取每个键紧跟其后的说明字符串（PEP 258 风格）。

    运行时注解是字符串，说明拿不到；读一次本模块源码即可 ——
    换来的是「每个参数的说明只写一份」。源码不可用时（冻结分发）静默降级成只列类型。
    """
    try:
        source = _inspect.getsource(_sys.modules[__name__])
    except (OSError, TypeError):  # pragma: no cover
        return {}

    found: dict[str, dict[str, str]] = {}
    for node in _ast.parse(source).body:
        if not isinstance(node, _ast.ClassDef):
            continue
        docs: dict[str, str] = {}
        body = node.body
        for i, item in enumerate(body):
            if not isinstance(item, _ast.AnnAssign) or not isinstance(item.target, _ast.Name):
                continue
            nxt = body[i + 1] if i + 1 < len(body) else None
            if (isinstance(nxt, _ast.Expr) and isinstance(nxt.value, _ast.Constant)
                    and isinstance(nxt.value.value, str)):
                docs[item.target.id] = " ".join(nxt.value.value.split())
        found[node.name] = docs
    return found


_KEY_DOCS = _key_docs()


def _docs_for(cls: type) -> dict[str, str]:
    merged: dict[str, str] = {}
    for base in reversed(getattr(cls, "__mro__", ())):
        merged.update(_KEY_DOCS.get(base.__name__, {}))
    return merged


def _type_text(value: Any) -> str:
    """注解在运行时是字符串，TypedDict 会把它包成 ForwardRef —— 取回原文。"""
    arg = getattr(value, "__forward_arg__", None)
    return arg if arg is not None else str(value)


def _render(cls: type) -> str:
    docs = _docs_for(cls)
    out: list[str] = []
    for key, annotation in _all_keys(cls).items():
        out.append("  %s: %s" % (key, _type_text(annotation)))
        text = docs.get(key)
        if text:
            out.extend("      " + line for line in _textwrap.wrap(text, 74) or [""])
    return "\n".join(out)


def describe(which: str = "request") -> str:
    """返回参数表的纯文本：``which`` 取 ``"request"`` / ``"session"`` / ``"tcp"``。"""
    cls = {"request": RequestOptions, "session": SessionOptions, "tcp": TcpShape}
    if which not in cls:
        raise ValueError("which 只能是 %s，收到 %r" % ("/".join(sorted(cls)), which))
    return _render(cls[which])


# 让 help() / Ctrl+Q 直接看到每个参数的说明（说明仍只在上面写了一份）
for _cls in (TcpShape, RequestOptions, SessionOptions):
    _cls.__doc__ = "%s\n\n参数一览：\n%s" % ((_cls.__doc__ or "").strip(), _render(_cls))
del _cls
