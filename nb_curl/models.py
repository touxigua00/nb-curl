"""nb_curl.models —— 响应模型（Headers / Cookies / Response / Request）"""

from __future__ import annotations

import calendar
import json as _json
import re
import threading
import time
from datetime import timedelta
from typing import Any, Iterable, Iterator, Mapping

from .const import http_version_name
from .exceptions import HTTPError

__all__ = ["Headers", "Cookies", "CookieJar", "Response", "Request", "parse_header_blocks"]

_REASON_RE = re.compile(r"^HTTP/(\d(?:\.\d)?)\s+(\d{3})\s*(.*)$")
_CHARSET_RE = re.compile(r"charset\s*=\s*[\"']?([\w\-]+)", re.I)


class Headers:
    """保序 + 大小写不敏感的头部容器（支持同名重复头）。"""

    __slots__ = ("_items", "raw")

    def __init__(self, items: Iterable[tuple[str, str]] | Mapping[str, str] | None = None,
                 raw: str = ""):
        self._items: list[tuple[str, str]] = []
        self.raw = raw
        if items is None:
            return
        if isinstance(items, Mapping):
            items = items.items()
        for name, value in items:
            self._items.append((str(name), str(value)))

    # -- 基础 ------------------------------------------------------------ #
    def get(self, key: str, default: Any = None) -> Any:
        """同名重复头按 ", " 合并后返回（与浏览器 ``Headers`` / requests 一致）。"""
        key_l = key.lower()
        found = [value for name, value in self._items if name.lower() == key_l]
        if not found:
            return default
        return found[0] if len(found) == 1 else ", ".join(found)

    def get_list(self, key: str) -> list[str]:
        key_l = key.lower()
        return [v for n, v in self._items if n.lower() == key_l]

    def raw_items(self) -> list[tuple[str, str]]:
        """原始大小写 + 原始顺序的 (name, value) 列表（调试用；对外一律小写）。"""
        return list(self._items)

    def __getitem__(self, key: str) -> str:
        value = self.get(key)
        if value is None:
            raise KeyError(key)
        return value

    def __contains__(self, key: str) -> bool:
        return self.get(key) is not None

    def __iter__(self) -> Iterator[str]:
        return iter(self.keys())

    def __len__(self) -> int:
        return len(self.keys())

    def keys(self) -> list[str]:
        """唯一键，**大小写按服务端原样**（同一个头的多种写法取第一次出现的那个）。"""
        order: list[str] = []
        seen: set[str] = set()
        for name, _value in self._items:
            key = name.lower()
            if key not in seen:
                seen.add(key)
                order.append(name)
        return order

    def values(self) -> list[str]:
        return [value for _name, value in self.items()]

    def items(self) -> list[tuple[str, str]]:
        """每个头一条：名字用服务端原大小写，重复值按 ", " 合并。

        大小写**不改写**（服务端发 ``Content-Type`` 就是 ``Content-Type``）；需要按名取值
        一律走大小写不敏感的 :meth:`get` / :meth:`get_list` / ``[]``。
        """
        out: dict[str, list[str]] = {}
        for name, value in self._items:
            key = name.lower()
            if key in out:
                out[key][1] = out[key][1] + ", " + value
            else:
                out[key] = [name, value]
        return [(name, value) for name, value in out.values()]

    def to_dict(self) -> dict[str, str]:
        """同 :meth:`items`，返回 dict（键保持服务端大小写）。"""
        return dict(self.items())

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Headers):
            return self._items == other._items
        if isinstance(other, Mapping):
            return self.to_dict() == dict(other)
        return NotImplemented

    def __repr__(self) -> str:
        return "Headers(%r)" % (self._items,)


class Cookies(dict):
    """响应里的 cookie 视图：``name -> value``，另外记住每条的 domain/path。

    ``get_dict(domain=, path=)`` 可以按作用域过滤（对齐 curl_cffi）；
    ``set(...)`` 只是让迁移过来的代码不报错（改响应对象不会回写会话罐）。
    """

    def __init__(self, items: Mapping[str, Any] | None = None,
                 meta: Mapping[str, Mapping[str, Any]] | None = None):
        super().__init__(items or {})
        self._meta: dict[str, dict[str, Any]] = {k: dict(v) for k, v in (meta or {}).items()}

    def get_dict(self) -> dict[str, str]:
        """扁平副本（浏览器没有这个概念，留着只是把它当普通 dict 用）。"""
        return dict(self)

    def __repr__(self) -> str:
        return "Cookies(%r)" % (dict(self),)


# --------------------------------------------------------------------------- #
# cookie 罐
# --------------------------------------------------------------------------- #
# 内建 cookie 引擎（libcurl 的 cookie engine）导出与接受的是同一套 Netscape 格式：
#
#     [#HttpOnly_]domain \t tailmatch \t path \t secure \t expires \t name \t value
#
# 本模块按这个格式解析与生成：只有用引擎自己的表达形式往返，Secure / Domain /
# 过期时间这些属性才不会有损。带作用域的行由 :class:`CookieJar` 统一保管。

def _netscape_cookie_line(domain: str, tailmatch: bool, path: str, name: str,
                          value: str, *, secure: bool = False, expires: int = 0,
                          httponly: bool = False) -> str:
    """拼一行 Netscape cookie（``domain`` 不带头点，是否补由 ``tailmatch`` 决定）。"""
    if tailmatch and domain and not domain.startswith("."):
        domain = "." + domain
    return "%s%s\t%s\t%s\t%s\t%d\t%s\t%s" % (
        "#HttpOnly_" if httponly else "",
        domain,
        "TRUE" if tailmatch else "FALSE",
        path or "/",
        "TRUE" if secure else "FALSE",
        int(expires or 0),
        name,
        value if value is not None else "",
    )


def _cookie_line_fields(line: str) -> tuple[tuple[str, str, bool, str], bool, int, str] | None:
    """解析一行 Netscape cookie，返回 ``(作用域键, secure, 过期时间, 值)``。

    作用域键 = ``(name, domain, tailmatch, path)``。不是 cookie 行（注释、空行、
    字段不足）返回 ``None``。
    """
    if line.startswith("#HttpOnly_"):
        line = line[10:]
    elif line.startswith("#"):
        return None
    fields = line.rstrip("\r\n").split("\t")
    if len(fields) < 6:
        return None
    domain, tailmatch, path, secure, expires, name = fields[:6]
    value = fields[6] if len(fields) > 6 else ""
    try:
        expires_at = int(expires or 0)
    except ValueError:
        expires_at = 0
    key = (name, domain.lstrip(".").lower(),
           tailmatch.strip().upper() == "TRUE", path or "/")
    return key, secure.strip().upper() == "TRUE", expires_at, value


def parse_cookie_line(line: str) -> tuple[tuple[str, str, bool, str], str, int] | None:
    """解析一行 Netscape cookie，返回 ``(作用域键, 值, 过期时间)``。

    作用域键 = ``(name, domain, tailmatch, path)`` —— 与引擎判断"是不是同一条
    cookie"的维度一致，也是本模块做增量下发的比较单位。不是 cookie 行（注释、
    空行、字段不足）返回 ``None``。
    """
    parsed = _cookie_line_fields(line)
    if parsed is None:
        return None
    key, _secure, expires_at, value = parsed
    return key, value, expires_at


def _domain_matches(host: str, domain: str, tailmatch: bool) -> bool:
    """``host`` 是否落在 cookie 的 domain 作用域内（RFC 6265 5.1.3 的简化版）。"""
    host = (host or "").lower()
    domain = (domain or "").lower().lstrip(".")
    if not domain:                      # 没有 domain 的行 = 对所有主机生效
        return True
    if host == domain:
        return True
    return bool(tailmatch) and host.endswith("." + domain)


def _path_matches(request_path: str, cookie_path: str) -> bool:
    """``request_path`` 是否落在 cookie 的 path 作用域内（RFC 6265 5.1.4）。"""
    request_path = request_path or "/"
    cookie_path = cookie_path or "/"
    if cookie_path == "/" or request_path == cookie_path:
        return True
    if not request_path.startswith(cookie_path):
        return False
    return cookie_path.endswith("/") or request_path[len(cookie_path)] == "/"


def _default_path(request_path: str) -> str:
    """RFC 6265 5.1.4 的默认 Path：请求路径去掉最后一段（没有斜杠就用 "/"）。"""
    path = request_path or "/"
    if not path.startswith("/"):
        return "/"
    cut = path.rfind("/")
    return "/" if cut <= 0 else path[:cut]


# 「可信来源」白名单：与 Chrome 一致 —— https，以及 localhost / 环回地址
# （它们本身就被当作 secure context，所以 Secure cookie 在 http://localhost 上也能读写）。
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def is_secure_origin(scheme: str, host: str) -> bool:
    """当前请求是否算「安全上下文」（决定 Secure cookie 发不发）。"""
    if (scheme or "").lower() in ("https", "wss"):
        return True
    name = (host or "").lower().strip("[]")
    return name in _LOCAL_HOSTS or name.endswith(".localhost")


_EXPIRES_FORMATS = (
    "%a, %d %b %Y %H:%M:%S GMT",
    "%a, %d-%b-%Y %H:%M:%S GMT",
    "%a, %d %b %Y %H:%M:%S",
    "%a, %d-%b-%Y %H:%M:%S",
    "%a %b %d %H:%M:%S %Y",
)


def _parse_cookie_date(value: str) -> float | None:
    """把 ``Expires`` 值解析成 UTC 时间戳；解析不了返回 ``None``。

    用 ``calendar.timegm``（纯 UTC 算术）而不是 ``time.mktime``：后者在 Windows 上
    对 1970 前后/越界日期会抛 ``OverflowError``，而 ``Expires=Thu, 01 Jan 1970``
    正是"删除 cookie"最常用的写法。
    """
    text = (value or "").strip()
    if not text:
        return None
    # 浏览器容忍 weekday 缺失/大小写混杂，这里先去掉星期几再按几种格式试
    candidates = [text, text.split(",", 1)[-1].strip()]
    for cand in candidates:
        for fmt in _EXPIRES_FORMATS:
            try:
                parsed = time.strptime(cand, fmt)
            except ValueError:
                continue
            try:
                return float(calendar.timegm(parsed))
            except (OverflowError, ValueError):
                return 0.0
    return None


def parse_set_cookie(value: str, request_host: str, request_path: str,
                     now: float | None = None) -> dict[str, Any] | None:
    """解析一条 ``Set-Cookie`` 值（RFC 6265 5.2）。

    返回 ``{"name", "value", "domain", "tailmatch", "path", "secure",
    "httponly", "expires"}``；``expires`` <= ``now`` 表示这条 cookie 已被删除。
    域不匹配（Domain 不是 host 的后缀）返回 ``None``。
    """
    now = time.time() if now is None else float(now)
    text = (value or "").strip()
    if not text:
        return None
    first, _, attrs = text.partition(";")
    name, sep, val = first.partition("=")
    name, val = name.strip(), val.strip()
    if not sep or not name:
        return None

    domain = ""
    tailmatch = False
    path = ""
    secure = False
    httponly = False
    expires: float | None = None
    host_l = (request_host or "").lower()

    for item in attrs.split(";"):
        key, _, raw = item.partition("=")
        key = key.strip().lower()
        raw = raw.strip()
        if key == "expires":
            parsed = _parse_cookie_date(raw)
            if parsed is not None:
                expires = parsed
        elif key == "max-age":
            try:
                delta = int(raw)
            except ValueError:
                continue
            expires = now + delta
        elif key == "domain":
            candidate = raw.lstrip(".").lower().strip("[]")
            if not candidate:
                continue
            # Domain 必须是 host 的后缀（且不能是裸顶级域），否则整条拒收
            if host_l == candidate or host_l.endswith("." + candidate):
                if "." in candidate or candidate in _LOCAL_HOSTS:
                    domain = candidate
                    tailmatch = True
                else:
                    return None
            else:
                return None
        elif key == "path":
            path = raw or "/"
        elif key == "secure":
            secure = True
        elif key == "httponly":
            httponly = True

    if not domain:
        domain = host_l                      # host-only cookie
        tailmatch = False
    if not path or not path.startswith("/"):
        path = _default_path(request_path)

    return {
        "name": name,
        "value": val,
        "domain": domain,
        "tailmatch": tailmatch,
        "path": path,
        "secure": secure,
        "httponly": httponly,
        "expires": expires,
    }


def expired_cookie_line(key: tuple[str, str, bool, str]) -> str:
    """给某个作用域键造一条"早已过期"的行 —— 推给引擎即等同于删除该 cookie。"""
    name, domain, tailmatch, path = key
    return _netscape_cookie_line(domain, tailmatch, path, name, "", expires=1)


def _cookie_names(value: str) -> set[str]:
    """从一条 ``Cookie`` 头值里认出 cookie 名（**只用于去重，不改写原文**）。

    用户给的整串在线上是原样发出的，这里只解析"占了哪些名字"，好让会话罐里的
    同名 cookie 不再追加一份。
    """
    names: set[str] = set()
    for item in str(value).split(";"):
        name = item.split("=", 1)[0].strip()
        if name:
            names.add(name)
    return names


class CookieJar(dict):
    """``session.cookies``：``name -> value`` 的表面视图 + 浏览器口径的完整罐。

    设计目标只有一个：**发出去的 ``Cookie`` 头与真浏览器逐字节一致**。

    * **发送**：请求头里的 ``Cookie`` 一律由 :meth:`header_value` 拼（显式 cookie 在
      前、罐内 cookie 在后，罐内按 RFC 6265 5.4 排序：path 长者先、同长按创建时间），
      再作为一条普通 header 行下发；内建 cookie 引擎在发送前被清空，绝不让它拼第二
      条（它按 ``path/domain/name`` **长度**排序，与浏览器口径不同）。
    * **学习**：引擎仍然开着，响应里的 ``Set-Cookie`` 照常被它学到，收尾时经
      :meth:`_absorb` 吸收进罐；删除（``Max-Age=0`` / 过期 ``Expires``）另外由
      :meth:`remember_set_cookie` 从原始头里解析确认 —— 引擎被清空过，删不到它不
      认识的行。
    * **作用域**：脚本里直接 ``session.cookies["k"] = "v"`` 没有 domain 信息，第一次
      真正发请求时按"当前主机"绑成 host-only（浏览器对没有 Domain 属性的 cookie 就
      是这个语义），因此不会跨站泄漏；要显式指定作用域用 :meth:`set`。
    * **创建时间**：本类自己维护一个单调序号（第一次见到这条 cookie 的时刻），
      引擎改写 value 时序号保持不变 —— 与 RFC 6265 "更新不重置创建时间" 一致。
    """

    def __init__(self, items: Mapping[str, Any] | None = None):
        super().__init__()
        # 复合操作锁：_absorb/_prune/_candidates 是"读-改-写"的复合操作，并发请求
        # 同时吸收各自引擎导出会互相踩 —— 每一步都整体持锁。
        self._lock = threading.RLock()
        self._lines: dict[tuple[str, str, bool, str], str] = {}
        self._seq: dict[tuple[str, str, bool, str], int] = {}
        self._counter = 0
        self._explicit: dict[str, Any] = {}
        self._explicit_host: dict[str, str] = {}
        for name, value in dict(items or {}).items():
            self[name] = value

    # -- 内部 ------------------------------------------------------------- #
    def _next_seq(self) -> int:
        self._counter += 1
        return self._counter

    def _drop_key(self, key: tuple[str, str, bool, str]) -> None:
        """删掉一条作用域行；该名字再没有别的行时，表面视图也一起清掉。"""
        self._lines.pop(key, None)
        self._seq.pop(key, None)
        name = key[0]
        if not any(k[0] == name for k in self._lines):
            self._explicit.pop(name, None)
            self._explicit_host.pop(name, None)
            dict.pop(self, name, None)

    # -- 用户写入：记为"未绑定"，第一次发请求时绑到当前主机 ---------------- #
    def __setitem__(self, name: str, value: Any) -> None:
        key = str(name)
        with self._lock:
            self._explicit[key] = value
            self._explicit_host.pop(key, None)
            dict.__setitem__(self, key, value)

    def update(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        for name, value in dict(*args, **kwargs).items():
            self[name] = value

    def setdefault(self, name: str, default: Any = None) -> Any:
        if name not in self:
            self[name] = default
        return dict.__getitem__(self, name)

    def __delitem__(self, name: str) -> None:
        self._forget(name)
        dict.__delitem__(self, name)

    def pop(self, name: str, *default: Any) -> Any:
        existed = name in self
        value = dict.pop(self, name, *default)
        if existed:
            self._forget(name)
        return value

    def clear(self) -> None:
        with self._lock:
            self._explicit.clear()
            self._explicit_host.clear()
            self._lines.clear()
            self._seq.clear()
            dict.clear(self)

    def _forget(self, name: str) -> None:
        """用户删掉一个 cookie：显式记录 + 所有作用域下的同名行全部作废。"""
        with self._lock:
            self._explicit.pop(name, None)
            self._explicit_host.pop(name, None)
            for key in [k for k in self._lines if k[0] == name]:
                self._lines.pop(key, None)
                self._seq.pop(key, None)

    # -- 引擎侧（只在 session 内部用） ------------------------------------ #
    def _absorb(self, dump: str, now: float,
                skip: frozenset = frozenset()) -> None:
        """吸收一次引擎导出（``CURLINFO_COOKIELIST`` 的原始文本）。

        ``skip`` 是本次请求专用的作用域键（显式 ``Cookie`` 头转来的，用完即弃），
        不能被记进会话罐。过期键删除是**幂等 pop**：并发请求可能已经先吸收了同一条
        过期通知。
        """
        with self._lock:
            for line in dump.splitlines():
                parsed = parse_cookie_line(line)
                if parsed is None or parsed[0] in skip:
                    continue
                key, value, expires_at = parsed
                name = key[0]
                if expires_at and expires_at <= now:
                    self._drop_key(key)
                    continue
                if key not in self._lines:
                    self._seq[key] = self._next_seq()      # 新 cookie：创建序 = 现在
                self._lines[key] = line
                self._explicit.pop(name, None)
                self._explicit_host.pop(name, None)
                dict.__setitem__(self, name, value)

    def remember_set_cookie(self, header_value: str, host: str, request_path: str,
                            now: float | None = None) -> None:
        """从响应原始 ``Set-Cookie`` 里确认**删除**（引擎被清空过，删不到它不认识的）。

        新增/更新照旧由引擎导出负责（作用域语义与 libcurl 完全一致），这里只处理
        ``Max-Age=0`` / 已过期 ``Expires`` 这类"删掉罐里已有的那条"的情况。
        """
        now = time.time() if now is None else float(now)
        parsed = parse_set_cookie(header_value, host, request_path, now=now)
        if parsed is None:
            return
        expires = parsed["expires"]
        # expires=None 表示这条 Set-Cookie 根本没带过期时间（不是删除）
        if expires is None or expires > now:
            return
        name, domain, tailmatch, path = (parsed["name"], parsed["domain"],
                                         parsed["tailmatch"], parsed["path"])
        with self._lock:
            for key in [k for k in self._lines
                        if k[0] == name and k[1] == domain and k[3] == path]:
                self._drop_key(key)
            # 引擎那侧也可能留着一份同作用域的行
            self._explicit.pop(name, None)

    def _wanted(self, host: str, now: float) -> dict[tuple[str, str, bool, str], str]:
        """本次请求在 ``host`` 上**作用域命中**的全部 cookie 行（作用域键 -> 行）。"""
        self._prune(now)
        with self._lock:
            wanted: dict[tuple[str, str, bool, str], str] = {}
            for key, line in self._lines.items():
                name, domain, tailmatch, _path = key
                if _domain_matches(host, domain, tailmatch):
                    wanted[key] = line
            for name, value in self._explicit.items():
                key = (name, host, False, "/")
                if key not in wanted:
                    wanted[key] = _netscape_cookie_line(host, False, "/", str(name),
                                                        "" if value is None else str(value))
            return wanted

    def _candidates(self, host: str, request_path: str, secure: bool,
                    now: float) -> list[tuple[str, str]]:
        """本次请求该发出的 cookie，**按浏览器口径排好序**。

        排序规则（RFC 6265 5.4 / Chrome 实测）：path 长者在先，同长按创建时间升序。
        """
        self._prune(now)
        ranked: list[tuple[int, int, str, str]] = []
        with self._lock:
            for key, line in self._lines.items():
                name, domain, tailmatch, cookie_path = key
                if not _domain_matches(host, domain, tailmatch):
                    continue
                if not _path_matches(request_path, cookie_path):
                    continue
                fields = _cookie_line_fields(line)
                if fields is None:
                    continue
                _key, is_secure, expires_at, value = fields
                if expires_at and expires_at <= now:
                    continue
                if is_secure and not secure:
                    continue
                ranked.append((-len(cookie_path or "/"), self._seq.get(key, 0), name, value))
            for name, value in list(self._explicit.items()):
                bound = self._explicit_host.get(name)
                if bound is None:
                    # 没有 Domain 的 cookie：第一次用到时绑成 host-only
                    self._explicit_host[name] = host
                    bound = host
                if bound != host:
                    continue
                key = (name, host, False, "/")
                if key in self._lines:
                    continue
                if key not in self._seq:
                    self._seq[key] = self._next_seq()
                ranked.append((-1, self._seq[key], name, "" if value is None else str(value)))
        ranked.sort()
        return [(name, value) for _l, _s, name, value in ranked]

    def cookie_parts(self, host: str, request_path: str = "/", *,
                     secure: bool = False, pairs: Iterable[tuple[str, str]] = (),
                     raw: str = "", now: float | None = None) -> list[str]:
        """本次请求该发的 cookie，**一条一份**（HTTP/2 拆行用）。

        顺序：``raw``（用户整串给的）→ ``pairs``（请求级 ``cookies=``）
        → 罐内命中的 cookie（浏览器排序：path 长者先、同长按创建时间）。
        """
        now = time.time() if now is None else float(now)
        parts: list[str] = []
        explicit_names: set[str] = set()
        text = (raw or "").strip()
        if text:
            parts.append(text)
            explicit_names.update(_cookie_names(text))
        for name, value in pairs:
            parts.append("%s=%s" % (name, value))
            explicit_names.add(str(name))
        for name, value in self._candidates((host or "").lower(), request_path,
                                           secure, now):
            # 只挡住"用户已经显式给过"的同名 cookie；罐里同名不同 path 的几条
            # **都要发**（浏览器就是 sid=deep; sid=root 这么发的）。
            if name in explicit_names:
                continue
            parts.append("%s=%s" % (name, value))
        return parts

    def header_value(self, host: str, request_path: str = "/", *,
                     secure: bool = False, pairs: Iterable[tuple[str, str]] = (),
                     raw: str = "", now: float | None = None) -> str:
        """拼一条 ``Cookie:`` 头值（不带 ``Cookie:`` 前缀）。"""
        return "; ".join(self.cookie_parts(host, request_path, secure=secure,
                                           pairs=pairs, raw=raw, now=now))

    def _prune(self, now: float) -> None:
        """丢弃已经过期的行（比如从文件读进来的、带过期时间的 cookie）。"""
        with self._lock:
            for key, line in list(self._lines.items()):
                parsed = parse_cookie_line(line)
                if parsed and parsed[2] and parsed[2] <= now:
                    self._drop_key(key)

    def __repr__(self) -> str:
        return "CookieJar(%r)" % (dict(self),)


def parse_header_blocks(raw: bytes) -> list[tuple[int, str, Headers]]:
    """把 native 累积的原始响应头切成 [(status_code, reason, Headers), ...]。

    会跳过 1xx（含 100 Continue）与代理 CONNECT 的临时响应。
    """
    if not raw:
        return []

    text = raw.decode("latin-1", "replace")
    text = text.replace("\r\n", "\n")

    blocks: list[tuple[int, str, Headers]] = []
    for chunk in text.split("\n\n"):
        lines = [ln for ln in chunk.split("\n") if ln.strip()]
        if not lines:
            continue
        m = _REASON_RE.match(lines[0].strip())
        if not m:
            # 不是状态行：可能是 100-continue 之后没有换行，或被代理截断
            continue
        code = int(m.group(2))
        reason = m.group(3).strip()

        items: list[tuple[str, str]] = []
        for line in lines[1:]:
            if ":" not in line:
                continue
            name, _, value = line.partition(":")
            items.append((name.strip(), value.strip()))

        if 100 <= code < 200:
            continue  # 临时响应，不进 history
        blocks.append((code, reason, Headers(items, raw=chunk)))

    return blocks


class Request:
    """一次请求的最小描述（供 response.request 使用）。"""

    __slots__ = ("method", "url", "headers")

    def __init__(self, method: str, url: str, headers: Headers | None = None):
        self.method = method
        self.url = url
        self.headers = headers or Headers()

    def __repr__(self) -> str:
        return "<Request [%s]>" % self.method


class Response:
    """HTTP 响应。

    默认（非流式）响应体在返回前已经读完，``content`` 就是全部内容。
    ``stream=True`` 的响应则挂着一条**正在传输**的流：``iter_content()`` 边收边给
    （真·增量，内存占用与响应体大小无关），``content`` / ``text`` / ``json()`` 会把
    **还没读的部分**整体读出来 —— 两者混用会瓜分响应体（与 requests 一致）。

    流式响应用完要 ``close()``（或写成 ``with nb_curl.get(..., stream=True) as r:``）
    释放连接；忘了关也不会一直挂着，响应被回收时会自动中止后台传输。
    """

    def __init__(
        self,
        *,
        status_code: int,
        headers: Headers,
        content: bytes | None,
        url: str,
        reason: str = "",
        http_version: str = "",
        primary_ip: str = "",
        elapsed: float = 0.0,
        history: list["Response"] | None = None,
        redirect_count: int = 0,
        request: Request | None = None,
        cookie_list: str = "",
    ):
        self.status_code = status_code
        self.headers = headers
        self._content = content
        self.url = url
        self.reason = reason
        self.http_version = http_version
        self.primary_ip = primary_ip
        self.elapsed = timedelta(seconds=elapsed)
        self.history = history or []
        self.redirect_count = redirect_count
        self.request = request
        self._cookie_list = cookie_list
        self._encoding: str | None = None
        # 流式下载（stream=True）：响应体还在传输，_stream 是取数的地方
        self._stream: Any = None
        self._owned_session: Any = None

    # -- 便捷属性 --------------------------------------------------------- #
    @property
    def ok(self) -> bool:
        return self.status_code < 400

    @property
    def content(self) -> bytes:
        """响应体字节。流式响应会在这里把剩余部分读完（读完后再调用得到空 bytes）。"""
        if self._content is None:
            self._content = self._stream.read_all() if self._stream is not None else b""
        return self._content

    @content.setter
    def content(self, value: bytes | None) -> None:
        self._content = value

    @property
    def is_stream(self) -> bool:
        """该响应体是否还在传输中（``stream=True`` 且尚未读完）。"""
        return self._stream is not None and not self._stream.finished

    @property
    def stream_consumed(self) -> bool:
        """流式响应体是否已经被读过（无论整体读还是逐块读）。"""
        return self._stream is None or self._stream.consumed

    @property
    def encoding(self) -> str:
        if self._encoding:
            return self._encoding
        content_type = self.headers.get("content-type") or ""
        m = _CHARSET_RE.search(content_type)
        if m:
            return m.group(1)
        return "utf-8"

    @encoding.setter
    def encoding(self, value: str) -> None:
        self._encoding = value

    @property
    def apparent_encoding(self) -> str:
        try:
            import charset_normalizer  # type: ignore

            best = charset_normalizer.from_bytes(self.content).best()
            if best and best.encoding:
                return best.encoding
        except Exception:  # noqa: BLE001
            pass
        return self.encoding

    @property
    def text(self) -> str:
        encoding = self.encoding or "utf-8"
        try:
            return self.content.decode(encoding, errors="replace")
        except LookupError:
            return self.content.decode("utf-8", errors="replace")

    @property
    def cookies(self) -> Cookies:
        """本次响应里 ``Set-Cookie`` 的视图（带 domain/path 元信息）。"""
        jar = Cookies()
        for raw in self.headers.get_list("set-cookie"):
            pair = raw.split(";", 1)[0].strip()
            if "=" not in pair:
                continue
            name, _, value = pair.partition("=")
            name, value = name.strip(), value.strip()
            if not name:
                continue
            jar[name] = value
            parsed = parse_set_cookie(raw, "", "/")
            if parsed:
                jar._meta[name] = {"domain": parsed["domain"],
                                   "path": parsed["path"],
                                   "secure": parsed["secure"]}
        return jar

    @property
    def raw_cookie_list(self) -> str:
        return self._cookie_list

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "") or ""

    # -- 方法 ------------------------------------------------------------- #
    def json(self, **kwargs: Any) -> Any:
        """解析 JSON（对齐浏览器：**先按 UTF-8** 解，解不开才回退到声明的 charset）。

        Chrome 的 ``Response.json()`` 永远按 UTF-8 解码（`Response.text()` 也是），
        即使响应头写了别的 charset —— 实测 ``application/json; charset=gbk`` + GBK
        字节在 Chrome 里就是乱码。我们跟这个口径走，只在 UTF-8 解不开时才用
        :attr:`encoding` / 猜出来的编码兜底，避免把本来能读的数据变成替换符。
        """
        content = self.content
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            try:
                text = content.decode(self.encoding or "utf-8")
            except (UnicodeDecodeError, LookupError):
                text = content.decode(self.apparent_encoding or "utf-8", errors="replace")
        return _json.loads(text, **kwargs)

    def raise_for_status(self) -> "Response":
        if 400 <= self.status_code < 600:
            raise HTTPError(
                "%d %s for url: %s" % (self.status_code, self.reason or "Error", self.url),
                response=self,
            )
        return self

    def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
        """逐块产出响应体。

        流式响应（``stream=True``）时是真·增量：数据一到就给，不攒完整个响应体，
        所以内存占用与响应体大小无关。流是个游标 —— 可以分多次接着读，中途
        ``break`` 也不会丢掉剩下的数据（交给 ``content`` 或下一次调用即可）。

        非流式响应则是在已经读完的内容上切片（接口兼容，且每次调用都从头来）。
        """
        stream = self._stream
        if stream is not None and self._content is None:
            yield from stream.iter_chunks(chunk_size)
            return
        content = self.content
        for i in range(0, len(content), chunk_size):
            yield content[i:i + chunk_size]

    async def aiter_content(self, chunk_size: int = 8192) -> Any:
        """``iter_content`` 的异步版本：真·异步增量读取，**不**每块丢线程池。

        流式响应走 :meth:`_StreamBody.aiter_chunks`：每挂起一次只建一个 Future
        （由 reactor 线程经 ``call_soon_threadsafe`` 唤醒），不再每块一次
        ``asyncio.to_thread``。非流式响应在线程池里整体切片（内容已在内存）。
        """
        import asyncio

        stream = self._stream
        if stream is None:
            for part in self.iter_content(chunk_size):
                yield part
            return
        if self._content is None:
            async for part in stream.aiter_chunks(chunk_size):
                yield part
            return
        content = self.content
        for i in range(0, len(content), chunk_size):
            yield content[i:i + chunk_size]

    def iter_lines(self, chunk_size: int = 8192, delimiter: bytes | None = None) -> Iterator[bytes]:
        delim = delimiter or b"\n"
        pending = b""
        for chunk in self.iter_content(chunk_size):
            pending += chunk
            while delim in pending:
                line, pending = pending.split(delim, 1)
                yield line
        if pending:
            yield pending

    def close(self) -> None:
        """释放流式响应还占着的连接。

        非流式响应（内容已全部在内存里）调用它没有任何副作用；流式响应会中止仍
        在进行的传输并等后台线程收尾。
        """
        if self._stream is not None:
            self._stream.close()
        if self._owned_session is not None:
            session, self._owned_session = self._owned_session, None
            session.close()

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - 兜底：忘了 close() 也别把连接挂着
        """响应被回收时中止后台传输。

        ``stream=True`` 的响应如果既没读完也没 ``close()``，后台线程会一直卡在
        背压上、连接也一直占着。这里发个中止信号（不等它，句柄由后台线程自己收），
        让最坏情况变成"数据不读了"而不是"线程和连接一起泄漏"。
        """
        try:
            stream = getattr(self, "_stream", None)
            if stream is not None:
                stream.close(join=False)
            session = getattr(self, "_owned_session", None)
            self._owned_session = None
            if session is not None:
                session.close()
        except Exception:  # noqa: BLE001
            pass

    def __bool__(self) -> bool:
        return self.ok

    def __repr__(self) -> str:
        return "<Response [%d]>" % self.status_code


def _next_or(iterator: Any, sentinel: Any) -> Any:
    """``next(iterator, sentinel)`` —— 兼容保留（不再被 aiter_content 使用）。"""
    return next(iterator, sentinel)
