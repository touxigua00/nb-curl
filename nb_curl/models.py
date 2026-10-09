"""nb_curl.models —— 响应模型（Headers / Cookies / Response / Request）"""

from __future__ import annotations

import json as _json
import re
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
        key_l = key.lower()
        for name, value in self._items:
            if name.lower() == key_l:
                return value
        return default

    def get_list(self, key: str) -> list[str]:
        key_l = key.lower()
        return [v for n, v in self._items if n.lower() == key_l]

    def __getitem__(self, key: str) -> str:
        value = self.get(key)
        if value is None:
            raise KeyError(key)
        return value

    def __contains__(self, key: str) -> bool:
        return self.get(key) is not None

    def __iter__(self) -> Iterator[str]:
        return (name for name, _ in self._items)

    def __len__(self) -> int:
        return len(self._items)

    def keys(self) -> list[str]:
        return [name for name, _ in self._items]

    def values(self) -> list[str]:
        return [value for _, value in self._items]

    def items(self) -> list[tuple[str, str]]:
        return list(self._items)

    def to_dict(self) -> dict[str, str]:
        """重复头用 ", " 合并（与 requests 的 dict 视图一致）。"""
        out: dict[str, str] = {}
        for name, value in self._items:
            if name in out:
                out[name] = out[name] + ", " + value
            else:
                out[name] = value
        return out

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Headers):
            return self._items == other._items
        if isinstance(other, Mapping):
            return self.to_dict() == dict(other)
        return NotImplemented

    def __repr__(self) -> str:
        return "Headers(%r)" % (self._items,)


class Cookies(dict):
    """Cookie 容器，也可通过 ``get_dict`` 拿到扁平字典。"""

    def get_dict(self, domain: str | None = None, path: str | None = None) -> dict[str, str]:
        return dict(self)


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


def parse_cookie_line(line: str) -> tuple[tuple[str, str, bool, str], str, int] | None:
    """解析一行 Netscape cookie，返回 ``(作用域键, 值, 过期时间)``。

    作用域键 = ``(name, domain, tailmatch, path)`` —— 与引擎判断"是不是同一条
    cookie"的维度一致，也是本模块做增量下发的比较单位。不是 cookie 行（注释、
    空行、字段不足）返回 ``None``。
    """
    if line.startswith("#HttpOnly_"):
        line = line[10:]
    elif line.startswith("#"):
        return None
    fields = line.rstrip("\r\n").split("\t")
    if len(fields) < 6:
        return None
    domain, tailmatch, path, _secure, expires, name = fields[:6]
    value = fields[6] if len(fields) > 6 else ""
    try:
        expires_at = int(expires or 0)
    except ValueError:
        expires_at = 0
    key = (name, domain.lstrip(".").lower(),
           tailmatch.strip().upper() == "TRUE", path or "/")
    return key, value, expires_at


def expired_cookie_line(key: tuple[str, str, bool, str]) -> str:
    """给某个作用域键造一条"早已过期"的行 —— 推给引擎即等同于删除该 cookie。"""
    name, domain, tailmatch, path = key
    return _netscape_cookie_line(domain, tailmatch, path, name, "", expires=1)


class CookieJar(dict):
    """``session.cookies``：``name -> value`` 的表面视图 + 引擎要用的带作用域行。

    引擎（libcurl 的 cookie engine）是**唯一**能把 cookie 拼进 ``Cookie:`` 请求头
    的通道。早先把同一份 jar 又用 ``CURLOPT_COOKIE`` 给了一遍，于是引擎自己从
    ``Set-Cookie`` 学到的 cookie 会被拼两次（``Cookie: sid=x; sid=x``）——既是功能
    问题，也是可被识别的指纹特征。现在只留引擎一条路，本类负责三件事：

    * ``_lines``：带 domain/path/secure/过期时间的规范 cookie 行（会话级 jar，
      由引擎导出后吸收而来，可直接推给另一只 handle 的引擎，往返无损）；
    * ``_explicit``：用户显式给的 ``name=value``（还没有作用域，下发时按本次请求的
      主机补上 —— 与浏览器给"没有 Domain 属性的 cookie"的作用域规则一致）；
    * 表面仍是 ``dict``：``session.cookies["k"] = "v"`` / ``dict(session.cookies)``
      这些老写法照旧可用。显式赋值会被记进 ``_explicit``，删掉它则会在下一次请求时
      把对应 cookie 从引擎里一并删掉。
    """

    def __init__(self, items: Mapping[str, Any] | None = None):
        super().__init__()
        self._lines: dict[tuple[str, str, bool, str], str] = {}
        self._explicit: dict[str, str] = {}
        for name, value in dict(items or {}).items():
            self[name] = value

    # -- 用户写入：记为"显式"，需要按请求主机补作用域后下发 ---------------- #
    def __setitem__(self, name: str, value: Any) -> None:
        key = str(name)
        self._explicit[key] = value
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
        self._explicit.clear()
        self._lines.clear()
        dict.clear(self)

    def _forget(self, name: str) -> None:
        """用户删掉一个 cookie：显式记录 + 所有作用域下的同名行全部作废。"""
        self._explicit.pop(name, None)
        for key in [k for k in self._lines if k[0] == name]:
            del self._lines[key]

    # -- 引擎侧（只在 session 内部用） ------------------------------------ #
    def _absorb(self, dump: str, now: float,
                skip: frozenset = frozenset()) -> None:
        """吸收一次引擎导出（``CURLINFO_COOKIELIST`` 的原始文本）。

        ``skip`` 是本次请求专用的作用域键（显式 ``Cookie`` 头转来的，用完即弃），
        不能被记进会话罐。
        """
        for line in dump.splitlines():
            parsed = parse_cookie_line(line)
            if parsed is None or parsed[0] in skip:
                continue
            key, value, expires_at = parsed
            name = key[0]
            if expires_at and expires_at <= now:
                # 引擎里已经过期删掉了，表面视图也别再留着
                del self._lines[key]
                if not any(k[0] == name for k in self._lines):
                    self._explicit.pop(name, None)
                    dict.pop(self, name, None)
                continue
            self._lines[key] = line
            if self._explicit.get(name) not in (None, value):
                # 服务端改了同名 cookie：引擎里的值才是权威，别再用我们那份覆盖它
                del self._explicit[name]
            dict.__setitem__(self, name, value)

    def _wanted(self, host: str, now: float) -> dict[tuple[str, str, bool, str], str]:
        """本次请求在 ``host`` 上应该生效的全部 cookie 行（作用域键 -> 行）。"""
        self._prune(now)
        wanted = dict(self._lines)
        for name, value in self._explicit.items():
            key = (name, host, False, "/")
            if key not in wanted:      # 引擎里已有该主机下的同名 cookie，就别造第二份
                wanted[key] = _netscape_cookie_line(host, False, "/", name, value)
        return wanted

    def _prune(self, now: float) -> None:
        """丢弃已经过期的行（比如从文件读进来的、带过期时间的 cookie）。"""
        for key, line in list(self._lines.items()):
            parsed = parse_cookie_line(line)
            if parsed and parsed[2] and parsed[2] <= now:
                del self._lines[key]
                if not any(k[0] == key[0] for k in self._lines):
                    dict.pop(self, key[0], None)

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
        jar = Cookies()
        for raw in self.headers.get_list("set-cookie"):
            pair = raw.split(";", 1)[0].strip()
            if "=" in pair:
                name, _, value = pair.partition("=")
                jar[name.strip()] = value.strip()
        return jar

    @property
    def raw_cookie_list(self) -> str:
        return self._cookie_list

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "") or ""

    # -- 方法 ------------------------------------------------------------- #
    def json(self, **kwargs: Any) -> Any:
        return _json.loads(self.content.decode(self.encoding or "utf-8", errors="replace"), **kwargs)

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
        """``iter_content`` 的异步版本：每块都丢进线程池取，不卡事件循环。

        只在异步里用得上 —— 同步场景直接用 ``iter_content()`` 更省开销。
        """
        import asyncio

        stream = self._stream
        if stream is None:
            for part in self.iter_content(chunk_size):
                yield part
            return
        iterator = stream.iter_chunks(chunk_size)
        sentinel = object()
        while True:
            part = await asyncio.to_thread(_next_or, iterator, sentinel)
            if part is sentinel:
                return
            yield part

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
    """``next(iterator, sentinel)`` —— 供 ``asyncio.to_thread`` 调用。"""
    return next(iterator, sentinel)
