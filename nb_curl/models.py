"""nb_curl.models —— 响应模型（Headers / Cookies / Response / Request）"""

from __future__ import annotations

import json as _json
import re
from datetime import timedelta
from typing import Any, Iterable, Iterator, Mapping

from .const import http_version_name
from .exceptions import HTTPError

__all__ = ["Headers", "Cookies", "Response", "Request", "parse_header_blocks"]

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
    """HTTP 响应。"""

    def __init__(
        self,
        *,
        status_code: int,
        headers: Headers,
        content: bytes,
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
        self.content = content
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

    # -- 便捷属性 --------------------------------------------------------- #
    @property
    def ok(self) -> bool:
        return self.status_code < 400

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
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i:i + chunk_size]

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

    def close(self) -> None:  # 兼容 requests 的 close()（内容已全部在内存里）
        return None

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __bool__(self) -> bool:
        return self.ok

    def __repr__(self) -> str:
        return "<Response [%d]>" % self.status_code
