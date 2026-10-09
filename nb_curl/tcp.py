"""TCP 层画像（JA4T）：连接建立**之前**按 socket 设定 TTL / 窗口 / wscale / MSS。

三条硬规矩（2026-09-24 按用户要求重定）：

1. ``tcp=`` 收**完整的 JA4T 值**——``"64240_2-1-3-1-1-4_1400_8"``（四段都填真实值），
   也可以用 dict 只给关心的字段（``tcp={"window": 64240, "wscale": 8}``）。
2. **本机做不到的项只发警告，不报错**，请求照发，只是那一项不生效。
   警告可以关掉：``nb_curl.set_tcp_warnings(False)`` 或标准的
   ``warnings.simplefilter("ignore", nb_curl.TCPShapeWarning)``。
   画像串本身写错（格式、类型、取值越界）才是 :class:`TCPShapeError`。
3. **默认绝不改窗口**（Windows 与 Linux 一样）：只要给出的 ``window`` / ``wscale``
   这一对**不能同时精确达成**，就完全不碰 ``SO_RCVBUF``，本机默认窗口原样保留
   （Windows 上常见 64240），只发一条警告说明哪一项做不到。
   绝不把窗口"替换"成别的值 —— 例如 Windows 上 ``64240_..._8`` 做不到
   （rcvbuf ≤ 65535 时 wscale 恒为 0），那就什么都不设，不会被顶成 65535。

各观测点的平台能力（实测结论，别重新怀疑）：

* **TCP option 顺序任何 OS 都改不了**（写在内核源码里，没有 setsockopt 接口）。
  顺序段只能填本机原生值，否则发警告。原生值：Windows ``2-1-3-1-1-4``、
  Linux ``2-4-8-1-3``、macOS ``2-1-3-1-1-8-4-0``；Linux 的顺序还随全局时间戳变
  （关掉 ``net.ipv4.tcp_timestamps`` 变 ``2-1-1-4-1-3``），所以是读 sysctl 现算的。
* **window 与 wscale 共用 ``SO_RCVBUF``**，两个平台公式不同（见
  :func:`plan_rcvbuf`）；``SO_RCVBUF`` 一旦显式设置，该 socket 的窗口自动调优就关闭。
* **MSS**：Linux 走 ``TCP_MAXSEG``（逐 socket）；Windows 上 ``TCP_MAXSEG`` 任何
  optname 都返回 ``WSAENOPROTOOPT``，SYN 里的 MSS 只能靠改网卡 MTU
  （:func:`set_interface_mtu`，需管理员）。
* **时间戳**：Windows 逐 socket（optname 10）；Linux 只有全局 sysctl，
  :func:`set_tcp_timestamps` 是唯一路子（需 root）。
* **TTL 是最便宜也最有效的一项**——检测站按 TTL 判 OS，只改 options 不改 TTL
  会被判成 ``Unknown``。
"""

from __future__ import annotations

import platform as _platform
import re
import subprocess as _subprocess
import sys as _sys
import warnings as _warnings
from typing import Any, Mapping

from .exceptions import TCPShapeError, TCPShapeWarning

__all__ = [
    "TcpProfile", "parse_tcp_profile", "build_tcp_profile", "tcp_support",
    "verify_actual", "interface_mtu", "set_interface_mtu",
    "set_tcp_timestamps", "set_tcp_warnings", "plan_rcvbuf", "emit_warning",
]

_NATIVE_ORDER = {
    "windows": "2-1-3-1-1-4",
    "linux": "2-4-8-1-3",
    "darwin": "2-1-3-1-1-8-4-0",
}
_LINUX_ORDER_TS_OFF = "2-1-1-4-1-3"

#: 平台 -> 每个观测点能否设置
_KNOBS = {
    "windows": {"ttl": True, "mss": True, "window": True, "wscale": True,
                "timestamp": True},
    "linux": {"ttl": True, "mss": True, "window": True, "wscale": True,
              "timestamp": True},
    "darwin": {"ttl": True, "mss": False, "window": False, "wscale": False,
               "timestamp": False},
}
_KNOBS_UNKNOWN = {"ttl": True, "mss": False, "window": False, "wscale": False,
                  "timestamp": False}

#: 平台 -> MSS 的落点
_MSS_MECHANISM = {"windows": "interface-mtu", "linux": "socket", "darwin": None}
#: 平台 -> 时间戳的落点
_TS_MECHANISM = {"windows": "socket", "linux": "global-sysctl", "darwin": None}

#: 平台 -> 建连后能否回读证实
_VERIFIABLE = {
    "windows": {"ttl": True, "mss": True, "window": True, "wscale": True,
                "timestamp": True},
    "linux": {"ttl": True, "mss": True, "window": True, "wscale": True,
              "timestamp": False},
    "darwin": {"ttl": False, "mss": False, "window": False, "wscale": False,
               "timestamp": False},
}
_VERIFIABLE_UNKNOWN = {"ttl": False, "mss": False, "window": False,
                       "wscale": False, "timestamp": False}

_ORDER_RE = re.compile(r"^\d+(-\d+)*$")

_FIELD_CN = {
    "ttl": "TTL（IP_TTL）",
    "mss": "MSS（最大报文段）",
    "window": "window size（初始通告窗口）",
    "wscale": "window scale（窗口缩放）",
    "timestamp": "time stamp（时间戳选项）",
    "order": "option 顺序",
}

_SIO_MSS_SLACK = 12
_TS_OPTION_BYTES = 12

#: 画像里可用的键（dict 形式 + 报错文案共用）
_PROFILE_KEYS = ("window", "order", "mss", "wscale")

_MTU_CACHE: dict | None = None

#: ``set_tcp_warnings`` 的全局开关；``TcpProfile.warn is None`` 时跟随它
_WARN_ENABLED = True


# --------------------------------------------------------------------------- #
# 平台与警告
# --------------------------------------------------------------------------- #
def _platform_family() -> str:
    if _platform.system() == "Windows":
        return "windows"
    if _platform.system() == "Linux":
        return "linux"
    if _platform.system() == "Darwin":
        return "darwin"
    return "unknown"


def _platform_label() -> str:
    system = _platform.system()
    if system == "Windows":
        return "Windows (build %s)" % _platform.version()
    if system == "Linux":
        return "Linux %s" % _platform.release()
    if system == "Darwin":
        return "macOS %s" % _platform.mac_ver()[0]
    return "%s %s" % (system or "未知平台", _platform.release())


def set_tcp_warnings(on: bool = True) -> bool:
    """打开 / 关闭 TCP 画像的"本机做不到"警告，返回改之前的状态。

    只影响**平台限制**类警告（顺序改不了、wscale 上不去、MSS 压不下来…）。
    画像串本身写错（格式、类型、越界）永远是 :class:`TCPShapeError`，不受此开关影响。
    """
    global _WARN_ENABLED
    old = _WARN_ENABLED
    _WARN_ENABLED = bool(on)
    return old


def _warn(profile: "TcpProfile | None", message: str,
          stacklevel: int = 3) -> None:
    """发一条"本机做不到"的警告。

    ``profile.warn`` 为 False 或全局开关关掉时静默；``profile=None`` 时只看全局开关。
    Python 默认的 warning 过滤器是"每个位置只报一次"，所以同一处代码重复请求
    只会看到一条；要每次都看到就 ``warnings.simplefilter("always")``。
    """
    if not _WARN_ENABLED:
        return
    if profile is not None and profile.warn is False:
        return
    _warnings.warn(message, TCPShapeWarning, stacklevel=stacklevel)


def _plain(head: str, *, actual: str | None = None,
           fix: str | None = None) -> str:
    """警告文案：一行问题 +（可选）``本机：``实际情况 +（可选）``可做：``一条做法。"""
    lines = [head]
    if actual is not None:
        lines.append("  本机：%s" % actual)
    if fix is not None:
        lines.append("  可做：%s" % fix)
    return "\n".join(lines)


def emit_warning(profile: "TcpProfile | None", message: str,
                 *, actual: str | None = None, fix: str | None = None,
                 stacklevel: int = 3) -> None:
    """对外公开的"本机做不到"警告出口（请求路径上复用同一套开关）。

    :mod:`nb_curl.session` 在 native 层回了 socket 错误时用它把消息抛出去，
    因此它必须与 :func:`_warn` 共用 ``profile.warn`` / :func:`set_tcp_warnings`
    的静音逻辑 —— 关掉警告后这里也不能响。
    """
    _warn(profile, _plain(message, actual=actual, fix=fix), stacklevel=stacklevel)


# --------------------------------------------------------------------------- #
# Linux sysctl / 接口 MTU 读取
# --------------------------------------------------------------------------- #
_LINUX_TS_PATH = "/proc/sys/net/ipv4/tcp_timestamps"
_LINUX_RMEM_MAX_PATH = "/proc/sys/net/core/rmem_max"
_LINUX_ADV_WIN_SCALE_PATH = "/proc/sys/net/ipv4/tcp_adv_win_scale"


def _read_int(path: str) -> int | None:
    try:
        with open(path) as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def _linux_timestamps() -> int | None:
    return _read_int(_LINUX_TS_PATH)


def _linux_rmem_max() -> int:
    return _read_int(_LINUX_RMEM_MAX_PATH) or 212992


def _linux_adv_win_scale() -> int:
    value = _read_int(_LINUX_ADV_WIN_SCALE_PATH)
    return 1 if value is None else value


def _linux_ws_of(space: int) -> int:
    """把 `space` 折成能达到的最小 wscale。"""
    ws = 0
    while space > 65535:
        space >>= 1
        ws += 1
    return ws


def _linux_window_of_space(space: int, mss: int) -> int:
    """Linux：SO_RCVBUF 折出的 `space` 最终会在 SYN 里通告多少窗口。"""
    if space > mss:
        space -= space % mss
    return min(space, 65535)


def _linux_mss_guess(profile: "TcpProfile") -> int:
    if profile.mss:
        return profile.mss
    mtus = [v for k, v in interface_mtu().items()
            if k != "lo" and v and v < 65536]
    return (max(mtus) - 40) if mtus else 1460


def interface_mtu(iface: str | None = None, refresh: bool = False):
    """查询本机各接口 IPv4 MTU。``MSS = MTU - 40``。

    无参返回 ``{接口名: mtu}``；给了 ``iface`` 返回该接口的 int（没有则 None）。
    Windows 用 ``netsh interface ipv4 show subinterfaces``（不需要管理员），
    Linux 读 ``/sys/class/net/*/mtu``，其他平台返回 ``{}``。
    """
    global _MTU_CACHE
    if _MTU_CACHE is None or refresh:
        family = _platform_family()
        if family == "windows":
            _MTU_CACHE = _windows_mtu()
        elif family == "linux":
            _MTU_CACHE = _linux_mtu()
        else:
            _MTU_CACHE = {}
    if iface is None:
        return dict(_MTU_CACHE)
    return _MTU_CACHE.get(iface)


def _windows_mtu() -> dict:
    try:
        out = _subprocess.run(
            ["netsh", "interface", "ipv4", "show", "subinterfaces"],
            capture_output=True, timeout=15,
        ).stdout.decode("mbcs" if _sys.platform == "win32" else "utf-8", "replace")
    except Exception:  # noqa: BLE001
        return {}
    result = {}
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) != 5:
            continue
        try:
            mtu = int(parts[0])
        except ValueError:
            continue
        name = parts[4].strip()
        if name:
            result[name] = mtu
    return result


def _linux_mtu() -> dict:
    import os

    result = {}
    try:
        for name in os.listdir("/sys/class/net"):
            try:
                with open("/sys/class/net/%s/mtu" % name) as fh:
                    result[name] = int(fh.read().strip())
            except (OSError, ValueError):
                continue
    except OSError:
        return {}
    return result


def set_interface_mtu(mtu: int, iface: str, *, store: str = "active") -> int | None:
    """改接口 IPv4 MTU（Windows 上改 SYN 里 MSS 的唯一路径）。返回改前的 MTU。

    * 需要**管理员权限**（Windows）或 root（Linux）。
    * ``store="active"`` 只在本次开机内生效；``"persistent"`` 写进配置。
    * 这是**全局**改动，影响该网卡上的所有连接 —— 用完请自己还原::

        old = nb_curl.set_interface_mtu(1400, "以太网")
        ...                       # 走这个画像的请求
        nb_curl.set_interface_mtu(old, "以太网")

    Linux 走 ``ip link set dev <iface> mtu <n>``。
    """
    if mtu < 576 or mtu > 65535:
        raise TCPShapeError("MTU 应在 576-65535 之间，收到 %r" % (mtu,))
    old = interface_mtu(iface)
    family = _platform_family()
    if family == "windows":
        cmd = ["netsh", "interface", "ipv4", "set", "subinterface", iface,
               "mtu=%d" % mtu, "store=%s" % store]
    elif family == "linux":
        cmd = ["ip", "link", "set", "dev", iface, "mtu", str(mtu)]
    else:
        raise TCPShapeError(
            "本平台没有接口 MTU 设置接口。\n  可做：只支持 Windows（netsh）与 Linux（ip link）")
    proc = _subprocess.run(cmd, capture_output=True)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout).decode(
            "mbcs" if family == "windows" else "utf-8", "replace").strip()
        names = ", ".join(sorted(interface_mtu(refresh=True))) or "（读不到接口列表）"
        raise TCPShapeError(
            "改接口 MTU 失败：%s\n  可做：需要管理员 / root；本机接口名：%s"
            % (err or "命令返回 %d" % proc.returncode, names))
    global _MTU_CACHE
    _MTU_CACHE = None
    return old


def set_tcp_timestamps(on: bool) -> int | None:
    """开关全局 TCP 时间戳（Linux 上唯一的路子）。返回改前的值。

    * 需要 **root**；这是**全局**改动，影响本机所有连接，用完请还原::

        old = nb_curl.set_tcp_timestamps(0)     # 关掉时间戳（SYN 里不再有 kind 8）
        ...                                    # 走这个画像的请求
        nb_curl.set_tcp_timestamps(old)        # 还原

    * 关掉后 Linux 的 option 顺序会变（``2-4-8-1-3`` -> ``2-1-1-4-1-3``），
      画像里的顺序段要填新顺序。
    * Windows 不需要它（逐 socket 的 ``timestamps=`` 就行）。
    """
    family = _platform_family()
    if family != "linux":
        raise TCPShapeError(
            "全局时间戳开关只有 Linux 有。\n  可做：Windows 用请求参数 timestamps=True / False")
    old = _linux_timestamps()
    if old is None:
        raise TCPShapeError(
            "读不到 /proc/sys/net/ipv4/tcp_timestamps。\n"
            "  可做：sudo sysctl -w net.ipv4.tcp_timestamps=%d"
            % (1 if on else 0))
    proc = _subprocess.run(
        ["sysctl", "-w", "net.ipv4.tcp_timestamps=%d" % (1 if on else 0)],
        capture_output=True,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout).decode("utf-8", "replace").strip()
        raise TCPShapeError(
            "改 net.ipv4.tcp_timestamps 失败：%s\n  可做：需要 root："
            "sudo sysctl -w net.ipv4.tcp_timestamps=%d"
            % (err or "命令返回 %d" % proc.returncode, 1 if on else 0))
    return old


# --------------------------------------------------------------------------- #
# 画像
# --------------------------------------------------------------------------- #
class TcpProfile:
    """解析后的 TCP 画像。``None`` 字段 = 不指定、跟随本机。

    ``warn``：``None`` = 跟随 :func:`set_tcp_warnings` 的全局开关；
    ``False`` = 这一次请求不发"本机做不到"的警告。
    """

    __slots__ = ("window", "order", "mss", "wscale", "ttl", "timestamp", "warn",
                 "predicted_window")

    def __init__(self, window: int | None, order: str | None,
                 mss: int | None, wscale: int | None, ttl: int | None,
                 timestamp: int | None = None, warn: bool | None = None):
        self.window = window
        self.order = order
        self.mss = mss
        self.wscale = wscale
        self.ttl = ttl
        self.timestamp = timestamp
        self.warn = warn
        # Linux：_check_linux 预告过"内核会把这个窗口压成多少"，
        # 回读校验据此避免把同一件事再报一遍（见 verify_actual）。
        self.predicted_window: int | None = None

    def key(self) -> tuple:
        """用于句柄侧"当前画像"比对与切换检测。不含 warn（不影响线上取值）。"""
        return (self.window, self.order, self.mss, self.wscale, self.ttl,
                self.timestamp)

    def __repr__(self) -> str:
        return ("TcpProfile(window=%r, order=%r, mss=%r, wscale=%r, ttl=%r, "
                "timestamp=%r)" % (self.window, self.order, self.mss,
                                   self.wscale, self.ttl, self.timestamp))


def _parse_int(value: Any, field: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        if isinstance(value, str) and value.strip().lstrip("+-").isdigit():
            value = int(value.strip())
        else:
            raise TCPShapeError(
                "tcp 画像的 %s 段必须是整数（%d-%d），收到 %r" % (field, low, high, value))
    if not low <= value <= high:
        raise TCPShapeError(
            "tcp 画像的 %s 段超出范围（%d-%d）：%d" % (field, low, high, value))
    return int(value)


def _parse_order(order: Any) -> str:
    if not isinstance(order, str) or not _ORDER_RE.match(order.strip()):
        raise TCPShapeError(
            "tcp 画像的 order 段要写成 TCP option kind 序列（如 '2-1-3-1-1-4'，"
            "整段可空表示跟随本机），收到 %r" % (order,))
    return order.strip()


def _parse_only_string(spec: str, warn: bool | None) -> TcpProfile:
    """只解析（含越界校验），不做平台能力检查。"""
    if not isinstance(spec, str):
        raise TCPShapeError(
            'tcp 必须是 JA4T 字符串 "window_order_mss_wscale"（或只给关心字段的 dict），'
            "收到 %r" % (spec,))

    parts = spec.strip().split("_")
    if len(parts) != 4:
        raise TCPShapeError(
            "tcp 格式错误：%r\n"
            '  应为 "window_order_mss_wscale"（JA4T 四段），'
            '如 "64240_2-1-3-1-1-4_1400_8"\n'
            "  想只改其中几项就传 dict，如 tcp={'window': 64240, 'wscale': 8}" % spec)

    window_seg, order_seg, mss_seg, wscale_seg = (p.strip() for p in parts)

    return TcpProfile(
        _parse_int(window_seg, "window", 1, 65535),
        _parse_order(order_seg),
        _parse_int(mss_seg, "MSS", 536, 65535),
        _parse_int(wscale_seg, "wscale", 0, 14),
        None, None, warn,
    )


def parse_tcp_profile(spec: str, *, warn: bool | None = None) -> TcpProfile:
    """解析 JA4T 四段串 ``"window_order_mss_wscale"``，四段都填真实值。

    就是检测站输出的 JA4T 原样格式，如 ``"64240_2-1-3-1-1-4_1400_8"``。
    TTL 与时间戳不在这里 —— 它们是独立参数（见 :func:`build_tcp_profile`）。
    本机做不到的项只发 :class:`TCPShapeWarning`。
    """
    profile = _parse_only_string(spec, warn)
    _check_platform(profile, stacklevel=4)
    return profile


def _parse_tcp_dict(spec: Mapping[str, Any], *, warn: bool | None = None) -> TcpProfile:
    """dict 形式：只给想改的字段，其余跟随本机。

    ``{"window": 64240, "order": "2-1-3-1-1-4", "mss": 1400, "wscale": 8}``
    四个键都可选；一个都不给等于只给 ttl / timestamps。
    """
    unknown = set(spec) - set(_PROFILE_KEYS)
    if unknown:
        raise TCPShapeError(
            "tcp 字典含未知键 %s；可用键：%s"
            % (sorted(unknown), ", ".join(_PROFILE_KEYS)))

    profile = TcpProfile(
        _parse_int(spec["window"], "window", 1, 65535) if spec.get("window") is not None else None,
        _parse_order(spec["order"]) if spec.get("order") is not None else None,
        _parse_int(spec["mss"], "MSS", 536, 65535) if spec.get("mss") is not None else None,
        _parse_int(spec["wscale"], "wscale", 0, 14) if spec.get("wscale") is not None else None,
        None, None, warn,
    )
    return profile


def build_tcp_profile(tcp: Any = None, ttl: int | None = None,
                      timestamps: bool | int | None = None,
                      warn: bool | None = None) -> TcpProfile | None:
    """把三个独立参数合成一个画像；全空返回 ``None``（不启用）。

    * ``tcp``：JA4T 四段串，或 ``{"window":..., "order":..., "mss":..., "wscale":...}``
    * ``ttl``：1-255 的整数（``IP_TTL``）
    * ``timestamps``：``True`` / ``False``（TCP 时间戳选项）
    * ``warn``：``False`` 关掉本次的"本机做不到"警告（``None`` 跟随全局开关）
    """
    if tcp is None and ttl is None and timestamps is None:
        return None
    if tcp is None:
        profile = TcpProfile(None, None, None, None, None, None, warn)
    elif isinstance(tcp, str):
        profile = _parse_only_string(tcp, warn)
    elif isinstance(tcp, Mapping):
        profile = _parse_tcp_dict(tcp, warn=warn)
    else:
        raise TCPShapeError(
            "tcp 只接受 JA4T 字符串或 dict，收到 %r" % (tcp,))

    profile.warn = warn

    if ttl is not None:
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= 255:
            raise TCPShapeError("ttl 必须是 1-255 的整数，收到 %r" % (ttl,))
        profile.ttl = ttl
    if timestamps is not None:
        if isinstance(timestamps, bool):
            profile.timestamp = 1 if timestamps else 0
        elif timestamps in (0, 1):
            profile.timestamp = int(timestamps)
        else:
            raise TCPShapeError(
                "timestamps 必须是 True/False（或 0/1），收到 %r" % (timestamps,))

    _check_platform(profile, stacklevel=4)
    return profile


def _check_platform(profile: TcpProfile, *, stacklevel: int = 3) -> None:
    """本机能力相关的问题一律**发警告**，不抛异常。"""
    family = _platform_family()
    knobs = _KNOBS.get(family, _KNOBS_UNKNOWN)

    if profile.order is not None:
        native = _native_order(family)
        if native is None:
            _warn(profile, _plain(
                "option 顺序段 %r 无法校验（本机平台 %s 未标定）。"
                % (profile.order, _platform.system() or "unknown"),
                actual="顺序由内核决定，与本参数无关",
                fix="用 nb_curl.tcp_support() 查本机顺序"), stacklevel)
        elif profile.order != native:
            fix = "顺序段只能填 %s" % native
            if family == "linux" and "8" in native and "8" not in profile.order:
                fix += "；关掉时间戳（timestamps=False）后顺序变为 %s" % _LINUX_ORDER_TS_OFF
            _warn(profile, _plain(
                "option 顺序 %s 本机改不了，这一项不生效。" % profile.order,
                actual="顺序恒为 %s" % native,
                fix=fix), stacklevel)

    for field in ("window", "wscale", "mss", "ttl", "timestamp"):
        value = getattr(profile, field)
        if value is None or knobs[field]:
            continue
        if family == "windows" and field == "mss":
            continue
        _warn(profile, _plain(
            "%s 在本平台没有设置接口，这一项不生效。" % _FIELD_CN[field],
            actual="%s = %s" % (field, value),
            fix="用 nb_curl.tcp_support() 查看本机可用字段"), stacklevel)

    if family == "linux":
        _check_linux(profile, stacklevel=stacklevel + 1)

    if family == "windows" and profile.mss is not None:
        need = profile.mss + 40
        mtus = [v for v in interface_mtu().values() if 576 <= v <= 65535]
        if mtus and need > max(mtus):
            _warn(profile, _plain(
                "mss=%d 需要网卡 MTU >= %d，本机最大只有 %d。"
                % (profile.mss, need, max(mtus)),
                fix="netsh interface ipv4 set subinterface \"<网卡名>\" mtu=%d "
                    "store=active（需管理员）" % need), stacklevel)


def _check_linux(profile: TcpProfile, *, stacklevel: int = 3) -> None:
    mss = _linux_mss_guess(profile)

    # 内核把通告窗口向下取整到 MSS 的整数倍（65535 = "能多大就多大"，不参与）。
    # 用户没给 mss 时用本机网卡 MTU 推算 —— 宁可提前提示，也别让他以为窗口真是 64240；
    # 建连后 verify_actual() 还会用**回读到的真实 MSS** 再确认一次。
    if (profile.window is not None and profile.window < 65535
            and profile.window >= mss and profile.window % mss):
        rounded = profile.window - profile.window % mss
        if profile.mss is not None:
            actual = "mss=%d（你给的）" % mss
            fix = "改用 window=%d，或把 mss 段改成能整除 %d 的值" % (rounded, profile.window)
        else:
            actual = "按本机网卡 MTU 推算 mss=%d" % mss
            fix = "改用 window=%d" % rounded
        profile.predicted_window = rounded
        _warn(profile, _plain(
            "window=%d 不是 mss=%d 的整数倍，内核会压成 %d。"
            % (profile.window, mss, rounded),
            actual=actual, fix=fix), stacklevel)

    if profile.timestamp is not None:
        current = _linux_timestamps()
        if current is None:
            _warn(profile, _plain(
                "读不到 /proc/sys/net/ipv4/tcp_timestamps，timestamps 不生效。",
                fix="去掉 timestamps 参数"), stacklevel)
        elif current != int(profile.timestamp):
            _warn(profile, _plain(
                "timestamps=%s 与全局状态不符，不生效（Linux 只能全局改）。"
                % ("True" if profile.timestamp else "False"),
                actual="net.ipv4.tcp_timestamps = %d" % current,
                fix="sudo sysctl -w net.ipv4.tcp_timestamps=%d（需 root），"
                    "或去掉 timestamps 参数" % profile.timestamp), stacklevel)

    # window / wscale 的可行性由 plan_rcvbuf 统一判定（它在请求路径上只被调一次，
    # 免得同一条警告从这里和那里各发一遍）。


# --------------------------------------------------------------------------- #
# SO_RCVBUF：window / wscale 的唯一落点
# --------------------------------------------------------------------------- #
def _win_rcvbuf(profile: TcpProfile, *, stacklevel: int = 3) -> int | None:
    """Windows：`ws = max(0, floor(log2(SO_RCVBUF)) - 15)`，`win = min(rcvbuf, 65535)`。

    实测锚点：8192/32768/65535 -> ws0，64K -> 1、128K -> 2、512K -> 4、
    1M -> 5、2M -> 6、8M -> 8、16M -> 9。

    一个 SO_RCVBUF 同时决定窗口与 wscale，所以：

    * 两个都给了 -> 只有存在同时成立的 rcvbuf 才下发（``window==65535`` 可以配任意
      wscale；``window<65535`` 只有 ``wscale==0`` 成立），否则**一个都不设**；
    * 只给了一个 -> 另一个会跟着变，下发前发一条提示说明会变成多少。
    """
    if profile.window is None and profile.wscale is None:
        return None

    if profile.window is not None and profile.wscale is not None:
        if profile.window >= 65535:
            return 65535 if profile.wscale <= 0 else 1 << (profile.wscale + 15)
        if profile.wscale != 0:
            _warn(profile, _plain(
                "window=%d 配 wscale=%d 在 Windows 上做不到，这一组不生效，"
                "本机默认窗口保持不变。" % (profile.window, profile.wscale),
                actual="rcvbuf<=65535 时窗口=rcvbuf、wscale 恒 0",
                fix="改用 wscale=0 配 window=%d，或 window=65535 配 wscale=%d"
                    % (profile.window, profile.wscale)), stacklevel)
            return None
        return profile.window

    if profile.window is not None:
        # 只给窗口：rcvbuf=window，wscale 必然变成 0
        _warn(profile, _plain(
            "只给了 window=%d，wscale 会跟着 SO_RCVBUF 变成 0。" % profile.window,
            fix="想连 wscale 一起定就两个都传，如 "
                "tcp={'window': %d, 'wscale': 0}" % profile.window), stacklevel)
        return profile.window

    # 只给 wscale
    rcvbuf = 65535 if profile.wscale <= 0 else 1 << (profile.wscale + 15)
    _warn(profile, _plain(
        "只给了 wscale=%d，window 会跟着 SO_RCVBUF 变成 %d。"
        % (profile.wscale, min(rcvbuf, 65535)),
        fix="想连 window 一起定就两个都传，如 "
            "tcp={'window': %d, 'wscale': %d}" % (min(rcvbuf, 65535), profile.wscale)),
        stacklevel)
    return rcvbuf


def plan_rcvbuf(profile: TcpProfile, *, stacklevel: int = 3) -> int | None:
    """把画像折算成一个 ``SO_RCVBUF``（下发值）。

    **返回 ``None`` = 完全不碰 ``SO_RCVBUF``**，本机默认窗口 / wscale 原样保留。
    这些情况会返回 None（并各发一条警告）：

    * 只给了 ttl / mss / timestamps；
    * ``window`` 与 ``wscale`` 这一对在本机无法用同一个 SO_RCVBUF 同时达成
      （Windows 的 ``64240_..._8``、Linux 上 rmem_max 不够的高 wscale…）；
    * 本机换算表失效（Linux ``net.ipv4.tcp_adv_win_scale != 1``）。

    绝不"折中"成一个别的值 —— 宁可什么都不设。
    """
    if profile.window is None and profile.wscale is None:
        return None
    family = _platform_family()
    if family == "windows":
        return _win_rcvbuf(profile, stacklevel=stacklevel + 1)
    if family != "linux":
        _warn(profile, _plain(
            "%s 上没有窗口 / wscale 的设置接口，这一组不生效。" % (_platform.system() or "本平台"),
            actual="本机默认窗口保持不变",
            fix="用 nb_curl.tcp_support() 查本机可用字段"), stacklevel)
        return None

    if _linux_adv_win_scale() != 1:
        _warn(profile, _plain(
            "本机 net.ipv4.tcp_adv_win_scale = %d，窗口 / wscale 的换算表只在默认值 1 "
            "下有效，这一组不生效，本机默认窗口保持不变。" % _linux_adv_win_scale(),
            fix="sudo sysctl -w net.ipv4.tcp_adv_win_scale=1（需 root），"
                "或去掉 tcp= 只传 ttl / timestamps"), stacklevel)
        return None

    mss = _linux_mss_guess(profile)
    rmem = _linux_rmem_max()
    lo, hi = 1, rmem

    if profile.wscale is not None:
        if profile.wscale == 0:
            hi = min(hi, 65535)
        else:
            lo = max(lo, 1 << (profile.wscale + 15))
            hi = min(hi, (1 << (profile.wscale + 16)) - 1)
        if lo > rmem:
            _warn(profile, _plain(
                "wscale=%d 需要 SO_RCVBUF >= %d，超过本机上限 %d，这一组不生效，"
                "本机默认窗口保持不变。" % (profile.wscale, lo, rmem),
                actual="net.core.rmem_max = %d" % rmem,
                fix="sudo sysctl -w net.core.rmem_max=%d（需 root），或改用 wscale=%d"
                    % (lo * 2, _linux_ws_of(rmem))), stacklevel)
            return None

    if profile.window is not None:
        if profile.window >= 65535:
            lo = max(lo, -(-65535 // mss) * mss)
        else:
            lo = max(lo, profile.window)
            hi = min(hi, profile.window + mss - 1)

    if lo > hi:
        _warn(profile, _plain(
            "window=%s 与 wscale=%s 在本机无法同时达成，这一组不生效，"
            "本机默认窗口保持不变。" % (profile.window, profile.wscale),
            actual="两者都出自同一个 SO_RCVBUF（估计 MSS = %d）：wscale>=1 时窗口只能是 65535"
                   % mss,
            fix="改用 wscale=0 配 window=%s，或 window=65535 配该 wscale"
                % profile.window), stacklevel)
        return None

    # 只给了一个：另一个由 SO_RCVBUF 决定，下发前告诉用户会变成多少
    if profile.window is None:
        _warn(profile, _plain(
            "只给了 wscale=%d，window 会跟着 SO_RCVBUF 变成 %d。"
            % (profile.wscale, _linux_window_of_space(lo, mss)),
            fix="想连 window 一起定就两个都传"), stacklevel)
    elif profile.wscale is None:
        _warn(profile, _plain(
            "只给了 window=%d，wscale 会跟着 SO_RCVBUF 变成 %d。"
            % (profile.window, _linux_ws_of(lo)),
            fix="想连 wscale 一起定就两个都传"), stacklevel)

    return lo


# --------------------------------------------------------------------------- #
# 回读校验
# --------------------------------------------------------------------------- #
def verify_actual(profile: TcpProfile, actual: dict,
                  *, rcvbuf_set: bool = True, stacklevel: int = 3) -> None:
    """连接建立后回读校验：可回读的字段不符就**发警告**。

    ``actual`` 是底层 ``easy_check_tcp_shape()`` 的返回（-1 = 该平台读不到）。
    读不到的字段跳过；连接复用时底层不给快照，这里也不会被调用。

    ``rcvbuf_set=False``：本次**故意没有**下发 ``SO_RCVBUF``（见 :func:`plan_rcvbuf`），
    窗口与 wscale 保持本机默认 —— 这两项不再比对，免得报出"未达成"的假问题。
    """
    family = _platform_family()
    verifiable = _VERIFIABLE.get(family, _VERIFIABLE_UNKNOWN)

    if family == "windows":
        rcvbuf = actual.get("rcvbuf", -1)
        if rcvbuf and rcvbuf > 0:
            if rcvbuf_set and profile.window is not None:
                got_win = min(rcvbuf, 65535)
                if got_win != profile.window:
                    _warn(profile, _plain(
                        "window=%d 未达成，内核发的是 %d。" % (profile.window, got_win),
                        fix="改用 window=%d" % got_win), stacklevel)
            if profile.mss is not None:
                ts_on = 1 if actual.get("timestamp") == 1 else 0
                expect = profile.mss - _TS_OPTION_BYTES * ts_on
                got_mss = actual.get("mss", -1)
                if got_mss and got_mss > 0 and abs(got_mss - expect) > _SIO_MSS_SLACK:
                    syn_mss = got_mss + _TS_OPTION_BYTES * ts_on
                    need = profile.mss + 40
                    mtu_max = max(
                        (v for v in interface_mtu().values()
                         if 576 <= v <= 65535), default=0)
                    if mtu_max and need <= mtu_max:
                        _warn(profile, _plain(
                            "mss=%d 未达成，实际是 %d；网卡 MTU 已够，是这条路由的 PMTU 更小。"
                            % (profile.mss, syn_mss),
                            fix="改用 mss=%d；改网卡 MTU 无效" % syn_mss), stacklevel)
                    else:
                        _warn(profile, _plain(
                            "mss=%d 未达成，实际是 %d（本机最大网卡 MTU %d）。"
                            % (profile.mss, syn_mss, mtu_max),
                            fix="netsh interface ipv4 set subinterface \"<网卡名>\" "
                                "mtu=%d store=active（需管理员）" % need), stacklevel)
            # 没下发 SO_RCVBUF 时 wscale 保持本机默认，不比对（否则会报"未达成"的假问题）
            if rcvbuf_set and profile.wscale is not None:
                got_ws = max(0, rcvbuf.bit_length() - 16)
                if got_ws != profile.wscale:
                    _warn(profile, _plain(
                        "wscale=%d 未达成，实际是 %d。" % (profile.wscale, got_ws),
                        fix="改用 wscale=%d" % got_ws), stacklevel)

    if family == "linux":
        rcvbuf = actual.get("rcvbuf", -1)
        got_mss = actual.get("mss", -1)
        # getsockopt(SO_RCVBUF) 回读的是内核双倍化后的值，所以 space = rcvbuf // 2；
        # rcvbuf_set=False 时我们故意没设，窗口是本机默认，不比对（否则会误报未达成）。
        if rcvbuf_set and rcvbuf and rcvbuf > 0 and profile.window is not None:
            space = rcvbuf // 2
            if profile.mss is not None:
                mss_cands = [profile.mss]
            elif got_mss and got_mss > 0:
                guess = _linux_mss_guess(profile)
                mss_cands = sorted({got_mss, got_mss + _TS_OPTION_BYTES, guess})
            else:
                mss_cands = []
            if mss_cands:
                wins = [_linux_window_of_space(space, m) for m in mss_cands]
                # predicted_window 命中 = 就是 _check_linux 提前讲过的那个取整结果，
                # 不需要把同一件事再说一遍。
                if (profile.window not in wins
                        and profile.predicted_window not in wins):
                    _warn(profile, _plain(
                        "window=%d 未达成，实际可能是 %s。"
                        % (profile.window, " / ".join(str(w) for w in wins)),
                        actual="SO_RCVBUF=%d、MSS=%s"
                               % (rcvbuf, " / ".join(str(m) for m in mss_cands)),
                        fix="把 mss 段写成这条链路的真实值 %d，或改用 window=%d"
                            % (got_mss, wins[0])), stacklevel)

    for field in ("ttl", "mss", "wscale", "timestamp"):
        target = getattr(profile, field)
        if target is None or not verifiable[field]:
            continue
        if family == "windows" and field in ("mss", "window", "wscale"):
            continue
        if field == "wscale" and not rcvbuf_set:
            continue        # 没下发 SO_RCVBUF，wscale 保持本机默认，不比对
        got = actual.get(field, -1)
        if got is None or got < 0:
            continue
        if got == target:
            continue
        if family == "linux" and field == "mss" and abs(got - target) <= _TS_OPTION_BYTES:
            continue
        if family == "linux" and field == "mss":
            _warn(profile, _plain(
                "mss=%d 未达成，实际是 %d。" % (target, got),
                actual="TCP_MAXSEG 会被内核夹到它接受的范围",
                fix="改用 mss=%d" % got), stacklevel)
            continue
        if field == "wscale":
            rcvbuf = actual.get("rcvbuf", -1)
            actual_line = "wscale 实际 %d" % got
            if rcvbuf and rcvbuf > 0:
                actual_line += "，SO_RCVBUF 生效 %d" % rcvbuf
            _warn(profile, _plain(
                "wscale=%d 未达成。" % target,
                actual=actual_line,
                fix="改用 wscale=%d" % got), stacklevel)
            continue
        if field == "timestamp":
            _warn(profile, _plain(
                "timestamps=%s 未达成。" % ("True" if target else "False"),
                actual="实际 %s" % ("已开启" if got else "已关闭"),
                fix="去掉 timestamps 参数"), stacklevel)
            continue
        _warn(profile, _plain(
            "%s=%s 未达成，实际是 %s。" % (field, target, got),
            fix="改用 %s=%s" % (field, got)), stacklevel)


# --------------------------------------------------------------------------- #
# 自省
# --------------------------------------------------------------------------- #
def tcp_support() -> dict:
    """本机 TCP 画像能力自省。

    返回::

        {
          "platform": "Windows (build 10.0.19045)",
          "native_order": "2-1-3-1-1-4",   # 本机 option 顺序（改不了）
          "knobs":      {"ttl": True, "mss": True, "window": True,
                         "wscale": True, "timestamp": True},
          "verifiable": {"ttl": True, "mss": True, "window": True,
                         "wscale": True, "timestamp": True},
          "mss_mechanism": "interface-mtu",   # 或 "socket"
          "ts_mechanism":  "socket",          # Linux 是 "global-sysctl"
          "interface_mtu":  {"以太网": 1500},
        }

    ``knobs`` = 能否设置；``verifiable`` = 设置后能否回读证实。
    Linux 上多两个键：``tcp_timestamps``（当前全局值）、``rmem_max``。
    """
    family = _platform_family()
    info = {
        "platform": _platform_label(),
        "native_order": _native_order(family),
        "knobs": dict(_KNOBS.get(family, _KNOBS_UNKNOWN)),
        "verifiable": dict(_VERIFIABLE.get(family, _VERIFIABLE_UNKNOWN)),
        "mss_mechanism": _MSS_MECHANISM.get(family),
        "ts_mechanism": _TS_MECHANISM.get(family),
        "interface_mtu": interface_mtu(),
        "warn_enabled": _WARN_ENABLED,
    }
    if family == "linux":
        info["tcp_timestamps"] = _linux_timestamps()
        info["rmem_max"] = _linux_rmem_max()
    return info


def _native_order(family: str) -> str | None:
    if family == "linux":
        ts = _linux_timestamps()
        if ts == 0:
            return _LINUX_ORDER_TS_OFF
    return _NATIVE_ORDER.get(family)
