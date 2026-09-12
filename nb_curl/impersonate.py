"""nb_curl.impersonate —— 内置指纹预设

内置表在 **C 内核**（``lib/impersonate.c`` 的 ``impersonations[]``，
由 native 的 ``easy_impersonate_exists`` 真实校验），全部可以直接传给
``impersonate`` 参数，本模块负责归一化与校验。

想知道有哪些值可以填：

* 看本模块的 :data:`ImpersonateTarget`（IDE 里对 ``impersonate`` 参数
  会直接补全这些值）；
* 运行期用 ``nb_curl.available_targets()``（只列出本机真正可用的）；
* 家族别名（``"chrome"`` / ``"firefox"`` / ``"safari"`` / ``"edge"`` /
  ``"okhttp"`` / ``"tor"``）会自动解析为该家族的最新版本。
"""

from __future__ import annotations

from typing import Literal

from ._native import lib
from .exceptions import ImpersonateError

__all__ = [
    "ImpersonateTarget",
    "BUILTIN_TARGETS",
    "FAMILY_LATEST",
    "resolve_target",
    "available_targets",
    "is_available",
    "normalize_spec",
    "assert_available",
]

# lib/impersonate.c 的 impersonations[]（40 个），仅用于展示与文档；
# 真正的是否可用一律以 native 探测结果为准。
BUILTIN_TARGETS: tuple[str, ...] = (
    "chrome99", "chrome99_android",
    "chrome100", "chrome101", "chrome104", "chrome107", "chrome110",
    "chrome116", "chrome119", "chrome120", "chrome123", "chrome124",
    "chrome131", "chrome131_android", "chrome133a", "chrome136",
    "chrome142", "chrome145", "chrome146", "chrome150", "chrome152",
    "edge99", "edge101",
    "firefox133", "firefox135", "firefox144", "firefox147",
    "okhttp4_android",
    "safari153", "safari155", "safari170", "safari172_ios",
    "safari180", "safari180_ios", "safari184", "safari184_ios",
    "safari260", "safari2601", "safari260_ios",
    "tor145",
)

# impersonate 参数的 IDE 补全提示（Literal）。
# 新增 C 预设时同步把名字加进这里（测试会校验与 BUILTIN_TARGETS 一致）。
ImpersonateTarget = Literal[
    "chrome99", "chrome99_android",
    "chrome100", "chrome101", "chrome104", "chrome107", "chrome110",
    "chrome116", "chrome119", "chrome120", "chrome123", "chrome124",
    "chrome131", "chrome131_android", "chrome133a", "chrome136",
    "chrome142", "chrome145", "chrome146", "chrome150", "chrome152",
    "edge99", "edge101",
    "firefox133", "firefox135", "firefox144", "firefox147",
    "okhttp4_android",
    "safari153", "safari155", "safari170", "safari172_ios",
    "safari180", "safari180_ios", "safari184", "safari184_ios",
    "safari260", "safari2601", "safari260_ios",
    "tor145",
]

# 家族名 -> 最新版本
FAMILY_LATEST = {
    "chrome": "chrome152",
    "chromium": "chrome152",
    "edge": "edge101",
    "firefox": "firefox147",
    "okhttp": "okhttp4_android",
    "safari": "safari2601",
    "tor": "tor145",
}

# 本项目主推的内置版本
RECOMMENDED_TARGETS: tuple[str, ...] = (
    "chrome99",
    "chrome116",
    "chrome131",
    "chrome146",
    "chrome150",
    "chrome152",
    "firefox147",
)


def resolve_target(target: str) -> str:
    """把家族名/预设名解析成具体名字（已经是版本号则原样返回）。

    解析顺序：家族别名 -> C 内置表。
    """
    if not target:
        raise ImpersonateError("impersonate target 不能为空")
    key = target.strip()
    lowered = key.lower()
    if lowered in FAMILY_LATEST:
        return FAMILY_LATEST[lowered]
    # 大小写不敏感匹配 C 内置表
    for name in BUILTIN_TARGETS:
        if name.lower() == lowered:
            return name
    return key


def is_available(target: str) -> bool:
    """探测某个 target 在 native 层是否真的存在。"""
    if not target:
        return False
    resolved = resolve_target(target)
    return bool(lib.easy_impersonate_exists(resolved.encode("utf-8")))


def available_targets() -> list[str]:
    """返回本机真正可用的 target 列表（C 内核逐个探测）。"""
    return [name for name in BUILTIN_TARGETS if is_available(name)]


def normalize_spec(spec: str) -> tuple[str, bool]:
    """拆解 ``"chrome116"`` / ``"chrome116:no"`` -> ``("chrome116", True/False)``。

    返回 ``(target, default_headers)``；``:no`` 表示不下发浏览器默认头。
    """
    if not isinstance(spec, str):
        raise ImpersonateError("impersonate 必须是字符串，收到 %r" % (spec,))
    name, _, flag = spec.partition(":")
    name = name.strip()
    flag = flag.strip().lower()
    default_headers = True
    if flag in ("no", "false", "0", "off"):
        default_headers = False
    elif flag in ("yes", "true", "1", "on", ""):
        default_headers = True
    else:
        raise ImpersonateError("impersonate 后缀只能是 yes/no，收到 %r" % flag)
    return resolve_target(name), default_headers


def assert_available(target: str) -> str:
    """校验 target 可用，不可用则抛 ImpersonateError（附可用列表）。"""
    resolved = resolve_target(target)
    if not is_available(resolved):
        raise ImpersonateError(
            "未知或不可用的 impersonate target: %r。可用示例: %s"
            % (target, ", ".join(RECOMMENDED_TARGETS))
        )
    return resolved
