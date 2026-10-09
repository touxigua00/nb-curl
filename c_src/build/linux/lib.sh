#!/bin/bash
# 公共变量与工具函数 —— 其它脚本都 source 这个文件
#
# 目录约定（统一根 = <仓库根>，本文件在 <root>/build/linux/scripts/lib.sh）：
#
#   <root>/python/                 项目根（Python 包 + C 桥接源码 + 测试 + dist）
#   <root>/deps/sources/           打补丁的 BoringSSL / curl 源码包（Windows 也共用）
#   <root>/build/linux/_work/      Linux 构建中间目录（可删，会重新解包编译）
#   <root>/build/linux/_work/prefix  BoringSSL + curl 的安装前缀
set -euo pipefail

# scripts/ -> build/linux/ -> build/ -> 仓库根
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORK="$ROOT/build/linux/_work"
PREFIX="$WORK/prefix"
SOURCES="$ROOT/deps/sources"

BSSL_SRC="$WORK/boringssl"
CURL_SRC="$WORK/curl-8.22.0"
CURL_BUILD="$CURL_SRC/build-linux"

SCRIPTS="$ROOT/build/linux/scripts"   # 本套件脚本目录
PROJECT="$ROOT/python"            # 项目根（含 native/ 与 nb_curl/）
NATIVE_DIR="$PROJECT/native"      # 桥接层源码
PKG="$PROJECT/nb_curl"              # Python 包目录
LIBDIR="$PKG/_lib"                # 动态库落位处

JOBS="${NB_CURL_JOBS:-$(nproc 2>/dev/null || echo 4)}"

# ------------------------------------------------------------------ #
# 输出
# ------------------------------------------------------------------ #
c_info()  { printf '\033[1;34m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
c_ok()    { printf '\033[1;32m[ OK ]\033[0m %s\n' "$*"; }
c_warn()  { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
c_err()   { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; }

die() { c_err "$*"; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "缺少命令 $1 —— 请先运行 scripts/00_deps.sh"
}

# 把源码包解到 _work/<final>（已存在则跳过）
#   $1 = 压缩包路径
#   $2 = 最终目录名（如 boringssl）
#   $3 = 包内顶层目录名（如 boringssl-156c7b75...）
unpack() {
  local archive="$1" final="$2" top="$3"
  if [ -d "$WORK/$final" ]; then
    c_info "$final 源码已存在，跳过解包"
    return 0
  fi
  [ -f "$archive" ] || die "找不到源码包 $archive"
  mkdir -p "$WORK"
  c_info "解包 $(basename "$archive") ..."
  tar -xzf "$archive" -C "$WORK"
  if [ "$top" != "$final" ]; then
    [ -d "$WORK/$top" ] || die "解包后没找到 $WORK/$top"
    mv "$WORK/$top" "$WORK/$final"
  fi
  c_ok "$final 就绪"
}
