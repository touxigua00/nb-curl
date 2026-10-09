#!/bin/bash
# 00 —— 安装系统依赖
#
# 目标平台：Ubuntu 22.04 / 24.04（Debian 系同理）
# 其它发行版请对照安装等价包。
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

c_info "安装系统依赖（需要 sudo）"

SUDO=""
if [ "$(id -u)" != "0" ]; then
  command -v sudo >/dev/null 2>&1 || die "非 root 且没有 sudo"
  SUDO="sudo"
fi

export DEBIAN_FRONTEND=noninteractive
$SUDO apt-get update -qq

# 分组说明：
#   build-essential cmake ninja-build pkg-config   —— 编译工具链
#   perl                                           —— BoringSSL perlasm 生成汇编
#   nasm                                           —— x86_64 汇编（Windows 必需，POSIX 装了也无害）
#   zlib1g-dev libbrotli-dev libzstd-dev           —— curl 的压缩支持
#   libnghttp2-dev                                 —— HTTP/2
#   libidn2-dev                                    —— 域名 IDN
#   python3-dev python3-venv python3-pip           —— 编译 CFFI 扩展 / 建 venv
#   ca-certificates                                —— 运行期 CA（我们另有内置 cacert.pem）
$SUDO apt-get install -y --no-install-recommends \
  build-essential cmake ninja-build pkg-config perl nasm \
  zlib1g-dev libbrotli-dev libzstd-dev libnghttp2-dev libidn2-dev \
  python3-dev python3-venv python3-pip \
  ca-certificates file

c_ok "系统依赖就绪"
echo
c_info "版本检查："
for c in gcc cmake ninja perl nasm python3; do
  printf '  %-8s %s\n' "$c" "$(command -v $c >/dev/null 2>&1 && $c --version 2>/dev/null | head -1 || echo '(缺失)')"
done
