#!/bin/bash
# toolchain.sh —— 定位 Windows 构建工具链（MSVC / Windows SDK / cmake / ninja / nasm）
#
# 被 build/windows/*.sh 用 `. toolchain.sh` 引入。所有路径都能用环境变量覆盖，
# 默认值全部自动探测，换一台机器不需要改脚本：
#
#   NB_CURL_MSVC_TOOLS   ...\VC\Tools\MSVC 目录（留空则先问 vswhere，再扫常见安装位置）
#   NB_CURL_SDK_ROOT     Windows SDK 根目录（默认 C:\Program Files (x86)\Windows Kits\10）
#   NB_CURL_SDK_VER      SDK 版本（留空取 Include/ 下最新的一个）
#   NB_CURL_CMAKE        显式指定 cmake.exe
#   NB_CURL_NINJA        显式指定 ninja.exe
#   NB_CURL_NASM         显式指定 nasm.exe
#   NB_CURL_VCPKG        第三方静态库树（zlib/brotli/zstd/nghttp2）
#   NB_CURL_PRINT_TOOLCHAIN=1   引入时把探测结果打出来，便于排查
#
# 引入后可用变量：MSVC SDK SDKV CL CMAKE NINJA NASM VCPKG
# MSVC/SDK/CL/CMAKE 等一律是 Windows 风格路径（C:/...），因为 cl.exe 与 cmake
# 不认 MSYS 的 /c/... 写法。
#
# 前提：调用方必须先设好 $REPO（仓库根的 Windows 风格路径）。

[ -n "$NB_CURL_TOOLCHAIN_LOADED" ] && return 0
NB_CURL_TOOLCHAIN_LOADED=1

if [ -z "$REPO" ]; then
  echo "[ERROR] toolchain.sh 需要调用方先设置 \$REPO（仓库根路径）" >&2
  return 1 2>/dev/null || exit 1
fi

# MSYS 路径 -> Windows 风格（C:/...）；cl.exe / cmake 只认后者
_winp() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"
  else printf '%s' "$1" | sed -E 's#^/([a-zA-Z])/#\1:/#'
  fi
}

_find_msvc_tools() {
  if [ -n "$NB_CURL_MSVC_TOOLS" ] && [ -d "$NB_CURL_MSVC_TOOLS" ]; then
    echo "$NB_CURL_MSVC_TOOLS"; return 0
  fi
  local vsw="/c/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe"
  if [ -f "$vsw" ]; then
    local inst
    inst=$("$vsw" -latest -products '*' -property installationPath 2>/dev/null \
           | tr -d '\r' | head -1)
    if [ -n "$inst" ]; then
      local p
      p="$(cygpath -u "$inst" 2>/dev/null || echo "$inst")/VC/Tools/MSVC"
      [ -d "$p" ] && { echo "$p"; return 0; }
    fi
  fi
  local base edn
  for base in "/c/Program Files" "/c/Program Files (x86)" "/d/Program_files" "/d/Program Files"; do
    for edn in Community Professional Enterprise BuildTools; do
      if [ -d "$base/Microsoft Visual Studio/2022/$edn/VC/Tools/MSVC" ]; then
        echo "$base/Microsoft Visual Studio/2022/$edn/VC/Tools/MSVC"; return 0
      fi
    done
  done
  return 1
}

MSVC_TOOLS="$(_find_msvc_tools)" || {
  echo "[ERROR] 找不到 MSVC 工具链。" >&2
  echo "        请安装 Visual Studio 2022 并勾选「使用 C++ 的桌面开发」工作负载，" >&2
  echo "        或用 NB_CURL_MSVC_TOOLS 指向 ...\\VC\\Tools\\MSVC。" >&2
  return 1 2>/dev/null || exit 1
}
# 同一台机器可能装了多个版本，取版本号最大的
MSVC_VER="$(ls "$MSVC_TOOLS" 2>/dev/null | sort -V | tail -1)"
[ -n "$MSVC_VER" ] || {
  echo "[ERROR] $MSVC_TOOLS 下没有版本目录" >&2
  return 1 2>/dev/null || exit 1
}
MSVC="$(_winp "$MSVC_TOOLS/$MSVC_VER")"
CL="$MSVC/bin/Hostx64/x64/cl.exe"
[ -f "$CL" ] || {
  echo "[ERROR] 缺少 64 位编译器：$CL" >&2
  echo "        Visual Studio 安装时请勾选 x64 工具集。" >&2
  return 1 2>/dev/null || exit 1
}

if [ -n "$NB_CURL_SDK_ROOT" ]; then
  SDK_MSYS="$NB_CURL_SDK_ROOT"
else
  SDK_MSYS="/c/Program Files (x86)/Windows Kits/10"
  [ -d "$SDK_MSYS" ] || SDK_MSYS="/c/Program Files/Windows Kits/10"
fi
[ -d "$SDK_MSYS" ] || {
  echo "[ERROR] 找不到 Windows SDK：$SDK_MSYS" >&2
  echo "        请安装「Windows 10/11 SDK」，或用 NB_CURL_SDK_ROOT 指定根目录。" >&2
  return 1 2>/dev/null || exit 1
}
SDK="$(_winp "$SDK_MSYS")"
if [ -n "$NB_CURL_SDK_VER" ]; then
  SDKV="$NB_CURL_SDK_VER"
else
  SDKV="$(ls "$SDK_MSYS/Include" 2>/dev/null | grep -E '^10\.' | sort -V | tail -1)"
fi
[ -n "$SDKV" ] || {
  echo "[ERROR] $SDK_MSYS/Include 下找不到 SDK 版本目录" >&2
  return 1 2>/dev/null || exit 1
}

# 构建工具：优先仓库自带的 deps/tools/，其次 PATH
_find_tool() {
  local envname="$1" rel="$2" exe="$3" v hit
  eval "v=\${$envname}"
  if [ -n "$v" ] && [ -f "$v" ]; then echo "$v"; return 0; fi
  hit="$(ls -1 $REPO/$rel 2>/dev/null | head -1)"
  if [ -n "$hit" ]; then
    _winp "$hit"; return 0
  fi
  command -v "$exe" 2>/dev/null && return 0
  return 1
}
CMAKE="$(_find_tool NB_CURL_CMAKE "deps/tools/cmake-*/bin/cmake.exe" cmake)" || {
  echo "[ERROR] 找不到 cmake。" >&2
  echo "        请安装 cmake（或把便携版放到 deps/tools/），或用 NB_CURL_CMAKE 指定。" >&2
  return 1 2>/dev/null || exit 1
}
NINJA="$(_find_tool NB_CURL_NINJA "deps/tools/ninja.exe" ninja)" || {
  echo "[ERROR] 找不到 ninja。请安装 ninja，或用 NB_CURL_NINJA 指定。" >&2
  return 1 2>/dev/null || exit 1
}
NASM="$(_find_tool NB_CURL_NASM "deps/tools/nasm.exe" nasm)" || NASM=""

VCPKG="${NB_CURL_VCPKG:-$REPO/deps/windows-prebuilt/vcpkg-static}"

if [ -n "$NB_CURL_PRINT_TOOLCHAIN" ]; then
  echo "--- 工具链探测结果 ---"
  echo "MSVC  = $MSVC"
  echo "SDK   = $SDK  ($SDKV)"
  echo "cl    = $CL"
  echo "cmake = $CMAKE"
  echo "ninja = $NINJA"
  echo "nasm  = ${NASM:-（未找到，重建 BoringSSL 时才需要）}"
  echo "vcpkg = $VCPKG"
  echo "----------------------"
fi
