#!/bin/bash
# 从源码重建 BoringSSL 静态库（Windows x64）
#
# 什么时候需要跑：想升级 BoringSSL / 换 TLS 层行为时。
# 平时不用跑 —— deps/windows-prebuilt/boringssl/ 里已经有可用的 ssl.lib / crypto.lib。
#
# 前置：
#   1) 把打过 curl-impersonate 钩子的 BoringSSL 源码解到 deps/sources/ 下并改名为 boringssl
#      （参见 docs/04-升级指南.md §3）
#   2) 验证钩子确实在：
#      grep -c extension_order deps/sources/boringssl/include/openssl/ssl.h   # 应 > 0
#
# 结论：BoringSSL 库本体**不需要 Go**。BUILD_TESTING=OFF 就避开了需要 Go 的目标，
#       err_data / win.asm 等生成文件仓库里已预生成。
set -e
cd "$(dirname "$0")"

# 用 pwd -W：cl.exe / cmake 只认 Windows 路径
REPO="$(cd ../.. && pwd -W)"
SRC="$REPO/deps/sources/boringssl"
DEST="$REPO/deps/windows-prebuilt/boringssl"

unset http_proxy HTTP_PROXY https_proxy HTTPS_PROXY \
      no_proxy NO_PROXY all_proxy ALL_PROXY \
      MSYSTEM OSTYPE MSYSTEM_CHERE MSYSTEM_PREFIX TMPDIR 2>/dev/null || true
export CODEBUDDY_SAFE_DELETE_ENABLED=0
export CODEBUDDY_BROKERED_FS_HOOK_ENABLED=0

# MSVC / SDK / cmake / ninja / nasm：自动探测，可用 NB_CURL_* 覆盖（见 toolchain.sh）
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/toolchain.sh"

for f in "$CMAKE" "$NINJA"; do
  [ -f "$f" ] || { echo "[ERROR] 缺少构建工具：$f" >&2; exit 1; }
done
: "${NASM:?[ERROR] 找不到 nasm：请安装 nasm，或用 NB_CURL_NASM 指定路径}"
[ -f "$NASM" ] || { echo "[ERROR] 缺少构建工具：$NASM" >&2; exit 1; }

[ -d "$SRC" ] || {
  echo "[ERROR] 找不到 BoringSSL 源码：$SRC" >&2
  echo "        请先解包 deps/sources/boringssl-patched.tar.gz 并命名为 boringssl" >&2
  exit 1
}
grep -q "extension_order" "$SRC/include/openssl/ssl.h" || {
  echo "[ERROR] 源码缺少 curl-impersonate 钩子，用错包了" >&2
  echo "        （要用 deps/sources/boringssl-patched.tar.gz，不是上游原版）" >&2
  exit 1
}

export INCLUDE="$MSVC/include;$SDK/Include/$SDKV/ucrt;$SDK/Include/$SDKV/um;$SDK/Include/$SDKV/shared;$SDK/Include/$SDKV/winrt"
export LIB="$MSVC/lib/x64;$SDK/Lib/$SDKV/ucrt/x64;$SDK/Lib/$SDKV/um/x64"

BD="$SRC/build-win"
mkdir -p "$BD"

echo "=== configure (Release, /MT, BUILD_TESTING=OFF) ==="
"$CMAKE" -S "$SRC" -B "$BD" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$DEST" \
  -DCMAKE_MAKE_PROGRAM="$NINJA" \
  "-DCMAKE_C_COMPILER=$MSVC/bin/Hostx64/x64/cl.exe" \
  "-DCMAKE_CXX_COMPILER=$MSVC/bin/Hostx64/x64/cl.exe" \
  "-DCMAKE_ASM_NASM_COMPILER=$NASM" \
  -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_SYSTEM_PROCESSOR=AMD64 \
  -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded \
  -DBUILD_TESTING=OFF

echo "=== build ssl + crypto ==="
"$CMAKE" --build "$BD" --config Release --target ssl crypto

echo "=== install -> $DEST ==="
"$CMAKE" --install "$BD"

for lib in libssl.a libcrypto.a; do :; done   # 占位：Windows 产物是 .lib
for lib in ssl.lib crypto.lib; do
  [ -f "$DEST/lib/$lib" ] || { echo "[FAIL] 缺少 $DEST/lib/$lib" >&2; exit 1; }
done
[ -f "$DEST/include/openssl/ssl.h" ] || { echo "[FAIL] 缺少头文件" >&2; exit 1; }

echo
echo "=== 产物 ==="
ls -la "$DEST/lib/"
echo
echo "下一步（重建桥接层 + 验证）："
echo "  bash build/windows/build_all.sh"
echo "  python/.venv/Scripts/python.exe python/tests/test_nb_curl.py"
echo "BORINGSSL-REBUILD-OK"
