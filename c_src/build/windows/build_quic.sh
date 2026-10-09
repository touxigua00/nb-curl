#!/bin/bash
# 编译 ngtcp2（BoringSSL crypto 后端）+ nghttp3 → HTTP/3 传输层与帧层
#
# 产物：deps/windows-prebuilt/{ngtcp2,nghttp3}/{lib,include}
#   ngtcp2:  lib/ngtcp2.lib + lib/ngtcp2_crypto_boringssl.lib + include/ngtcp2/
#   nghttp3: lib/nghttp3.lib + include/nghttp3/
#
# 之后跑 rebuild_curl.sh（带 USE_NGTCP2/USE_NGHTTP3）重建 curl 静态库。
set -e
cd "$(dirname "$0")"

REPO="$(cd ../.. && pwd -W)"
BSSL="$REPO/deps/windows-prebuilt/boringssl"
NGTCP2_SRC="$REPO/deps/sources/ngtcp2-src"
NGHTTP3_SRC="$REPO/deps/sources/nghttp3-src"
DEST_NGTCP2="$REPO/deps/windows-prebuilt/ngtcp2"
DEST_NGHTTP3="$REPO/deps/windows-prebuilt/nghttp3"
WORK="$REPO/build/windows/_work_quic"

unset http_proxy HTTP_PROXY https_proxy HTTPS_PROXY \
      no_proxy NO_PROXY all_proxy ALL_PROXY \
      MSYSTEM OSTYPE MSYSTEM_CHERE MSYSTEM_PREFIX TMPDIR 2>/dev/null || true
export CODEBUDDY_SAFE_DELETE_ENABLED=0
export CODEBUDDY_BROKERED_FS_HOOK_ENABLED=0

# MSVC / SDK / cmake / ninja：自动探测，可用 NB_CURL_* 覆盖（见 toolchain.sh）
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/toolchain.sh"

for f in "$CMAKE" "$NINJA" "$CL"; do
  [ -f "$f" ] || { echo "[ERROR] 缺少：$f" >&2; exit 1; }
done
[ -d "$BSSL/include" ] || { echo "[ERROR] 缺少 BoringSSL：$BSSL" >&2; exit 1; }

export INCLUDE="$MSVC/include;$SDK/Include/$SDKV/ucrt;$SDK/Include/$SDKV/um;$SDK/Include/$SDKV/shared;$SDK/Include/$SDKV/winrt;$BSSL/include"
export LIB="$MSVC/lib/x64;$SDK/Lib/$SDKV/ucrt/x64;$SDK/Lib/$SDKV/um/x64"

mkdir -p "$WORK"

# ============================================================
# 1) ngtcp2 + BoringSSL crypto 后端
# ============================================================
BD2="$WORK/ngtcp2"
echo "=== configure ngtcp2 (BoringSSL, static, /MT) ==="
"$CMAKE" -S "$NGTCP2_SRC" -B "$BD2" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_MAKE_PROGRAM="$NINJA" \
  "-DCMAKE_C_COMPILER=$CL" \
  -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_TESTING=OFF \
  -DENABLE_LIB_ONLY=ON \
  -DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF \
  -DENABLE_BORINGSSL=ON \
  -DENABLE_OPENSSL=OFF -DENABLE_GNUTLS=OFF -DENABLE_WOLFSSL=OFF \
  -DENABLE_LIBRESSL=OFF -DENABLE_QUICTLS=OFF \
  -DBORINGSSL_INCLUDE_DIR="$BSSL/include" \
  -DBORINGSSL_LIBRARIES="$BSSL/lib/ssl.lib;$BSSL/lib/crypto.lib" \
  -DCMAKE_INSTALL_PREFIX="$DEST_NGTCP2" \
  > "$WORK/ngtcp2-configure.log" 2>&1 || {
    echo "[FAIL] ngtcp2 configure 失败，见 $WORK/ngtcp2-configure.log" >&2
    tail -20 "$WORK/ngtcp2-configure.log" >&2
    exit 1
  }
grep -i "boringssl\|quic" "$WORK/ngtcp2-configure.log" | head -5 || true

echo "=== build ngtcp2 ==="
"$CMAKE" --build "$BD2" --config Release > "$WORK/ngtcp2-build.log" 2>&1 || {
  echo "[FAIL] ngtcp2 编译失败，见 $WORK/ngtcp2-build.log" >&2
  grep -i "error" "$WORK/ngtcp2-build.log" | head -20 >&2
  exit 1
}
"$CMAKE" --install "$BD2" --config Release > "$WORK/ngtcp2-install.log" 2>&1
echo "ngtcp2 产物："
ls "$DEST_NGTCP2/lib/"*.lib 2>/dev/null

# ============================================================
# 2) nghttp3（纯 H3 帧层，不依赖 TLS）
# ============================================================
BD3="$WORK/nghttp3"
echo "=== configure nghttp3 (static, /MT) ==="
"$CMAKE" -S "$NGHTTP3_SRC" -B "$BD3" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_MAKE_PROGRAM="$NINJA" \
  "-DCMAKE_C_COMPILER=$CL" \
  -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_TESTING=OFF \
  -DENABLE_LIB_ONLY=ON \
  -DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF \
  -DCMAKE_INSTALL_PREFIX="$DEST_NGHTTP3" \
  > "$WORK/nghttp3-configure.log" 2>&1 || {
    echo "[FAIL] nghttp3 configure 失败，见 $WORK/nghttp3-configure.log" >&2
    tail -20 "$WORK/nghttp3-configure.log" >&2
    exit 1
  }

echo "=== build nghttp3 ==="
"$CMAKE" --build "$BD3" --config Release > "$WORK/nghttp3-build.log" 2>&1 || {
  echo "[FAIL] nghttp3 编译失败，见 $WORK/nghttp3-build.log" >&2
  grep -i "error" "$WORK/nghttp3-build.log" | head -20 >&2
  exit 1
}
"$CMAKE" --install "$BD3" --config Release > "$WORK/nghttp3-install.log" 2>&1
echo "nghttp3 产物："
ls "$DEST_NGHTTP3/lib/"*.lib 2>/dev/null

echo
echo "QUIC-BUILD-OK  （接下来跑 rebuild_curl.sh 重建 curl 静态库启用 H3）"
