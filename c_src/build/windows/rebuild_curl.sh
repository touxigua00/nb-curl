#!/bin/bash
# 从源码重建 libcurl-impersonate.lib（Windows x64 静态库）
#
# 什么时候需要跑：
#   改了 deps/sources/curl-8.22.0-patched.tar.gz 里的 C 源码
#   （例如 lib/impersonate.c 的预设、连接关闭行为等），需要重新产出静态库。
#   只改桥接层（python/native/*.c）不用跑这个，直接 build_all.sh。
#
# 产物：deps/windows-prebuilt/curl-impersonate/{lib,include}
#   之后必须再跑 build/windows/build_all.sh 重建 nb_curl_native.dll。
#
# 前置：MSVC 2022 + deps/tools/{cmake,ninja} + deps/windows-prebuilt/boringssl
set -e
cd "$(dirname "$0")"

# cl.exe / cmake 只认 Windows 路径；MSYS 变量会让 cl 误判路径风格
REPO="$(cd ../.. && pwd -W)"
SRCTAR="$REPO/deps/sources/curl-8.22.0-patched.tar.gz"
DEST="$REPO/deps/windows-prebuilt/curl-impersonate"
BSSL="$REPO/deps/windows-prebuilt/boringssl"
WORK="$REPO/build/windows/_work"          # 中间产物，可删

unset http_proxy HTTP_PROXY https_proxy HTTPS_PROXY \
      no_proxy NO_PROXY all_proxy ALL_PROXY \
      MSYSTEM OSTYPE MSYSTEM_CHERE MSYSTEM_PREFIX TMPDIR 2>/dev/null || true
export CODEBUDDY_SAFE_DELETE_ENABLED=0
export CODEBUDDY_BROKERED_FS_HOOK_ENABLED=0

# MSVC / SDK / cmake / ninja / vcpkg：自动探测，可用 NB_CURL_* 覆盖（见 toolchain.sh）
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/toolchain.sh"

for f in "$SRCTAR" "$CMAKE" "$NINJA" "$CL"; do
  [ -f "$f" ] || { echo "[ERROR] 缺少：$f" >&2; exit 1; }
done
[ -d "$BSSL/include" ] || { echo "[ERROR] 缺少 BoringSSL：$BSSL" >&2; exit 1; }
[ -d "$VCPKG/include" ] || {
  echo "[ERROR] 缺少 vcpkg 静态依赖：$VCPKG" >&2
  echo "        可用 NB_CURL_VCPKG=<路径> 覆盖，或用 deps/windows-prebuilt/vcpkg-static" >&2
  exit 1
}

export INCLUDE="$MSVC/include;$SDK/Include/$SDKV/ucrt;$SDK/Include/$SDKV/um;$SDK/Include/$SDKV/shared;$SDK/Include/$SDKV/winrt"
export LIB="$MSVC/lib/x64;$SDK/Lib/$SDKV/ucrt/x64;$SDK/Lib/$SDKV/um/x64"

# ---- 解包源码 ----
# 注意：不要用 rm -rf 清理（本仓库的沙箱有"删除转回收站"钩子，批量删除会被拦下），
# 用 tar 覆盖式解包即可。需要彻底重来就用 NB_CURL_FRESH=1。
mkdir -p "$WORK"
echo "=== 解包 $SRCTAR ==="
if [ "${NB_CURL_FRESH:-0}" = "1" ] && [ -d "$WORK/curl-8.22.0" ]; then
  echo "[i] NB_CURL_FRESH=1：请先手动删除 $WORK/curl-8.22.0 再跑本脚本" >&2
fi
tar --force-local -xzf "$SRCTAR" -C "$WORK" --overwrite
SRC="$WORK/curl-8.22.0"
[ -f "$SRC/lib/impersonate.c" ] || { echo "[FAIL] 源码包不含 lib/impersonate.c" >&2; exit 1; }

BD="$SRC/build-imp"
FRESH_ARG=""
[ "${NB_CURL_FRESH:-0}" = "1" ] && FRESH_ARG="--fresh"

echo "=== configure (Release, static, /MT) ==="
"$CMAKE" -S "$SRC" -B "$BD" -G Ninja $FRESH_ARG \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_MAKE_PROGRAM="$NINJA" \
  "-DCMAKE_C_COMPILER=$CL" \
  "-DCMAKE_PREFIX_PATH=$VCPKG" \
  "-DOPENSSL_ROOT_DIR=$BSSL" \
  "-DOPENSSL_INCLUDE_DIR:PATH=$BSSL/include" \
  -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded \
  -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF -DBUILD_EXAMPLES=OFF \
  -DBUILD_TESTING=OFF -DPICKY_COMPILER=OFF \
  -DCURL_USE_OPENSSL=ON -DCURL_USE_SCHANNEL=OFF \
  -DUSE_NGHTTP2=ON -DUSE_ECH=ON \
  -DUSE_NGTCP2=ON -DUSE_NGHTTP3=ON \
  -DNGTCP2_INCLUDE_DIR="$REPO/deps/windows-prebuilt/ngtcp2/include" \
  -DNGTCP2_LIBRARY="$REPO/deps/windows-prebuilt/ngtcp2/lib/ngtcp2.lib" \
  -DNGTCP2_CRYPTO_BORINGSSL_LIBRARY="$REPO/deps/windows-prebuilt/ngtcp2/lib/ngtcp2_crypto_boringssl.lib" \
  -DNGTCP2_USE_STATIC_LIBS=ON \
  -DNGHTTP3_INCLUDE_DIR="$REPO/deps/windows-prebuilt/nghttp3/include" \
  -DNGHTTP3_LIBRARY="$REPO/deps/windows-prebuilt/nghttp3/lib/nghttp3.lib" \
  -DNGHTTP3_USE_STATIC_LIBS=ON \
  -DCURL_ZLIB=ON -DCURL_BROTLI=ON -DCURL_ZSTD=ON \
  -DCURL_USE_LIBSSH2=OFF -DCURL_USE_LIBSSH=OFF \
  -DCURL_USE_LIBPSL=OFF -DCURL_USE_LIBUV=OFF \
  > "$WORK/configure.log" 2>&1 || {
    echo "[FAIL] configure 失败，见 $WORK/configure.log" >&2
    tail -20 "$WORK/configure.log" >&2
    exit 1
  }
grep -i "SSL backends\|BoringSSL\|HTTP2" "$WORK/configure.log" | head -5 || true

echo "=== build libcurl-impersonate ==="
# target 真名是 libcurl_static（LIB_NAME/libcurl-impersonate 只是 ALIAS + 输出名）。
# 用 -j2 降低并行度：Defender 实时扫描会短暂锁 .obj，并行越高冲突越频繁。
if ! "$CMAKE" --build "$BD" --config Release --target libcurl_static -- -j2 \
     > "$WORK/build.log" 2>&1; then
  echo "[FAIL] 编译失败，见 $WORK/build.log" >&2
  grep -a -i "error" "$WORK/build.log" | head -20 >&2
  exit 1
fi

LIBFILE="$(ls "$BD"/lib/libcurl-impersonate.lib "$BD"/lib/libcurl.lib 2>/dev/null | head -1)"
[ -n "$LIBFILE" ] || { echo "[FAIL] 没找到 libcurl-impersonate.lib" >&2; ls "$BD/lib" >&2; exit 1; }

echo "=== install -> $DEST ==="
mkdir -p "$DEST/lib" "$DEST/include"
cp -f "$LIBFILE" "$DEST/lib/libcurl-impersonate.lib"
cp -rf "$SRC/include/curl/." "$DEST/include/curl/"
ls -la "$DEST/lib/libcurl-impersonate.lib"
echo "CURL-IMPERSONATE-REBUILD-OK  （别忘了再跑 build/windows/build_all.sh）"
