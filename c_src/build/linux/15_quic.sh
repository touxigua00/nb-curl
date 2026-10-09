#!/bin/bash
# 15 —— 编译 ngtcp2（BoringSSL crypto 后端）+ nghttp3 —— HTTP/3 的传输层与帧层
#
# 产物（安装到 $PREFIX）：
#   lib/libngtcp2.a  lib/libngtcp2_crypto_boringssl.a  lib/libnghttp3.a
#   include/ngtcp2/  include/nghttp3/
#
# 之后由 20_curl.sh 带 USE_NGTCP2 / USE_NGHTTP3 重建 curl 静态库，HTTP/3 才算编进去。
#
# 两个必须处理的坑：
#  1) ngtcp2 的 crypto/boringssl 静态库里有 C++ 目标文件（BoringSSL 的
#     boringssl.cc / shared.cc），链接它的程序都要补 -lstdc++，否则 cmake 的
#     探测程序链接失败，会被误判成"符号不存在"。
#  2) BoringSSL 不是 OpenSSL 的 cmake package，必须显式给
#     BORINGSSL_INCLUDE_DIR / BORINGSSL_LIBRARIES。
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd cmake
require_cmd ninja

[ -f "$PREFIX/lib/libssl.a" ] || die "请先运行 $SCRIPTS/10_boringssl.sh"

NGTCP2_SRC="$SOURCES/ngtcp2-src"
NGHTTP3_SRC="$SOURCES/nghttp3-src"
[ -d "$NGTCP2_SRC" ] || die "缺少 ngtcp2 源码：$NGTCP2_SRC"
[ -d "$NGHTTP3_SRC" ] || die "缺少 nghttp3 源码：$NGHTTP3_SRC"

if [ -f "$PREFIX/lib/libngtcp2.a" ] && [ -f "$PREFIX/lib/libnghttp3.a" ] \
   && [ "${NB_CURL_FORCE_REBUILD:-0}" != "1" ]; then
  c_ok "ngtcp2 / nghttp3 已是编译好的，跳过"
  ls -la "$PREFIX/lib/" | grep -E "ngtcp2|nghttp3"
  exit 0
fi

# ---------------------------------------------------------------- ngtcp2 ---- #
BD2="$WORK/ngtcp2"
c_info "配置 ngtcp2（BoringSSL crypto 后端，静态库）..."
cmake -S "$NGTCP2_SRC" -B "$BD2" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DCMAKE_C_FLAGS="-O2 -fPIC" \
  -DCMAKE_CXX_FLAGS="-O2 -fPIC" \
  -DCMAKE_REQUIRED_LIBRARIES="pthread;dl;stdc++;m" \
  -DCMAKE_EXE_LINKER_FLAGS="-lstdc++" \
  -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF \
  -DENABLE_LIB_ONLY=ON \
  -DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF \
  -DENABLE_BORINGSSL=ON \
  -DENABLE_OPENSSL=OFF -DENABLE_GNUTLS=OFF -DENABLE_WOLFSSL=OFF \
  -DENABLE_LIBRESSL=OFF -DENABLE_QUICTLS=OFF \
  -DBORINGSSL_INCLUDE_DIR="$PREFIX/include" \
  -DBORINGSSL_LIBRARIES="$PREFIX/lib/libssl.a;$PREFIX/lib/libcrypto.a" \
  > "$WORK/ngtcp2-configure.log" 2>&1 \
  || { tail -30 "$WORK/ngtcp2-configure.log"; die "ngtcp2 配置失败"; }

c_info "编译 ngtcp2（-j$JOBS）..."
cmake --build "$BD2" -j "$JOBS" > "$WORK/ngtcp2-build.log" 2>&1 \
  || { grep -a -i "error" "$WORK/ngtcp2-build.log" | head -20; die "ngtcp2 编译失败"; }

cmake --install "$BD2" > "$WORK/ngtcp2-install.log" 2>&1 \
  || { tail -20 "$WORK/ngtcp2-install.log"; die "ngtcp2 安装失败"; }

# -------------------------------------------------------------- nghttp3 ---- #
BD3="$WORK/nghttp3"
c_info "配置 nghttp3（静态库，纯帧层不依赖 TLS）..."
cmake -S "$NGHTTP3_SRC" -B "$BD3" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DCMAKE_C_FLAGS="-O2 -fPIC" \
  -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF \
  -DENABLE_LIB_ONLY=ON \
  -DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF \
  > "$WORK/nghttp3-configure.log" 2>&1 \
  || { tail -30 "$WORK/nghttp3-configure.log"; die "nghttp3 配置失败"; }

c_info "编译 nghttp3（-j$JOBS）..."
cmake --build "$BD3" -j "$JOBS" > "$WORK/nghttp3-build.log" 2>&1 \
  || { grep -a -i "error" "$WORK/nghttp3-build.log" | head -20; die "nghttp3 编译失败"; }

cmake --install "$BD3" > "$WORK/nghttp3-install.log" 2>&1 \
  || { tail -20 "$WORK/nghttp3-install.log"; die "nghttp3 安装失败"; }

for f in libngtcp2.a libngtcp2_crypto_boringssl.a libnghttp3.a; do
  [ -f "$PREFIX/lib/$f" ] || die "缺少产物 $PREFIX/lib/$f"
done

c_ok "ngtcp2 / nghttp3 就绪"
ls -la "$PREFIX/lib/" | grep -E "ngtcp2|nghttp3"
