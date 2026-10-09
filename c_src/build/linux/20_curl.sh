#!/bin/bash
# 20 —— 编译 libcurl-impersonate（静态库）
#
# 产物：$PREFIX/lib/libcurl.a  $PREFIX/include/curl/*.h
#
# 关键点：
#  * curl-impersonate 的功能来自源码里的补丁：
#      lib/impersonate.c / lib/impersonate.h（内置 39 套浏览器指纹）
#      include/curl/curl.h 里的 CURLOPT_IMPERSONATE 等新选项
#    所以**必须**用 deps/sources/curl-8.22.0-patched.tar.gz，不要用官方原版。
#  * BoringSSL 通过 OPENSSL_ROOT_DIR 被当作 OpenSSL 找到（BoringSSL 提供
#    了兼容的 CMake config 与 openssl/*.h）。
#  * BUILD_SHARED_LIBS=OFF 生成静态库，方便整块链进 libnb_curl_native.so。
#  * CMAKE_POSITION_INDEPENDENT_CODE=ON 同样是为了能链进共享库。
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd cmake
require_cmd ninja

[ -f "$PREFIX/lib/libssl.a" ] || die "请先运行 $SCRIPTS/10_boringssl.sh"
for f in libngtcp2.a libngtcp2_crypto_boringssl.a libnghttp3.a; do
  [ -f "$PREFIX/lib/$f" ] || die "缺少 $PREFIX/lib/$f —— 请先运行 $SCRIPTS/15_quic.sh"
done

unpack "$SOURCES/curl-8.22.0-patched.tar.gz" "curl-8.22.0" "curl-8.22.0"

# 已编译过就跳过（$PREFIX/lib/libcurl-impersonate.a 还在就直接用）
if { [ -f "$PREFIX/lib/libcurl-impersonate.a" ] || [ -f "$PREFIX/lib/libcurl.a" ]; } \
   && [ "${NB_CURL_FORCE_REBUILD:-0}" != "1" ]; then
  c_ok "libcurl-impersonate 已是编译好的，跳过"
  ls -la "$PREFIX/lib/" | grep -E "libcurl"
  exit 0
fi

# CMake cache 含绝对路径，仓库移动过就失效 → 清掉重建
if [ -f "$CURL_BUILD/CMakeCache.txt" ]; then
  cached="$(sed -n 's/^CMAKE_CACHEFILE_DIR:INTERNAL=//p' "$CURL_BUILD/CMakeCache.txt" | head -1)"
  if [ -n "$cached" ] && [ "$cached" != "$CURL_BUILD" ]; then
    c_warn "CMake 缓存路径已失效（原为 $cached），清理后重新配置"
    rm -rf "$CURL_BUILD"
  fi
fi

[ -f "$CURL_SRC/lib/impersonate.c" ] \
  || die "curl 源码缺少 lib/impersonate.c —— 用错源码包了"
grep -q "CURLOPT_IMPERSONATE\|curl_easy_impersonate" "$CURL_SRC/include/curl/curl.h" \
  || c_warn "curl.h 里没直接看到 CURLOPT_IMPERSONATE（继续，可能是宏间接定义）"

# --------------------------------------------------------------------------- #
# 配置说明
#
# TLS 后端用 BoringSSL：通过 OPENSSL_ROOT_DIR / OPENSSL_*_LIBRARY 直接指到
# 我们 10_boringssl.sh 装出来的静态库，走 curl 的 OpenSSL 适配层。
#
# ⚠️ 两个必须处理的坑（Windows 上不会出现，因为 cl.exe 自动带 C++ 运行时）：
#
#   1) BoringSSL 的 Linux 静态库里含 C++ 目标文件（如 encrypted_client_hello.cc、
#      extensions.cc），任何链接它的程序都要补 -lstdc++。
#   2) curl 用 check_function_exists 探测 SSL_set0_wbio / SSL_set1_ech_config_list
#      时，生成的探测程序没链 libstdc++，链接失败被误判成"符号不存在"，
#      于是报 "ECH support missing in AWS-LC/BoringSSL/OpenSSL/Rustls/wolfSSL"。
#      这两个符号其实都在 libssl.a 里（nm 可见）。
#
#      而且 Ubuntu 默认 -Wl,--as-needed，把 -lstdc++ 放在 OpenSSL 库之前会被丢掉，
#      所以光加 CMAKE_REQUIRED_LIBRARIES 也不一定管用。
#
#      最稳的做法：直接把检测结果写进 CMake 缓存。CMake 的 check_function_exists
#      见到同名变量已定义就会跳过检测，于是这里 -DHAVE_XXX=1。
#
#      USE_ECH 必须为 ON：lib/impersonate.c 里大量浏览器预设带 .ech = "true"，
#      关掉会破坏指纹保真度。
#
#   3) 同一个坑还会咬 HTTP/3：curl 编 H3 前要确认 TLS 后端有 QUIC API，
#      探测的是 SSL_set_quic_use_legacy_codepoint —— 这个符号 BoringSSL 里**有**
#      （nm -g libssl.a 能看到 T），但探测程序同样因为没链 libstdc++ 而链接失败，
#      于是报 "QUICTLS API support is missing from OpenSSL/fork/wolfSSL"。
#      同样把结果写进缓存：-DHAVE_SSL_SET_QUIC_USE_LEGACY_CODEPOINT=1。
#      另外补一个 CMAKE_REQUIRED_LINK_OPTIONS=-lstdc++，把这一类探测从根上修好
#      （它排在库之后，不会被 --as-needed 丢掉）。
# --------------------------------------------------------------------------- #

c_info "配置 libcurl-impersonate ..."
cmake -S "$CURL_SRC" -B "$CURL_BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DCMAKE_C_FLAGS="-O2 -fPIC" \
  -DCURL_USE_OPENSSL=ON \
  -DOPENSSL_ROOT_DIR="$PREFIX" \
  -DOPENSSL_INCLUDE_DIR="$PREFIX/include" \
  -DOPENSSL_SSL_LIBRARY="$PREFIX/lib/libssl.a" \
  -DOPENSSL_CRYPTO_LIBRARY="$PREFIX/lib/libcrypto.a" \
  -DUSE_ECH=ON \
  -DHAVE_SSL_SET1_ECH_CONFIG_LIST=1 \
  -DHAVE_SSL_SET0_WBIO=1 \
  -DHAVE_SSL_SET_QUIC_USE_LEGACY_CODEPOINT=1 \
  -DCMAKE_EXE_LINKER_FLAGS="-lpthread -ldl -lstdc++ -lm" \
  -DCMAKE_REQUIRED_LIBRARIES="pthread;dl;stdc++;m" \
  -DCMAKE_REQUIRED_LINK_OPTIONS="-lstdc++" \
  -DUSE_NGHTTP2=ON \
  -DUSE_NGTCP2=ON -DUSE_NGHTTP3=ON \
  -DNGTCP2_INCLUDE_DIR="$PREFIX/include" \
  -DNGTCP2_LIBRARY="$PREFIX/lib/libngtcp2.a" \
  -DNGTCP2_CRYPTO_BORINGSSL_LIBRARY="$PREFIX/lib/libngtcp2_crypto_boringssl.a" \
  -DNGTCP2_USE_STATIC_LIBS=ON \
  -DNGHTTP3_INCLUDE_DIR="$PREFIX/include" \
  -DNGHTTP3_LIBRARY="$PREFIX/lib/libnghttp3.a" \
  -DNGHTTP3_USE_STATIC_LIBS=ON \
  -DCURL_ZLIB=AUTO -DCURL_BROTLI=ON -DCURL_ZSTD=ON \
  -DCURL_USE_LIBPSL=OFF -DCURL_USE_LIBSSH2=OFF -DCURL_USE_GSSAPI=OFF \
  -DCURL_USE_LIBIDN2=ON -DUSE_LIBIDN2=ON \
  -DCURL_USE_LIBUV=OFF -DENABLE_ARES=OFF \
  -DHTTP_ONLY=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_CURL_EXE=OFF -DBUILD_EXAMPLES=OFF \
  -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF -DENABLE_CURL_MANUAL=OFF \
  -DBUILD_TESTING=OFF -DPICKY_COMPILER=OFF \
  -DCURL_CA_PATH=/etc/ssl/certs \
  -DCURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
  > "$WORK/curl-configure.log" 2>&1 \
  || { tail -40 "$WORK/curl-configure.log"; die "curl 配置失败"; }

c_info "编译 libcurl（-j$JOBS）..."
cmake --build "$CURL_BUILD" -j "$JOBS" > "$WORK/curl-build.log" 2>&1 \
  || { tail -40 "$WORK/curl-build.log"; die "curl 编译失败"; }

c_info "安装到 $PREFIX ..."
cmake --install "$CURL_BUILD" > "$WORK/curl-install.log" 2>&1 \
  || { tail -20 "$WORK/curl-install.log"; die "curl 安装失败"; }

[ -f "$PREFIX/lib/libcurl.a" ] || [ -f "$PREFIX/lib/libcurl-impersonate.a" ] \
  || die "缺少静态库（libcurl.a / libcurl-impersonate.a 都没找到）"

c_ok "libcurl-impersonate 就绪"
ls -la "$PREFIX/lib/" | grep -E "libcurl|libssl|libcrypto"
echo
c_info "确认指纹符号存在："
# 注意：curl-impersonate 补丁把库名改成了 libcurl-impersonate.a
CURL_A="$PREFIX/lib/libcurl-impersonate.a"
[ -f "$CURL_A" ] || CURL_A="$PREFIX/lib/libcurl.a"
nm -g --defined-only "$CURL_A" 2>/dev/null \
  | grep -c "curl_easy_impersonate" | sed 's/^/  curl_easy_impersonate 出现次数: /'
nm -g --defined-only "$CURL_A" 2>/dev/null \
  | grep -c "impersonations" | sed 's/^/  内置指纹表 impersonations 出现次数: /'

c_info "确认 HTTP/3（ngtcp2 + nghttp3）已编进去："
if grep -q "USE_NGTCP2" "$CURL_BUILD/lib/curl_config.h" 2>/dev/null; then
  grep -E "USE_NGTCP2|USE_NGHTTP3" "$CURL_BUILD/lib/curl_config.h"
  c_ok "HTTP/3 已启用"
else
  c_warn "curl_config.h 里没看到 USE_NGTCP2 —— H3 可能没编进去"
fi
