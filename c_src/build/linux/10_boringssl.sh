#!/bin/bash
# 10 —— 编译 BoringSSL（含 curl-impersonate 的 TLS 指纹钩子）
#
# 产物：$PREFIX/lib/libssl.a  $PREFIX/lib/libcrypto.a  $PREFIX/include/openssl/*.h
#
# 说明：
#  * 这个 BoringSSL 源码已经打好了 curl-impersonate 的补丁（ssl.h 里有
#    extension order / GREASE / ALPS 等钩子），不要替换成上游原始版本，
#    否则 curl 的 CURLOPT_TLS_EXTENSION_ORDER 等选项会编译失败。
#  * BoringSSL 库本体**不需要 Go**：err_data.cc / 汇编均已预生成，
#    只要 BUILD_TESTING=OFF 就不会触发需要 Go 的目标。
#    （若你确实碰到 "Go is required"，装上 golang-go 即可。）
#  * 必须开 PIC：静态库最终要链进共享库 libnb_curl_native.so。
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd cmake
require_cmd ninja
require_cmd perl

unpack "$SOURCES/boringssl-patched.tar.gz" "boringssl" \
       "boringssl-156c7b75ae9b8c3b3f847acf264f17594c3859fb"

# 校验补丁确实在（防止用错源码包）
grep -q "impersonate\|extension_order" "$BSSL_SRC/include/openssl/ssl.h" \
  || die "BoringSSL 源码缺少 curl-impersonate 钩子 —— 用错源码包了"

BD="$BSSL_SRC/build"

# 已编译过就直接跳过（省 10 分钟）。想强制重建：rm -rf _work/prefix 后再跑
if [ -f "$PREFIX/lib/libssl.a" ] && [ -f "$PREFIX/lib/libcrypto.a" ] \
   && [ "${NB_CURL_FORCE_REBUILD:-0}" != "1" ]; then
  c_ok "BoringSSL 已是编译好的（$PREFIX/lib/），跳过"
  ls -la "$PREFIX/lib/libssl.a" "$PREFIX/lib/libcrypto.a"
  exit 0
fi

# CMake 的 cache 存了**绝对路径**：仓库被移动/改名后，旧 cache 会失效并报
# "The current CMakeCache.txt directory ... is different than the directory ..."
# 检测到这种情况就清掉重建。
if [ -f "$BD/CMakeCache.txt" ]; then
  cached="$(sed -n 's/^CMAKE_CACHEFILE_DIR:INTERNAL=//p' "$BD/CMakeCache.txt" | head -1)"
  if [ -n "$cached" ] && [ "$cached" != "$BD" ]; then
    c_warn "CMake 缓存路径已失效（原为 $cached），清理后重新配置"
    rm -rf "$BD"
  fi
fi

c_info "配置 BoringSSL ..."
cmake -S "$BSSL_SRC" -B "$BSSL_SRC/build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DCMAKE_C_FLAGS="-O2 -fPIC" \
  -DCMAKE_CXX_FLAGS="-O2 -fPIC" \
  -DBUILD_TESTING=OFF \
  > "$WORK/boringssl-configure.log" 2>&1 \
  || { tail -30 "$WORK/boringssl-configure.log"; die "BoringSSL 配置失败"; }

c_info "编译 ssl + crypto（-j$JOBS）..."
cmake --build "$BSSL_SRC/build" --target ssl crypto -j "$JOBS" \
  > "$WORK/boringssl-build.log" 2>&1 \
  || { tail -40 "$WORK/boringssl-build.log"; die "BoringSSL 编译失败"; }

c_info "安装到 $PREFIX ..."
cmake --install "$BSSL_SRC/build" > "$WORK/boringssl-install.log" 2>&1 \
  || { tail -20 "$WORK/boringssl-install.log"; die "BoringSSL 安装失败"; }

# 兜底：某些 BoringSSL 版本的 install 规则不完整，缺什么补什么
mkdir -p "$PREFIX/lib" "$PREFIX/include"
for lib in libssl.a libcrypto.a; do
  [ -f "$PREFIX/lib/$lib" ] || {
    found="$(find "$BSSL_SRC/build" -name "$lib" | head -1)"
    [ -n "$found" ] && cp "$found" "$PREFIX/lib/" && c_warn "手动补 $lib"
  }
done
for lib in libssl.a libcrypto.a; do
  [ -f "$PREFIX/lib/$lib" ] || die "缺少 $PREFIX/lib/$lib"
done
[ -f "$PREFIX/include/openssl/ssl.h" ] || {
  cp -r "$BSSL_SRC/include/openssl" "$PREFIX/include/" && c_warn "手动补 include/openssl"
}

c_ok "BoringSSL 就绪"
ls -la "$PREFIX/lib/"
