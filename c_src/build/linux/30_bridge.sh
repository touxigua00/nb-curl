#!/bin/bash
# 30 —— 编译桥接层 libnb_curl_native.so
#
# 产物：python/nb_curl/_lib/libnb_curl_native.so
#
# 说明：
#  * 桥接层源码 nb_curl_bridge.c 是**跨平台**的（内部已有 _WIN32 分支），
#    和 Windows 版是同一份，改一处两边都生效。
#  * 用 -DCURL_STATICLIB：静态链接 libcurl 时必须定义，否则会走
#    dllimport 声明导致链接失败。
#  * --start-group/--end-group：curl 与 BoringSSL 之间存在循环引用，
#    分组可以让 ld 反复扫描直到全部符号解析。
#  * -lstdc++：BoringSSL 的 Linux 构建含 C++ 源码，静态库里带 C++ 运行时
#    符号（__gxx_personality_v0 / __cxa_throw 等），**必须**补上，
#    否则链接报 undefined reference。Windows 用 cl.exe 时是自动带的。
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd gcc

[ -f "$PREFIX/lib/libcurl-impersonate.a" ] || [ -f "$PREFIX/lib/libcurl.a" ] \
  || die "请先运行 scripts/20_curl.sh"
[ -f "$NATIVE_DIR/nb_curl_bridge.c" ] || die "缺少 native/nb_curl_bridge.c"
for f in libngtcp2.a libngtcp2_crypto_boringssl.a libnghttp3.a; do
  [ -f "$PREFIX/lib/$f" ] || die "缺少 $PREFIX/lib/$f —— 请先运行 scripts/15_quic.sh"
done

# curl-impersonate 补丁把静态库名改成了 libcurl-impersonate.a，两种名字都兼容一下
CURL_A="$PREFIX/lib/libcurl-impersonate.a"
[ -f "$CURL_A" ] || CURL_A="$PREFIX/lib/libcurl.a"

mkdir -p "$LIBDIR"

c_info "编译 libnb_curl_native.so ..."

# -Wl,--strip-debug：只关自己的调试信息是不够的。-g0 只作用于本文件的 obj，
# 而 libssl.a / libcrypto.a / libngtcp2.a 等静态库成员里带着完整的 .debug_* 段，
# 链接成 .so 后会被整段带出来（实测 37 MB 里有 32 MB 是 .debug_info 这些段，
# wheel 因此虚高到 13.9 MB）。--strip-debug 在链接期丢掉这些段，
# 保留 .symtab（函数名还在，crash 时仍可对栈），比事后 strip 更稳。
gcc -shared -fPIC -O2 -g0 -Wl,--strip-debug \
  -D_GNU_SOURCE -DCURL_STATICLIB \
  -I"$PREFIX/include" \
  -I"$NATIVE_DIR" \
  -o "$LIBDIR/libnb_curl_native.so" \
  "$NATIVE_DIR/nb_curl_bridge.c" \
  -Wl,--start-group \
    "$CURL_A" \
    "$PREFIX/lib/libssl.a" \
    "$PREFIX/lib/libcrypto.a" \
    "$PREFIX/lib/libngtcp2.a" \
    "$PREFIX/lib/libngtcp2_crypto_boringssl.a" \
    "$PREFIX/lib/libnghttp3.a" \
  -Wl,--end-group \
  -lnghttp2 -lbrotlidec -lbrotlicommon -lzstd -lz -lidn2 \
  -lstdc++ \
  -lpthread -ldl -lm \
  || die "桥接层编译失败"

c_ok "libnb_curl_native.so 已生成"
ls -la "$LIBDIR/libnb_curl_native.so"

echo
c_info "导出的符号（应能看到 nb_* / easy_* 系列）："
nm -D --defined-only "$LIBDIR/libnb_curl_native.so" 2>/dev/null \
  | grep -E " T (nb_|easy_)" | awk '{print "  " $3}' | head -12
echo "  ..."

echo
c_info "动态依赖（运行期需要这些系统库）："
ldd "$LIBDIR/libnb_curl_native.so" | sed 's/^/  /'
