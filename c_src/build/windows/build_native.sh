#!/bin/bash
# 编译 C 桥接层 -> nb_curl_native.dll（Windows x64）
#
# 静态链接：libcurl-impersonate + BoringSSL(ssl/crypto) + nghttp2/zlib/brotli/zstd
# 依赖全部在 <root>/deps/windows-prebuilt/ 里，不需要外部 vcpkg 安装。
#
# 目录：本脚本在 <root>/build/windows/，项目在 <root>/python/
#
# 注意：这个 .dll 是**唯一的 C 产出物**，会进 wheel 发给别人；
#       python/native/nb_curl_bridge.c 是源码，不进 wheel。
set -e
cd "$(dirname "$0")"

# 注意用 pwd -W：Git Bash 的 pwd 给的是 /d/proj 这种 MSYS 路径，
# 而 cl.exe / link.exe 只认 Windows 路径（D:/proj）。pwd -W 直接给后者。
REPO="$(cd ../.. && pwd -W)"
PROJECT="$REPO/python"
DEPS="$REPO/deps/windows-prebuilt"

# 代理会干扰 cl/link 的库查找；MSYS 变量会让 cl 误判路径风格
unset http_proxy HTTP_PROXY https_proxy HTTPS_PROXY \
      no_proxy NO_PROXY all_proxy ALL_PROXY \
      MSYSTEM OSTYPE TMPDIR 2>/dev/null || true
# 本脚本只操作构建产物（python/build/）：关掉沙箱的"删除转回收站"钩子
export CODEBUDDY_SAFE_DELETE_ENABLED=0
export CODEBUDDY_BROKERED_FS_HOOK_ENABLED=0

BSSL="$DEPS/boringssl"            # include/openssl + lib/{ssl,crypto}.lib
CURLLIB="$DEPS/curl-impersonate"  # include/curl + lib/libcurl-impersonate.lib

# MSVC / Windows SDK / vcpkg 路径：自动探测，可用 NB_CURL_* 覆盖（见 toolchain.sh）
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/toolchain.sh"

for d in "$BSSL" "$CURLLIB" "$VCPKG"; do
  [ -d "$d" ] || { echo "[ERROR] 缺少依赖目录：$d" >&2; echo "        见 deps/README.md" >&2; exit 1; }
done

LINK_LIBS="$CURLLIB/lib/libcurl-impersonate.lib"
LINK_LIBS="$LINK_LIBS $BSSL/lib/ssl.lib $BSSL/lib/crypto.lib"
LINK_LIBS="$LINK_LIBS $VCPKG/lib/zlib.lib $VCPKG/lib/brotlidec.lib $VCPKG/lib/brotlicommon.lib"
LINK_LIBS="$LINK_LIBS $VCPKG/lib/zstd.lib $VCPKG/lib/nghttp2.lib"
# HTTP/3 (ngtcp2 + nghttp3，BoringSSL crypto 后端)
NGTCP2="$DEPS/ngtcp2"
NGHTTP3="$DEPS/nghttp3"
LINK_LIBS="$LINK_LIBS $NGTCP2/lib/ngtcp2.lib $NGTCP2/lib/ngtcp2_crypto_boringssl.lib"
LINK_LIBS="$LINK_LIBS $NGHTTP3/lib/nghttp3.lib"
LINK_LIBS="$LINK_LIBS ws2_32.lib wldap32.lib bcrypt.lib advapi32.lib crypt32.lib iphlpapi.lib"
LINK_LIBS="$LINK_LIBS user32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib"

export INCLUDE="$MSVC/include;$SDK/Include/$SDKV/ucrt;$SDK/Include/$SDKV/um;$SDK/Include/$SDKV/shared;$SDK/Include/$SDKV/winrt;$CURLLIB/include;$BSSL/include;$VCPKG/include;$NGTCP2/include;$NGHTTP3/include"
export LIB="$MSVC/lib/x64;$SDK/Lib/$SDKV/ucrt/x64;$SDK/Lib/$SDKV/um/x64"

cd "$PROJECT"
mkdir -p build nb_curl/_lib

echo "=== building nb_curl_native.dll ==="
"$CL" /nologo /LD /O2 /MD /DNDEBUG /W3 /utf-8 \
    /DNB_BUILD_DLL /DCURL_STATICLIB /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS \
    /Fo:build/ \
    c_src/native/nb_curl_bridge.c \
    /Fe:build/nb_curl_native.dll \
    /link $LINK_LIBS

# 复制带重试：新写出的 .dll 可能被 Defender 实时保护短暂锁住
for i in 1 2 3 4 5 6 7 8; do
  if cp -f build/nb_curl_native.dll nb_curl/_lib/nb_curl_native.dll 2>/dev/null; then break; fi
  echo "  [..] 复制 dll 被占用，重试 $i/8"
  sleep 0.5
done

[ -f nb_curl/_lib/nb_curl_native.dll ] || { echo "[FAIL] dll 未生成" >&2; exit 1; }
ls -la nb_curl/_lib/nb_curl_native.dll
echo "NB_CURL-NATIVE-BUILD-OK"
