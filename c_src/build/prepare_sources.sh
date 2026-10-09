#!/bin/bash
# prepare_sources.sh —— 把「上游源码 + deps/patches/ 里的补丁」变成构建脚本需要的源码
#
# 为什么需要这个脚本：
#   build/windows/rebuild_curl.sh 和 build/linux/scripts/*.sh 都是**直接解已打好补丁的
#   源码包**（deps/sources/*-patched.tar.gz），它们自己不做任何 patch。所以从零复刻时，
#   必须先跑本脚本把 patched 产物生成出来。
#
# 用法：
#   bash deps/prepare_sources.sh            # 下载 + 打补丁 + 落位（已存在的会跳过）
#   bash deps/prepare_sources.sh --check    # 只打印各依赖的版本与来源，不下载
#   bash deps/prepare_sources.sh --force    # 忽略已有产物，全部重做
#
# 产物（供后续构建直接消费）：
#   deps/sources/curl-8.22.0-patched.tar.gz   顶层目录 curl-8.22.0/
#   deps/sources/boringssl-patched.tar.gz     顶层目录 boringssl-<commit>/
#   deps/sources/nghttp3-src/                 目录（含 submodule）
#   deps/sources/ngtcp2-src/                  目录（含 submodule）
#
# 环境变量：
#   NB_CURL_SOURCES_CACHE   下载缓存目录（默认 deps/.cache）
#   NB_CURL_JOBS            并行 clone 用不到，保留给子脚本

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SRC="$ROOT/deps/sources"
PATCHES="$ROOT/deps/patches"
CACHE="${NB_CURL_SOURCES_CACHE:-$ROOT/deps/.cache}"
WORK="$CACHE/_work"

if command -v cygpath >/dev/null 2>&1; then ROOT_W="$(cygpath -m "$ROOT")"; else ROOT_W="$ROOT"; fi
TAROPT=()
case "$ROOT_W" in [A-Za-z]:*) TAROPT=(--force-local) ;; esac

# --------------------------------------------------------------------------- #
# 版本锚点：升级依赖时改这里
# --------------------------------------------------------------------------- #
CURL_VER="8.22.0"
BORINGSSL_COMMIT="156c7b75ae9b8c3b3f847acf264f17594c3859fb"
NGHTTP3_TAG="v1.18.0"
NGTCP2_COMMIT="3c23148ef32596cb75720b94615d9650cdec5391"

# curl 取 GitHub 官方仓库的 tag 归档（顶层目录 curl-curl-8_22_0/）。
# 这是本仓库补丁**实测打过**的底；curl.se 的发行包内容更少（不含 scripts/），
# 理论上也能打，但未验证 —— 想用就把 NB_CURL_SOURCES_CACHE 里换成发行包。
CURL_URL="https://github.com/curl/curl/archive/refs/tags/curl-${CURL_VER//./_}.tar.gz"
BSSL_URL="https://github.com/google/boringssl/archive/${BORINGSSL_COMMIT}.tar.gz"
NGHTTP3_REPO="https://github.com/ngtcp2/nghttp3"
NGTCP2_REPO="https://github.com/ngtcp2/ngtcp2"

CURL_OUT="$SRC/curl-${CURL_VER}-patched.tar.gz"
BSSL_OUT="$SRC/boringssl-patched.tar.gz"

MODE="run"
ONLY="all"
for arg in "$@"; do
  case "$arg" in
    --check)  MODE="check" ;;
    --force)  MODE="force" ;;
    --only=*) ONLY="${arg#--only=}" ;;
    "")       ;;
    *) echo "未知参数：$arg（可用 --check / --force / --only=curl|boringssl|quic|all）" >&2; exit 2 ;;
  esac
done
case "$ONLY" in curl|boringssl|quic|all) ;; *)
  echo "--only 只接受 curl / boringssl / quic / all（收到：$ONLY）" >&2; exit 2 ;;
esac

say()  { printf '%s\n' "$*"; }
step() { printf '\n=== %s ===\n' "$*"; }

if [ "$MODE" = "check" ]; then
  say "准备生成以下源码（版本已固定，与仓库当前构建产物一致）："
  say "  curl       ${CURL_VER}                <- ${CURL_URL}"
  say "             + deps/patches/curl.patch        (curl-impersonate)"
  say "             + deps/patches/nb_curl.patch      (本项目自研改动)"
  say "  BoringSSL  ${BORINGSSL_COMMIT:0:12}  <- ${BSSL_URL}"
  say "             + deps/patches/boringssl.patch    (curl-impersonate 钩子)"
  say "  nghttp3    ${NGHTTP3_TAG}              <- ${NGHTTP3_REPO} (含 submodule)"
  say "             + deps/patches/nghttp3.patch      (HTTP/3 SETTINGS 控制)"
  say "  ngtcp2     ${NGTCP2_COMMIT:0:12}  <- ${NGTCP2_REPO} (含 submodule)"
  say "             （无需补丁：壳侧已避开 curl-impersonate 用到的非公开符号）"
  say ""
  say "参考用（当前构建不消费）：brotli.patch、OpenBSD.patch、ngtcp2.patch"
  exit 0
fi

mkdir -p "$SRC" "$CACHE" "$WORK"

# --------------------------------------------------------------------------- #
# 工具
# --------------------------------------------------------------------------- #
_fetch() {  # _fetch <url> <dest-file>
  local url="$1" dest="$2"
  if [ -f "$dest" ]; then say "[=] 已缓存 $(basename "$dest")"; return 0; fi
  mkdir -p "$(dirname "$dest")"
  say "[>] 下载 $url"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 --connect-timeout 30 -o "$dest.part" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$dest.part" "$url"
  else
    say "[!] 既没有 curl 也没有 wget，请手动下载到 $dest" >&2; return 1
  fi
  mv -f "$dest.part" "$dest"
}

_apply() {  # _apply <patch-file> <src-dir> <label>
  local pf="$1" dir="$2" label="$3"
  if [ ! -f "$pf" ]; then say "[!] 缺少补丁 $pf" >&2; return 1; fi
  if (cd "$dir" && patch -p1 --dry-run -s < "$pf") >/dev/null 2>&1; then
    (cd "$dir" && patch -p1 -s < "$pf")
    say "[+] $label 已应用"
  elif (cd "$dir" && patch -p1 -R --dry-run -s < "$pf") >/dev/null 2>&1; then
    say "[=] $label 已经打过了，跳过"
  else
    say "[!] $label 打不上 —— 上游版本与补丁不匹配？" >&2
    say "    请确认版本锚点（本脚本头部）与 deps/patches/ 是同一代的。" >&2
    return 1
  fi
}

_reset_dir() {  # _reset_dir <dir>
  [ -e "$1" ] || return 0
  if [ "$MODE" = "force" ]; then
    if command -v rm >/dev/null 2>&1; then rm -rf "$1"; else say "[!] 请手动删除 $1" >&2; exit 1; fi
  fi
}

# --------------------------------------------------------------------------- #
# 1) curl：上游 tarball + curl.patch + nb_curl.patch
# --------------------------------------------------------------------------- #
case "$ONLY" in curl|all)
if [ "$MODE" = "force" ] || [ ! -f "$CURL_OUT" ]; then
  step "curl ${CURL_VER}"
  _fetch "$CURL_URL" "$CACHE/curl-${CURL_VER}.tar.gz"
  # 解到临时目录再归一化目录名：curl.se 的包顶层是 curl-8.22.0/，
  # GitHub 归档则是 curl-curl-8_22_0/ —— 两者都要能接。
  rm -rf "$WORK/_unpack"; mkdir -p "$WORK/_unpack"
  tar "${TAROPT[@]}" -xzf "$CACHE/curl-${CURL_VER}.tar.gz" -C "$WORK/_unpack"
  top="$(ls -1 "$WORK/_unpack" | head -1)"
  [ -n "$top" ] || { say "[!] 解包后为空" >&2; exit 1; }
  rm -rf "$WORK/curl-${CURL_VER}"
  mv "$WORK/_unpack/$top" "$WORK/curl-${CURL_VER}"
  rm -rf "$WORK/_unpack"

  _apply "$PATCHES/curl.patch"     "$WORK/curl-${CURL_VER}" "curl.patch（curl-impersonate）"
  _apply "$PATCHES/nb_curl.patch"  "$WORK/curl-${CURL_VER}" "nb_curl.patch（本项目自研）"

  # 自检：两个关键标记必须在
  [ -f "$WORK/curl-${CURL_VER}/lib/impersonate.c" ] || { say "[!] 缺 lib/impersonate.c" >&2; exit 1; }
  n=$(grep -rl "Curl_cffi rework" "$WORK/curl-${CURL_VER}/lib/" | wc -l)
  [ "$n" -ge 9 ] || { say "[!] 自研改动标记只找到 $n 个文件（预期 >= 9）" >&2; exit 1; }
  say "[✓] lib/impersonate.c 存在，自研标记命中 $n 个文件"

  tar "${TAROPT[@]}" -czf "$CURL_OUT" -C "$WORK" "curl-${CURL_VER}"
  say "[✓] $CURL_OUT"
else
  say "[=] 已存在 $(basename "$CURL_OUT")，跳过（--force 可重做）"
fi
;; esac

# --------------------------------------------------------------------------- #
# 2) BoringSSL：上游 commit + boringssl.patch
# --------------------------------------------------------------------------- #
case "$ONLY" in boringssl|all)
if [ "$MODE" = "force" ] || [ ! -f "$BSSL_OUT" ]; then
  step "BoringSSL ${BORINGSSL_COMMIT:0:12}"
  _fetch "$BSSL_URL" "$CACHE/boringssl-${BORINGSSL_COMMIT}.tar.gz"
  rm -rf "$WORK/_unpack"; mkdir -p "$WORK/_unpack"
  tar "${TAROPT[@]}" -xzf "$CACHE/boringssl-${BORINGSSL_COMMIT}.tar.gz" -C "$WORK/_unpack"
  top="$(ls -1 "$WORK/_unpack" | head -1)"
  [ -n "$top" ] || { say "[!] BoringSSL 解包后为空" >&2; exit 1; }
  rm -rf "$WORK/boringssl-${BORINGSSL_COMMIT}"
  mv "$WORK/_unpack/$top" "$WORK/boringssl-${BORINGSSL_COMMIT}"
  rm -rf "$WORK/_unpack"

  _apply "$PATCHES/boringssl.patch" "$WORK/boringssl-${BORINGSSL_COMMIT}" "boringssl.patch"

  # 自检：curl-impersonate 的钩子必须在
  grep -q "extension_order" "$WORK/boringssl-${BORINGSSL_COMMIT}/include/openssl/ssl.h" \
    || { say "[!] BoringSSL 缺 extension_order 钩子" >&2; exit 1; }
  say "[✓] extension_order 钩子存在"

  tar "${TAROPT[@]}" -czf "$BSSL_OUT" -C "$WORK" "boringssl-${BORINGSSL_COMMIT}"
  say "[✓] $BSSL_OUT"
  say "[i] build/windows/rebuild_boringssl.sh 需要解包目录 deps/sources/boringssl/，可执行："
  say "    tar ${TAROPT[*]} -xzf \"$BSSL_OUT\" -C \"$SRC\" && mv \"$SRC/boringssl-${BORINGSSL_COMMIT}\" \"$SRC/boringssl\""
else
  say "[=] 已存在 $(basename "$BSSL_OUT")，跳过（--force 可重做）"
fi
;; esac

# --------------------------------------------------------------------------- #
# 3) nghttp3 / ngtcp2：带 submodule 的 git 检出（tarball 不含 submodule）
# --------------------------------------------------------------------------- #
_prepare_git_dep() {  # <dest-name> <repo-url> <ref> <patch|null> <label>
  local name="$1" repo="$2" ref="$3" pf="$4" label="$5"
  local dest="$SRC/$name"
  if [ "$MODE" != "force" ] && [ -d "$dest/.git" ]; then
    say "[=] 已存在 deps/sources/$name，跳过（--force 可重做）"
    return 0
  fi
  step "$label"
  rm -rf "$dest"
  say "[>] git clone --recurse-submodules $repo"
  git clone --quiet --recurse-submodules --shallow-submodules "$repo" "$dest"
  ( cd "$dest" && git checkout --quiet "$ref" && git submodule update --init --recursive --depth 1 --quiet )
  say "[✓] 检出 $(cd "$dest" && git rev-parse --short HEAD)"
  if [ "$pf" != "null" ]; then
    _apply "$pf" "$dest" "$(basename "$pf")"
  fi
}

case "$ONLY" in quic|all)
_prepare_git_dep "nghttp3-src" "$NGHTTP3_REPO" "$NGHTTP3_TAG" "$PATCHES/nghttp3.patch" "nghttp3 $NGHTTP3_TAG"
_prepare_git_dep "ngtcp2-src"  "$NGTCP2_REPO"  "$NGTCP2_COMMIT" "null"              "ngtcp2 ${NGTCP2_COMMIT:0:12}"
;; esac

# --------------------------------------------------------------------------- #
step "完成"
say "deps/sources/ 现状："
ls -la "$SRC" | sed 's/^/  /'
say ""
say "下一步："
say "  Windows : bash build/windows/build_all.sh"
say "  Linux   : bash build/linux/scripts/build_all.sh"
say "（两者都会以 deps/sources/ 下的产物为输入；首次编译 BoringSSL 需要较长时间）"
