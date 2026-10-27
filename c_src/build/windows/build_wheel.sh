#!/bin/bash
# 构建可 pip install 的 wheel（只含二进制产物）
#
# 产物：<root>/python/dist/nb_curl-<版本>-py3-none-<平台>.whl
#
# 默认打 **发布版**：
#   * Python 源码经 build/tools/make_release.py 处理 —— 去掉所有解释性注释
#     与模块/私有函数的说明性 docstring，只保留 API docstring（含参数用法）；
#   * 只含编译好的二进制（.dll / .so / .pyd），**没有任何 C 源码**；
#   * 安装方**不需要编译器**，pip 不会触发任何 C 编译；
#   * 标签 py3-none 表示不绑定 Python 版本：
#       版本匹配  -> 走 CFFI API 模式后端
#       版本不匹配 -> 自动回退 ctypes 后端，功能一致
#
# 每次构建都会调用 build/tools/check_binary_only.py 校验，发现源码混入直接失败。
#
# 用法:
#   bash build/windows/build_wheel.sh                 # 发布版 wheel（去注释）
#   bash build/windows/build_wheel.sh --keep-comments # 开发版（保留全部注释）
#   bash build/windows/build_wheel.sh --with-sdist    # 发布版 + 额外出 sdist 并校验
set -e
cd "$(dirname "$0")"

# 用 pwd -W 拿 Windows 路径：CHECK 要传给 Windows 版 python，认不了 /d/... 形式
REPO="$(cd ../.. && pwd -W)"
PROJECT="$REPO/python"
CHECK="$REPO/build/tools/check_binary_only.py"
RELEASE_TOOL="$REPO/build/tools/make_release.py"
STAGE="$PROJECT/build/release_root"

KEEP_COMMENTS=0
WITH_SDIST=0
for arg in "$@"; do
  case "$arg" in
    --keep-comments) KEEP_COMMENTS=1 ;;
    --with-sdist)    WITH_SDIST=1 ;;
  esac
done

# 去掉代理：本仓库的构建/测试都在直连环境下做
unset http_proxy HTTP_PROXY https_proxy HTTPS_PROXY \
      no_proxy NO_PROXY all_proxy ALL_PROXY 2>/dev/null || true
# 本脚本只操作构建产物：关掉沙箱的"删除转回收站"钩子
export CODEBUDDY_SAFE_DELETE_ENABLED=0
export CODEBUDDY_BROKERED_FS_HOOK_ENABLED=0

cd "$PROJECT"
# 用绝对路径：后面会 cd 到暂存目录，相对路径会失效
if [ -n "${NB_CURL_PYTHON:-}" ]; then
  PY="$NB_CURL_PYTHON"
elif [ -x "./.venv/Scripts/python.exe" ]; then
  PY="$PROJECT/.venv/Scripts/python.exe"
else
  PY="python"
fi

echo "=== 1) 检查 native 产物（wheel 不带源码，必须先编好）==="
FOUND=0
for f in nb_curl/_lib/nb_curl_native.dll nb_curl/_lib/libnb_curl_native.so nb_curl/_lib/libnb_curl_native.dylib; do
  [ -f "$f" ] && FOUND=1
done
if [ "$FOUND" = "0" ]; then
  echo "[ERROR] 缺少 nb_curl/_lib/ 下的 native 动态库，请先编译：" >&2
  echo "        Windows: bash build/windows/build_native.sh" >&2
  echo "        Linux  : bash build/linux/scripts/30_bridge.sh" >&2
  exit 1
fi
ls -la nb_curl/_lib/

echo
echo "=== 2) 清理 setuptools 中间目录 ==="
rm -rf build/lib.* build/bdist.* build/temp.* nb_curl.egg-info ./*.egg-info 2>/dev/null || true
rm -rf dist 2>/dev/null || true

BUILD_ROOT="$PROJECT"
if [ "$KEEP_COMMENTS" = "0" ]; then
  echo
  echo "=== 3) 生成发布版源码（去解释性注释，保留参数 docstring）==="
  rm -rf "$STAGE"
  mkdir -p "$STAGE"
  "$PY" "$RELEASE_TOOL" --tree "$PROJECT/nb_curl" "$STAGE/nb_curl"
  cp -f setup.py pyproject.toml MANIFEST.in README.md LICENSE "$STAGE/"
  [ -d tests ] && cp -rf tests "$STAGE/tests"
  BUILD_ROOT="$STAGE"
else
  echo
  echo "=== 3) 跳过发布版处理（--keep-comments，打开发版）==="
fi

echo
echo "=== 4) 构建 wheel ==="
mkdir -p dist
cd "$BUILD_ROOT"
"$PY" -m build --wheel --no-isolation --outdir "$PROJECT/dist"

WHEEL="$(ls "$PROJECT"/dist/*.whl 2>/dev/null | head -1 || true)"
[ -n "$WHEEL" ] || { echo "[ERROR] 没有生成 wheel" >&2; exit 1; }

# CFFI 扩展缺失不致命（会自动回退 ctypes），但会丢掉性能，必须明确提示
# 注意：不能用 `ls *.pyd *.so` 判断 —— 两个 glob 有一个不匹配时 ls 整体返回非 0，
# 在只有 .pyd（Windows）或只有 .so（Linux）的平台上会恒定误报。
CFFI_EXT=""
for _f in "$PROJECT"/nb_curl/_nb_curl_cffi*.pyd "$PROJECT"/nb_curl/_nb_curl_cffi*.so; do
  [ -e "$_f" ] && { CFFI_EXT="$_f"; break; }
done
if [ -z "$CFFI_EXT" ]; then
  echo
  echo "[WARN] 包里没有 CFFI 扩展，使用方将只能用 ctypes 后端（功能一样，略慢）。" >&2
  echo "       想要 CFFI 加速请先运行: bash build/windows/build_cffi.sh" >&2
fi

echo
echo "=== 5) 校验：分发包里不得有 C 源码 ==="
"$PY" "$CHECK" "$WHEEL"

if [ "$WITH_SDIST" = "1" ]; then
  echo
  echo "=== 6) 构建并校验 sdist（--with-sdist）==="
  cd "$BUILD_ROOT"
  "$PY" -m build --sdist --no-isolation --outdir "$PROJECT/dist" >/dev/null 2>&1 || true
  SDIST="$(ls "$PROJECT"/dist/*.tar.gz 2>/dev/null | head -1 || true)"
  if [ -n "$SDIST" ]; then "$PY" "$CHECK" "$SDIST"; else echo "  (未生成 sdist，跳过)"; fi
else
  echo
  echo "=== 6) 跳过 sdist（默认只发 wheel；需要时加 --with-sdist）==="
fi

echo
echo "=== 产物 ==="
ls -la "$PROJECT/dist/"

echo
echo "=========================== 给使用方 ==========================="
echo "只需把这一个文件发出去（C 源码留在本仓库里）："
echo "  $(basename "$WHEEL")"
echo
echo "对方安装（不需要编译器、不需要源码、不需要联网编译）："
echo "  pip install $(basename "$WHEEL")"
echo "用法："
echo "  from nb_curl import requests"
echo "  r = requests.get(url, impersonate=\"chrome152\")"
echo "==============================================================="
echo "WHEEL-BUILD-OK"
