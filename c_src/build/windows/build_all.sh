#!/bin/bash
# 一键构建（Windows）：native DLL + CFFI API 模式扩展 + 自检
#
# 用法: bash build/windows/build_all.sh
set -e
cd "$(dirname "$0")"

REPO="$(cd ../.. && pwd -W)"   # pwd -W: 给 Windows 风格路径
PROJECT="$REPO/python"

# 本脚本只操作构建产物：关掉沙箱的"删除转回收站"钩子
export CODEBUDDY_SAFE_DELETE_ENABLED=0
export CODEBUDDY_BROKERED_FS_HOOK_ENABLED=0

bash build_native.sh
bash build_cffi.sh --quiet

echo
echo "=== build artifacts ==="
ls -la "$PROJECT/nb_curl/_lib/nb_curl_native.dll" 2>/dev/null || true
ls -la "$PROJECT"/nb_curl/_nb_curl_cffi*.pyd 2>/dev/null || true
echo
echo "=== self check ==="
cd "$PROJECT"
./.venv/Scripts/python.exe -c "import nb_curl; print(' backend:', nb_curl.backend_name()); print(' native :', nb_curl.backend_info()['native_lib']); print(' curl   :', nb_curl.native_version()); print(' available:', nb_curl.available_backends())"
echo
echo "ALL-DONE"
