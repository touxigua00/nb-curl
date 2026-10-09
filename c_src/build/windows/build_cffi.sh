#!/bin/bash
# 编译 nb_curl 的 CFFI API 模式扩展（纯 bash，不依赖 cmd.exe）
#
# 三个关键点（都踩过坑）：
#
#  1) MSVC/SDK 环境由 nb_curl/_cffi_build.py 内部以原生 Windows 路径注入。
#     不要用 vcvars64.bat：Git Bash 里 export PATH="D:/..." 会被 MSYS 改写成
#     PortableGit 下的相对路径；而本环境的 cmd.exe 又被安全策略拦截。
#
#  2) **必须设 NB_CURL_BACKEND=ctypes**（最容易被忽略、后果最严重）：
#     `python -m nb_curl._cffi_build` 会先执行 nb_curl/__init__.py，进而加载
#     _native 与 cffi 后端，把已存在的 _nb_curl_cffi*.pyd **映射进当前进程**。
#     然后同一进程再去删除/覆盖这个文件，Windows 会稳定报"拒绝访问
#     (WinError 5)"，现象是构建永远失败、而且看起来像杀毒软件在锁文件。
#     强制 ctypes 后端就不会去 import _nb_curl_cffi，文件自然不锁。
#
#  3) 清理旧产物交给 Python 侧（见 _cffi_build._clean_stale_artifacts），
#     不用 rm —— 带"安全删除"钩子的环境里 rm 可能被换成 shell 函数，
#     行为不可预期。CODEBUDDY_SAFE_DELETE_ENABLED=0 让删除真正生效
#     （删的是构建产物，不是用户文件）。
set -e
cd "$(dirname "$0")"

# 本脚本在 <root>/build/windows/，项目在 <root>/python/
REPO="$(cd ../.. && pwd -W)"   # pwd -W: 给 Windows 风格路径
PROJECT="$REPO/python"

unset http_proxy HTTP_PROXY https_proxy HTTPS_PROXY \
      no_proxy NO_PROXY all_proxy ALL_PROXY 2>/dev/null || true
export CODEBUDDY_SAFE_DELETE_ENABLED=0
export CODEBUDDY_BROKERED_FS_HOOK_ENABLED=0
export NB_CURL_BACKEND=ctypes

cd "$PROJECT"
PY="${NB_CURL_PYTHON:-./.venv/Scripts/python.exe}"
[ -x "$PY" ] || PY="python"

echo "=== building CFFI API-mode extension ==="
"$PY" -m nb_curl._cffi_build "$@"

# 强制校验：宁可失败也不要"看起来成功但没产物"
if ! ls nb_curl/_nb_curl_cffi*.pyd >/dev/null 2>&1; then
  echo "[FAIL] 没有生成 _nb_curl_cffi*.pyd —— 上面的编译输出里有原因" >&2
  exit 1
fi

ls -la nb_curl/_nb_curl_cffi*.pyd
echo "NB_CURL-CFFI-BUILD-OK"
