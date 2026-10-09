#!/bin/bash
# 40 —— 编译 CFFI API 模式扩展
#
# 产物：python/nb_curl/_nb_curl_cffi.cpython-XXX-x86_64-linux-gnu.so
#
# 说明：
#  * 这一步是**可选**的。没有它也完全可用 —— 会自动回退到 ctypes 后端。
#  * CFFI API 模式扩展在运行期依赖 cffi 包（它 import _cffi_backend）。
#  * 扩展链接 libnb_curl_native.so，并写入 rpath $ORIGIN/_lib，
#    这样 import 时能自动找到同包目录下的桥接层。
#  * 扩展按 CPython 版本编译（cp310/cp311/...），换版本要重编。
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[ -f "$LIBDIR/libnb_curl_native.so" ] || die "请先运行 scripts/30_bridge.sh"

VENV="$WORK/venv"
if [ ! -x "$VENV/bin/python" ]; then
  c_info "创建构建用 venv: $VENV"
  python3 -m venv "$VENV"
fi

c_info "准备构建依赖（cffi / setuptools / wheel）..."
"$VENV/bin/python" -m pip install -q --upgrade pip >/dev/null 2>&1 || true
# 优先离线：如果宿主机 pip 源不可用，可预先把 wheel 放进 deps/sources/
if ! "$VENV/bin/python" -c "import cffi" >/dev/null 2>&1; then
  "$VENV/bin/python" -m pip install -q cffi setuptools wheel \
    || die "安装 cffi/setuptools/wheel 失败（需要网络或本地 wheel 缓存）"
fi

c_info "编译扩展 ..."
cd "$PROJECT"
# NB_CURL_BACKEND=ctypes 是**必须**的：
#   不设的话，`python -m nb_curl._cffi_build` 会先执行 nb_curl/__init__.py，
#   加载 cffi 后端并把已存在的 _nb_curl_cffi*.so 映射进当前进程；
#   随后同一进程删除/覆盖该文件会失败（Windows 上是 WinError 5，
#   Linux 上则是把正在使用的 .so 覆盖成"半新半旧"，更隐蔽）。
NB_CURL_BACKEND=ctypes CODEBUDDY_SAFE_DELETE_ENABLED=0 \
  "$VENV/bin/python" -m nb_curl._cffi_build --quiet

c_ok "CFFI 扩展就绪"
ls -la "$PROJECT"/nb_curl/_nb_curl_cffi*.so 2>/dev/null || true

echo
c_info "自检（应显示 backend = cffi）："
cd "$PROJECT"
"$VENV/bin/python" -c "
import sys; sys.path.insert(0, '.')
import nb_curl
print('  backend:', nb_curl.backend_name())
print('  avail  :', nb_curl.available_backends())
print('  curl   :', nb_curl.native_version()[:70])
"
