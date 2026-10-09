#!/bin/bash
# 50 —— 打包成可 pip install 的 wheel
#
# 产物：dist/nb_curl-<版本>-py3-none-linux_x86_64.whl
#
# 标签 py3-none：同一份 wheel 能被任意 Python 3.x 安装
#   匹配的 Python  -> 用 CFFI API 模式后端
#   其它 Python    -> 回退 ctypes 后端
#
# ⚠️ glibc 兼容性（重要）：
#   这个 wheel 里的 .so 是**在当前机器上**编的，链接的是当前 glibc。
#   在 Ubuntu 24.04（glibc 2.39）上编的轮子，拿到 Ubuntu 22.04（2.35）
#   或更老的容器里会报 "GLIBC_2.3x not found"。
#   要发布给别人用，请在**目标最低版本**的系统里构建（见 Dockerfile），
#   或直接用 01_manylinux.sh 在容器里构建 manylinux 轮子。
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[ -f "$LIBDIR/libnb_curl_native.so" ] || die "请先运行 scripts/30_bridge.sh"

VENV="$WORK/venv"
[ -x "$VENV/bin/python" ] || die "请先运行 scripts/40_cffi.sh（或手动建 $VENV）"

c_info "清理旧的构建中间目录 ..."
cd "$PROJECT"
rm -rf build/lib.* build/bdist.* build/temp.* nb_curl.egg-info ./*.egg-info dist 2>/dev/null || true

c_info "构建 wheel ..."
"$VENV/bin/python" -m pip install -q --upgrade build >/dev/null 2>&1 || true
"$VENV/bin/python" -m build --wheel --no-isolation --outdir dist

WHEEL="$(ls "$PROJECT"/dist/*.whl 2>/dev/null | head -1 || true)"
[ -n "$WHEEL" ] || die "没有生成 wheel"

c_ok "wheel 就绪"
ls -la "$PROJECT"/dist/*.whl

echo
c_info "校验：wheel 里只含二进制产物"
"$VENV/bin/python" "$ROOT/build/tools/check_binary_only.py" "$WHEEL"

echo
c_info "wheel 内容："
"$VENV/bin/python" - "$WHEEL" <<'PY'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
for n in sorted(z.namelist()):
    print("  %-58s %9d" % (n, z.getinfo(n).file_size))
PY

echo
c_info "在本机装一遍验证："
"$VENV/bin/python" -m pip install -q --force-reinstall --no-deps "$PROJECT"/dist/*.whl
"$VENV/bin/python" -c "
import nb_curl, json
print('  backend:', nb_curl.backend_name())
r = nb_curl.get('https://www.xcctls.top/all', impersonate='chrome116', timeout=25)
d = json.loads(r.text)
print('  request:', r.status_code, r.http_version)
print('  ja4    :', (d['client_hello'].get('ja4') or {}).get('ja4'))
"

echo
echo "安装方式："
echo "  pip install $PROJECT/dist/$(basename "$(ls "$PROJECT"/dist/*.whl | head -1)")"
echo "或直接从源码目录："
echo "  pip install $PROJECT"
echo "WHEEL-BUILD-OK"
