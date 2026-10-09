#!/bin/bash
# 一键构建（Linux）：依赖 -> BoringSSL -> curl-impersonate -> 桥接层 -> CFFI -> wheel
#
# 用法：
#   bash scripts/build_all.sh              # 全流程
#   bash scripts/build_all.sh --no-deps    # 跳过 apt 安装（依赖已就绪时）
#   NB_CURL_JOBS=8 bash scripts/build_all.sh # 指定并行度
#
# 耗时参考（2 核 / 4GB 虚拟机）：约 25-40 分钟，其中 BoringSSL 占大头。
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

SKIP_DEPS=0
for a in "$@"; do
  [ "$a" = "--no-deps" ] && SKIP_DEPS=1
done

START=$(date +%s)

if [ "$SKIP_DEPS" = "0" ]; then
  bash "$SCRIPTS/00_deps.sh"
else
  c_warn "跳过依赖安装（--no-deps）"
fi

bash "$SCRIPTS/10_boringssl.sh"
bash "$SCRIPTS/15_quic.sh"
bash "$SCRIPTS/20_curl.sh"
bash "$SCRIPTS/30_bridge.sh"
bash "$SCRIPTS/40_cffi.sh"
bash "$SCRIPTS/50_wheel.sh"

END=$(date +%s)
echo
c_ok "全部完成，用时 $(( (END-START)/60 )) 分 $(( (END-START)%60 )) 秒"
echo
echo "产物："
ls -la "$PROJECT"/dist/*.whl 2>/dev/null || true
ls -la "$LIBDIR"/libnb_curl_native.so 2>/dev/null || true
ls -la "$PROJECT"/nb_curl/_nb_curl_cffi*.so 2>/dev/null || true
echo
echo "下一步："
echo "  bash scripts/90_test.sh          # 跑测试"
echo "  pip install $PROJECT             # 直接安装"
