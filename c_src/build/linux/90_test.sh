#!/bin/bash
# 90 —— 跑测试套件
#
# 说明：测试分两部分
#   * 指纹相关（第 1-5 节）打真实站点 www.xcctls.top，必须有外网；
#   * HTTP 语义（第 6 节）打本地回显服务，不需要外网。
# 若机器没有外网，可以只跑本地部分：
#   python tests/test_nb_curl.py --local-only   （见 tests 里的支持）
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

VENV="$WORK/venv"
[ -x "$VENV/bin/python" ] || die "请先运行 scripts/40_cffi.sh（或手动建 $VENV）"

cd "$PROJECT"

c_info "冒烟测试（导入 + 一次请求）"
"$VENV/bin/python" - <<'PY'
import json, nb_curl
print("  backend:", nb_curl.backend_name())
print("  native :", nb_curl.backend_info()["native_lib"])
print("  curl   :", nb_curl.native_version()[:80])
print("  targets:", len(nb_curl.available_targets()))
r = nb_curl.get("https://www.xcctls.top/all", impersonate="chrome116", timeout=25)
d = json.loads(r.text)
print("  request:", r.status_code, r.http_version)
print("  ja4    :", (d["client_hello"].get("ja4") or {}).get("ja4"))
PY

echo
c_info "完整测试套件（tests/test_nb_curl.py）"
ROOT="$ROOT" "$VENV/bin/python" "$PROJECT/tests/test_nb_curl.py"

c_ok "测试完成"
