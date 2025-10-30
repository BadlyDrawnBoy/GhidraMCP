#!/usr/bin/env bash
set -euo pipefail

# 0) Helper: latest short SHA touching any of the given paths (or empty)
sha() { git log -n1 --format='%h' -- "$@" 2>/dev/null || true; }

# 1) Collect SHAs per task (nur Files, die den Task wirklich belegen)
OPENAPI_FREEZE_SHA=$(sha \
  README.md \
  bridge/tests/golden/data/openapi_snapshot.json \
  bridge/tests/golden/test_openapi_snapshot.py)

API_MOUNT_SHA=$(sha \
  bridge/api/routes.py \
  bridge/api/tools.py \
  bridge/tests/integration/test_api_mount.py)

JT_SCAN_SHA=$(sha \
  bridge/api/routes.py \
  bridge/api/tools.py \
  bridge/features/jt.py \
  bridge/tests/contract/test_http_contracts.py \
  bridge/tests/golden/data/jt_slot_cases.json)

JT_SCAN_CONSISTENCY_SHA=$(sha \
  bridge/tests/contract/conftest.py \
  bridge/tests/contract/test_http_contracts.py \
  bridge/tests/contract/test_jt_scan_consistency.py)

# Aus deinem Log bekannt:
JT_VERIFY_SHA=844252e

RANGE_CONTRACT_SHA=$(sha \
  bridge/adapters/arm_thumb.py \
  bridge/tests/unit/test_adapters_arm_thumb.py)

CLIENT_UNIFY_SHA=$(sha \
  bridge/tests/unit/test_ghidra_whitelist.py \
  bridge/client)

CI_TESTS_SHA=$(sha \
  .github/workflows/build.yml)
if [ -z "${CI_TESTS_SHA:-}" ]; then
  CI_TESTS_SHA=$(python3 - <<'PY'
from pathlib import Path
import re
todo = Path('.plan/TODO.md').read_text(encoding='utf-8')
m = re.search(r"CI-TESTS.*?_commit:\s*([0-9a-f]{7})_", todo, re.DOTALL)
print(m.group(1) if m else(""))
PY
  )
fi

STRINGS_ASSERTS_SHA=$(python3 - <<'PY'
from pathlib import Path
import re
todo = Path('.plan/TODO.md').read_text(encoding='utf-8')
m = re.search(r"STRINGS-ASSERTS.*?_commit:\s*([^_\s]+)_", todo, re.DOTALL)
print(m.group(1) if m else (""))
PY
)

SSE_HANDSHAKE_SHA=$(python3 - <<'PY'
from pathlib import Path
import re
todo = Path('.plan/TODO.md').read_text(encoding='utf-8')
m = re.search(r"SSE-HANDSHAKE.*?_commit:\s*([0-9a-f]+)_", todo, re.DOTALL)
print(m.group(1) if m else(""))
PY
)

# 2) Update .plan/state.json for found SHAs
NOW=$(date -Iseconds)
update() {
  local id="$1" sha_val="$2"
  [ -z "${sha_val:-}" ] && return 0
  tmp=.plan/state.json.tmp
  jq --arg id "$id" --arg sha "$sha_val" --arg now "$NOW" \
     '.tasks[$id].status="done"
    | .tasks[$id].commit=$sha
    | .tasks[$id].updated_at=$now' \
    .plan/state.json > "$tmp" && mv "$tmp" .plan/state.json
  echo "✓ $id → $sha_val"
}

update OPENAPI-FREEZE   "$OPENAPI_FREEZE_SHA"
update API-MOUNT        "$API_MOUNT_SHA"
update JT-SCAN          "$JT_SCAN_SHA"
update JT-SCAN-CONSISTENCY "$JT_SCAN_CONSISTENCY_SHA"
update JT-VERIFY        "$JT_VERIFY_SHA"
update RANGE-CONTRACT   "$RANGE_CONTRACT_SHA"
update CLIENT-UNIFY     "$CLIENT_UNIFY_SHA"
update STRINGS-ASSERTS   "$STRINGS_ASSERTS_SHA"
update SSE-HANDSHAKE    "$SSE_HANDSHAKE_SHA"
update CI-TESTS         "$CI_TESTS_SHA"

echo
echo "Current state:"
jq '.tasks | to_entries[] | {id: .key, status: .value.status, commit: .value.commit}' .plan/state.json
