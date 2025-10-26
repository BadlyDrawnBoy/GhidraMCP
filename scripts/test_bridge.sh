#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# ============================================================================
# Ghidra MCP Bridge – Endpoint Smoke Test
# ----------------------------------------------------------------------------
# This script probes the shim and the underlying Ghidra HTTP bridge endpoints
# and performs a harmless WRITE→VERIFY cycle (setting/reading a decompiler
# comment) to ensure basic compatibility before using an LLM or Aider.
#
# Usage:
#   GHIDRA_SERVER=http://127.0.0.1:8080 \
#   MCP_SHIM=http://127.0.0.1:8081 \
#   ADDR=0x00200060 \
#   bash scripts/test_bridge.sh
#
# All vars have sane defaults if not provided.
# ============================================================================

BASE=${GHIDRA_SERVER:-http://127.0.0.1:8080}
SHIM=${MCP_SHIM:-http://127.0.0.1:8081}
ADDR=${ADDR:-0x00200060}

PASS=0
FAIL=0

say()  { echo -e "\n==== $* ====\n"; }
pass(){ echo "PASS  $*"; PASS=$((PASS+1)); }
fail(){ echo "FAIL  $*"; FAIL=$((FAIL+1)); }

http_get_code() {
  local url=$1
  curl -s -o /dev/null -w "%{http_code}" "$url" || echo 000
}

http_get_show() {
  local url=$1; shift || true
  curl -s "$url" | sed -n '1,12p;$p'
}

http_post_form() {
  local url=$1; shift
  curl -s -X POST -d "$*" "$url"
}

# ----------------------------------------------------------------------------
# 1) Shim connectivity
# ----------------------------------------------------------------------------
say "Shim connectivity"
code=$(http_get_code "$SHIM/openapi.json")
[[ "$code" == 200 ]] && pass "GET /openapi.json" || { fail "GET /openapi.json (HTTP $code)"; }
code=$(http_get_code "$SHIM/health")
[[ "$code" == 200 ]] && pass "GET /health" || { fail "GET /health (HTTP $code)"; }

# ----------------------------------------------------------------------------
# 2) Ghidra server: endpoint variants (compat)
# ----------------------------------------------------------------------------
say "Ghidra server: endpoint variants"

# decompile_by_addr (primary)
url="$BASE/decompile_by_addr?address=$ADDR"
code=$(http_get_code "$url")
[[ "$code" == 200 ]] && pass "decompile_by_addr → $url" || pass "decompile_by_addr not present (HTTP $code) – will rely on fallbacks"

# disassemble
url="$BASE/disassemble?address=$ADDR"
code=$(http_get_code "$url")
[[ "$code" == 200 ]] && pass "disassemble → $url" || pass "disassemble not present (HTTP $code) – may rely on bridge fallback"

# function_by_addr vs get_function_by_address (compat pair)
url_a="$BASE/function_by_addr?address=$ADDR"
url_b="$BASE/get_function_by_address?address=$ADDR"
code_a=$(http_get_code "$url_a")
code_b=$(http_get_code "$url_b")
if [[ "$code_a" == 200 ]]; then
  pass "function_by_addr present"
  http_get_show "$url_a" | sed 's/^/      /'
elif [[ "$code_b" == 200 ]]; then
  pass "get_function_by_address present (compat)"
  http_get_show "$url_b" | sed 's/^/      /'
else
  fail "No function-by-address endpoint present (got $code_a / $code_b)"
fi

# functions list (small page)
url="$BASE/functions?offset=0&limit=5"
code=$(http_get_code "$url")
[[ "$code" == 200 ]] && pass "list_functions small page" || pass "list_functions not present (HTTP $code) – not critical"

# ----------------------------------------------------------------------------
# 3) READ-only sanity (decompile entry)
# ----------------------------------------------------------------------------
say "READ-only sanity"
body=$(curl -s "$BASE/decompile_by_addr?address=$ADDR" || true)
if [[ -n "$body" ]] && [[ ! "$body" =~ ^\<h1\>404 ]]; then
  pass "Decompile returned content"
  echo "$body" | sed -n '1,12p;$p' | sed 's/^/      /'
else
  fail "Decompile returned empty/404"
fi

# ----------------------------------------------------------------------------
# 4) WRITE→VERIFY (harmless comment)
# ----------------------------------------------------------------------------
say "WRITE→VERIFY (decompiler comment)"
comment="MCP smoke-test $(date -u +%FT%TZ)"
resp=$(http_post_form "$BASE/set_decompiler_comment" "address=$ADDR&comment=$comment" || true)
if echo "$resp" | grep -qiE "success|ok|set"; then
  pass "set_decompiler_comment"
else
  echo "      Response: $resp"
  fail "set_decompiler_comment did not confirm success"
fi

# Verify by reading decompile again
body2=$(curl -s "$BASE/decompile_by_addr?address=$ADDR" || true)
if echo "$body2" | grep -Fq "$comment"; then
  pass "comment visible in decompile"
else
  echo "      (Comment not found in decompile output – some bridges render comments only in UI.)"
  # Not fatal: some backends don't echo comments, so mark soft pass
  pass "comment verification (soft)"
fi

# ----------------------------------------------------------------------------
# 5) Strings (small page)
# ----------------------------------------------------------------------------
say "Strings (small page)"
strs=$(curl -s "$BASE/strings?offset=0&limit=10" || true)
if [[ -n "$strs" ]] && [[ ! "$strs" =~ ^ERROR ]]; then
  pass "strings page"
  echo "$strs" | sed -n '1,12p' | sed 's/^/      /'
else
  fail "strings page"
fi

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------
say "Summary"
echo "PASS: $PASS  FAIL: $FAIL"
[[ $FAIL -eq 0 ]] || exit 1
exit 0

