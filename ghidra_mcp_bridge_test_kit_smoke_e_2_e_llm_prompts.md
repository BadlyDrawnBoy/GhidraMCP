# Ghidra MCP Bridge — Test Kit (Smoke, E2E & LLM Prompts)

A compact, reproducible way to verify your Python bridge ↔ JS plugin ↔ Ghidra HTTP server, without touching your production project. It includes:

- A **bash smoke test** (`test_bridge.sh`) for server & shim connectivity and core endpoints.
- A set of **LLM Copilot prompts** to exercise the MCP tools (READ/WRITE, gates, paging) safely.
- Minimal rollback notes.

---

## 0) Prereqs
- Ghidra HTTP server running (e.g. `http://127.0.0.1:8080/`).
- Your **Python MCP bridge** running with the shim (e.g. `http://127.0.0.1:8081/`).
- `curl` installed. (Optional: `jq`.)
- Have a **scratch copy** of your Ghidra project for testing.

---

## 1) Bash smoke test — `test_bridge.sh`
Copy the script below into a file named `test_bridge.sh`, make it executable (`chmod +x test_bridge.sh`), then run `./test_bridge.sh`.

```bash
#!/usr/bin/env bash
set -euo pipefail

# Config — adjust if needed
GHIDRA_SERVER="${GHIDRA_SERVER:-http://127.0.0.1:8080}"
MCP_SHIM="${MCP_SHIM:-http://127.0.0.1:8081}"
APP_ENTRY_ADDR="${APP_ENTRY_ADDR:-0x00200060}"
TEST_COMMENT="[TEST] bridge ok"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0

pass() { echo -e "${GREEN}PASS${NC}  $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}FAIL${NC}  $1"; FAIL=$((FAIL+1)); }
info() { echo -e "${YELLOW}INFO${NC}  $1"; }

http_ok() {
  local method="$1" url="$2"; shift 2
  if [[ "$method" == GET ]]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' "$url" "$@")
  else
    code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$url" "$@")
  fi
  [[ "$code" =~ ^2..$ ]] && return 0 || return 1
}

http_body() {
  local method="$1" url="$2"; shift 2
  if [[ "$method" == GET ]]; then
    curl -s "$url" "$@"
  else
    curl -s -X POST "$url" "$@"
  fi
}

headline() { echo; echo "==== $1 ===="; }

headline "Shim connectivity"
if http_ok GET "$MCP_SHIM/openapi.json"; then pass "GET /openapi.json"; else fail "GET /openapi.json"; fi
if http_ok GET "$MCP_SHIM/health"; then pass "GET /health"; else fail "GET /health"; fi

headline "Ghidra server: endpoint variants"
# New + old variants — we accept success if at least one variant works
try_endpoint_set() {
  local name="$1"; shift
  local ok=0
  while [[ $# -gt 0 ]]; do
    local url="$1"; shift
    if http_ok GET "$url"; then
      pass "$name → $(echo "$url" | sed 's#^.*://##')"; ok=1; break
    fi
  done
  [[ $ok -eq 1 ]] || fail "$name (no variant responded 2xx)"
}

try_endpoint_set "decompile_by_address" \
  "$GHIDRA_SERVER/decompile_by_addr?address=$APP_ENTRY_ADDR" \
  "$GHIDRA_SERVER/decompile_function?address=$APP_ENTRY_ADDR"

try_endpoint_set "disassemble" \
  "$GHIDRA_SERVER/disassemble?address=$APP_ENTRY_ADDR" \
  "$GHIDRA_SERVER/disassemble_function?address=$APP_ENTRY_ADDR"

try_endpoint_set "function_by_addr" \
  "$GHIDRA_SERVER/function_by_addr?address=$APP_ENTRY_ADDR" \
  "$GHIDRA_SERVER/get_function_by_address?address=$APP_ENTRY_ADDR"

try_endpoint_set "list_functions" \
  "$GHIDRA_SERVER/functions?offset=0&limit=5" \
  "$GHIDRA_SERVER/list_functions"

headline "READ-only sanity"
body=$(http_body GET "$GHIDRA_SERVER/decompile_by_addr?address=$APP_ENTRY_ADDR") || true
if [[ -z "$body" || "$body" == ERROR:* ]]; then
  # try old name
  body=$(http_body GET "$GHIDRA_SERVER/decompile_function?address=$APP_ENTRY_ADDR") || true
fi
if [[ -n "$body" && ! "$body" =~ ^ERROR: ]]; then pass "Decompile app_entry returned content"; else fail "Decompile app_entry empty/error"; fi

headline "WRITE→VERIFY (harmless comment)"
# Set a test decompiler comment at app_entry (writes are on the GHIDRA server)
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  "$GHIDRA_SERVER/set_decompiler_comment" \
  --data-urlencode "address=$APP_ENTRY_ADDR" \
  --data-urlencode "comment=$TEST_COMMENT")
if [[ "$code" =~ ^2..$ ]]; then pass "set_decompiler_comment"; else fail "set_decompiler_comment ($code)"; fi

# Verify by re-decompile
verify=$(http_body GET "$GHIDRA_SERVER/decompile_by_addr?address=$APP_ENTRY_ADDR") || true
[[ -z "$verify" || "$verify" == ERROR:* ]] && verify=$(http_body GET "$GHIDRA_SERVER/decompile_function?address=$APP_ENTRY_ADDR") || true
if grep -Fq "$TEST_COMMENT" <<<"$verify"; then pass "comment visible in decompile"; else fail "comment not visible"; fi

headline "Strings (small page; filter client-side)"
if http_ok GET "$GHIDRA_SERVER/strings?offset=0&limit=128"; then
  pass "strings page"
else
  fail "strings page"
fi

headline "Summary"
echo -e "${GREEN}PASS:${NC} $PASS  ${RED}FAIL:${NC} $FAIL"
[[ $FAIL -eq 0 ]] || exit 1
```

**How to run:**
```bash
chmod +x test_bridge.sh
GHIDRA_SERVER=http://127.0.0.1:8080 MCP_SHIM=http://127.0.0.1:8081 ./test_bridge.sh
```

Expected: All **PASS**. If some endpoints only exist in their *old* names, the script still passes by picking whichever variant responds.

> Rollback: The only write is a comment at `app_entry`; overwrite it later with your desired header.

---

## 2) LLM Copilot — Playground Prompts
Use these **exact blocks** in your MCP Copilot/Aider chat. They are small, safe, and exercise key mechanics.

### 2.1 READ-only sanity (no writes)
```mcp-bundle
{"actions":[
  {"id":"dasm_entry","call":"disassemble_function","args":{"address":"0x00200060"}},
  {"id":"dec_entry","call":"decompile_function_by_address","args":{"address":"0x00200060"}}
], "goal":"READ-only: confirm app_entry disasm/decompile without modifying program"}
```
**Expected:** Two successful READs, short summary.

### 2.2 Harmless WRITE→VERIFY (single comment)
```mcp-bundle
{"actions":[
  {"id":"w","call":"set_decompiler_comment","args":{"address":"0x00200060","comment":"[TEST] LLM write→verify"}},
  {"id":"v","call":"decompile_function_by_address","args":{"address":"0x00200060"}}
], "goal":"Write→Verify: add decompiler header comment at app_entry and verify it appears"}
```
**Expected:** Tool returns 200 for write; verify shows the comment in decompile output.

### 2.3 Gate demo (large listing triggers confirmation)
Ask the Copilot to do this **in one reply**, and observe it pausing with a CONFIRMATION REQUEST:
```
Please list 5000 functions using `list_functions` in one call. If the limit is over the hard cap, you must return a CONFIRMATION REQUEST and stop.
```
**Expected:** Copilot prints the `--- CONFIRMATION REQUEST ---` block rather than dumping thousands of lines.

### 2.4 Strings search (safe/paged)
```mcp-bundle
{"actions":[
  {"id":"s","call":"search_strings","args":{"query":"debug","case":false,"regex":false,"max_hits":64}},
  {"id":"s_win","call":"find_text_window","args":{"q":"update","start":"0x00200090","end":"0x002000B0"}}
], "goal":"Find indicative strings and scan literal window near entry"}
```
**Expected:** A small list of matches (if present) and a window scan output.

### 2.5 Jump-table probe (READ-first, then annotate 1 slot)
```mcp-bundle
{"actions":[
  {"id":"dump_lits","call":"list_data_window","args":{"start":"0x00200090","end":"0x002000B0"}},
  {"id":"jt0_read","call":"read_dword","args":{"address":"0x002000A0"}},
  {"id":"jt0_dasm","call":"disassemble_function","args":{"address_from":"jt0_read"}},
  {"id":"jt0_dec","call":"decompile_function_by_address","args":{"address_from":"jt0_read"}},
  {"id":"w_note","call":"set_decompiler_comment","args":{"address_from":"jt0_read","comment":"TEMP: dispatch_handler_00_tbd (origin: *0x002000A0)"}},
  {"id":"v_note","call":"decompile_function_by_address","args":{"address_from":"jt0_read"}}
], "goal":"READ literal pool near entry; try JT slot 0 (ARM); add TEMP header if target decompiles; verify"}
```
**Expected:** If pointer is valid code, disasm/decompile succeed and the TEMP header appears. If not, Copilot should mention UNVERIFIED.

### 2.6 Updater path — annotate & verify
```mcp-bundle
{"actions":[
  {"id":"w_udisk","call":"set_decompiler_comment","args":{"address":"0x0026887C","comment":"proto_tbd: maybe_update_from_udisk(int dry?, unsigned int dst?, const char* path?, const char* tag?, int ui_mode?, int post?)"}},
  {"id":"v_udisk","call":"decompile_function_by_address","args":{"address":"0x0026887C"}},
  {"id":"w_ucf","call":"set_decompiler_comment","args":{"address":"0x0026CCF8","comment":"proto_tbd: update_copy_or_flash(int dry, unsigned int dst, char* src, char* out_or_null, char* tag, char* msg_fail, char* msg_ok, int ui, int post)"}},
  {"id":"v_ucf","call":"decompile_function_by_address","args":{"address":"0x0026CCF8"}}
], "goal":"Anchor short prototypes at updater functions; verify in decompile headers"}
```
**Expected:** Both comments set; visible in decompile output.

> Tip: If your runner supports `address_from` substitution, the JT probe (2.5) will chain values automatically; otherwise, fill the concrete address manually after the read.

---

## 3) Troubleshooting quickies
- **404 on an endpoint**: Your Ghidra server may use older names. Use the bash test to see which variant responds. Consider adding **endpoint auto-resolve** in your bridge.
- **Huge dumps/LLM context overrun**: The MCP tools implement caps and confirmation gates. Prefer targeted calls (`list_data_window`, `search_strings`) instead of broad `list_*`.
- **Write not visible**: Some views cache text. Force a re-decompile (`decompile_function_by_address`) after setting a comment.

---

## 4) Cleanup / Rollback
- Overwrite or remove the `[TEST]` header comment at `app_entry @ 0x00200060` when done.
- Keep the smoke script around; it’s safe to re-run anytime against a scratch project.

