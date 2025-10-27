# MCP Bridge — LIVE To-Do / Task List
> Source of truth for Codex. On each session, Codex MUST read this list,
> pick the first ⬜️ item, complete it, run tests, commit, and **update this file**
> (checkbox + short note with commit SHA).

**Status legend:** ⬜️ todo · 🟨 in-progress · ✅ done · ⛔ blocked

## How Codex uses this list
1. Use the current repo state (no assumptions from previous chats).
2. Take the first **⬜️ todo** item.
3. Implement it, run tests locally, make **one atomic commit**:
   - Commit message prefix: `<ID>: <summary>`
4. Update this file:
   - Change ⬜️ → ✅ (or ⛔ with a one-line reason)
   - Append the short commit SHA after the DoD line.
5. Stop. I will handle the PR/merge. Next session starts again from this file.

---

### 1) ⬜️ API-MOUNT — Mount deterministic routes & register MCP tools (ID: API-MOUNT)
- Mount HTTP: `/api/jt_slot_check.json`, `/api/jt_slot_process.json`,
  `/api/jt_scan.json`, `/api/string_xrefs.json`, `/api/mmio_annotate.json`
- Register tools: `jt_slot_check`, `jt_slot_process`, `jt_scan`,
  `string_xrefs_compact`, `mmio_annotate_compact`
- Ensure **one** canonical entrypoint (guard/remove duplicate `main()` paths)
- **DoD:** `GET /openapi.json` 200; `POST /api/jt_slot_check.json` returns a valid envelope JSON  
  _commit:_

### 2) ⬜️ CLIENT-UNIFY — Single Ghidra client + whitelist (ID: CLIENT-UNIFY)
- One client module; **POST alias resolver** mirrors GET; cache aliases
- Enforce whitelist: **allowed** `read_dword`, `disassemble_function`,
  `get_function_by_address`, `get_xrefs_to`, `rename_function_by_address`, `set_*comment`
  · **forbidden** `read_bytes`, `read_cstring`, any `list_*`, any `search_*`, any `confirm:true`
- **DoD:** Unit tests show allowed pass, forbidden return a defined error  
  _commit:_

### 3) ⬜️ RANGE-CONTRACT — Enforce `[code_min, code_max)` (ID: RANGE-CONTRACT)
- Adapter uses `< code_max`; docs/tests updated
- **DoD:** Off-by-one at the upper bound covered by tests  
  _commit:_

### 4) ⬜️ JT-VERIFY — Strict ARM/Thumb READ→VERIFY (ID: JT-VERIFY)
- Probe ARM at `ptr` and Thumb at `ptr-1` only if in range
- Verify via `get_function_by_address` or `disassemble_function` before marking valid;
  else set `NO_FUNCTION_AT_TARGET`
- Treat `0xE12FFF1C` as `ARM_INSTRUCTION`
- **DoD:** Tests for instruction word, out-of-range, valid ARM, valid Thumb pass  
  _commit:_

### 5) ⬜️ JT-SCAN — Read-only batch scan (ID: JT-SCAN)
- Implement `jt_scan` aggregating `slot_check`; correct `summary.total == items.length`
- **DoD:** Contract test with 16 mixed slots passes  
  _commit:_

### 6) ⬜️ MMIO-HEUR — Precise MMIO heuristics (ID: MMIO-HEUR)
- Count only `LDR`/`STR`; exclude `LDM/STM`
- Extract targets from `[#imm]` or `=imm`; ignore unrelated immediates
- Writes gated by `ENABLE_WRITES=false` default and `dry_run:true`
- **DoD:** Unit tests demonstrate reduced false positives  
  _commit:_

### 7) ⬜️ SCHEMA-STRICT — Strict schemas + envelope (ID: SCHEMA-STRICT)
- All deterministic endpoints/tools return `{ ok, data|null, errors[] }`
- Validate `data` against JSON Schemas (`additionalProperties:false`)
- **DoD:** Contract tests enforce schemas; invalid payloads → 400 + error envelope  
  _commit:_

### 8) ⬜️ OBS-LIMITS — Observability & limits (ID: OBS-LIMITS)
- Apply `request_scope` to HTTP & MCP tools (timings, counters, request IDs)
- Enforce `MaxWritesPerRequest=2`, `MaxItemsPerBatch=256`, timeouts
- Write audit: old→new name, comment diff, verify result
- **DoD:** Structured logs visible; audit entries present on writes  
  _commit:_

### 9) ⬜️ LEGACY-PARITY — Prove old APIs unchanged (ID: LEGACY-PARITY)
- Golden tests for selected legacy endpoints
- Shell probe script exercises legacy routes successfully
- **DoD:** Golden + probe green  
  _commit:_

### 10) ⬜️ CI-TESTS — Run tests before packaging (ID: CI-TESTS)
- CI executes unit + contract + golden tests; fails on schema drift
- **DoD:** CI shows tests gating release  
  _commit:_

### 11) ⬜️ DOCS-BOOTSTRAP — Developer docs & artifacts (ID: DOCS-BOOTSTRAP)
- Update README (local run, health checks, examples, safe writes)
- Add `.env.sample` and `bin/smoke.sh`
- **DoD:** Quickstart reproducible on a clean machine  
  _commit:_

### 12) ⬜️ CONTROL-FILES — Repo control files (ID: CONTROL-FILES)
- Add/update: `/.plan/tasks.manifest.json`, `/.plan/state.json` (optional `/.plan/pr.json`)
- **DoD:** Codex reads/updates these each session; state persists across chats  
  _commit:_

### 13) ⬜️ OPTIONAL-ADAPTERS — Additional ArchAdapters (ID: OPTIONAL-ADAPTERS)
- Add x86/MIPS/RISC-V adapters after core is stable
- **DoD:** Adapter tests & docs  
  _commit:_

