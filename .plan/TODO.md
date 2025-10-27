> **Codex – Session Protocol (read this first, every time)**
>
> This file is the **single source of truth**. Work one task per run.

**How to proceed**

1. Read this `/.plan/TODO.md`. If `/.plan/tasks.manifest.json` exists, respect its `sequence`/`after` order; otherwise use the order here.
2. Pick the **first** item marked ⬜️ (todo). If it is already satisfied by the current code, mark ✅ with a one-line note and continue to the next run.
3. Implement **only** what this task’s DoD requires. Keep it **non-breaking**. Avoid repo-wide refactors unless the task explicitly says so.
4. Run tests locally (e.g., `pytest -q`). If tests fail and you cannot fix without scope creep, **stop**: set the task to ⛔ and add a one-line reason.
5. Make **one atomic commit** with message:  
   `TASK_ID: short summary`  
   (example: `JT-VERIFY: verify ARM/Thumb targets via get_function_by_address`)
6. Update this file:
   - change ⬜️ → ✅ (or ⛔ with reason)
   - append the short commit SHA on the DoD line (e.g., `_commit: 796e00d_`)
   - add a 1–3 line “What changed” note under the task (very brief)
7. Output a **final report** (in your chat reply) with:
   - task id, commit SHA, touched files, and a 1–3 line summary
   - how to run the relevant tests (commands)
8. **Do not**: reformat the whole repo, or modify other tasks. One task per run, then stop.

---

### 1) ✅ API-MOUNT — Mount deterministic routes & register MCP tools (ID: API-MOUNT)
- Mount HTTP: `/api/jt_slot_check.json`, `/api/jt_slot_process.json`,
  `/api/jt_scan.json`, `/api/string_xrefs.json`, `/api/mmio_annotate.json`
- Register tools: `jt_slot_check`, `jt_slot_process`, `jt_scan`,
  `string_xrefs_compact`, `mmio_annotate_compact`
- Ensure **one** canonical entrypoint (guard/remove duplicate `main()` paths)
- **DoD:** `GET /openapi.json` 200; `POST /api/jt_slot_check.json` returns a valid envelope JSON
  _commit: 78e230d
  - What changed: Added integration tests confirming OpenAPI availability and jt_slot_check envelope handling.
  - What changed: Verified MCP tool registration matches the required deterministic tool list.

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

