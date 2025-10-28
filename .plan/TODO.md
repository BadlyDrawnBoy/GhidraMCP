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

### 0) ☑ SYNC-STATE — Keep plan files in lockstep (ID: SYNC-STATE)

* Mirror task status & short SHA from `/.plan/TODO.md` → `/.plan/state.json`.
* Add a tiny check in tests (or a pre-commit) that fails on mismatch.
* **DoD:** `python -m pytest -q tests/plan/test_state_sync.py` green.

### 1) ✅ API-MOUNT — Deterministic routes & MCP tools (ID: API-MOUNT)

* HTTP: `/api/jt_slot_check.json`, `/api/jt_slot_process.json`, `/api/jt_scan.json`, `/api/string_xrefs.json`, `/api/mmio_annotate.json`
* **DoD:** `GET /openapi.json` 200; `POST /api/jt_slot_check.json` returns envelope.
* *commit:* (already set)

### 2) ✅ CLIENT-UNIFY — Single client + whitelist (ID: CLIENT-UNIFY)

* **DoD:** Unit tests prove allow/deny surface (cached alias resolver).
* *commit:* (already set)

### 3) ✅ RANGE-CONTRACT — Enforce `[code_min, code_max)` (ID: RANGE-CONTRACT)

* **DoD:** Upper-bound off-by-one covered by tests.
* *commit:* (already set)

### 4) ✅ JT-VERIFY — Strict ARM/Thumb READ→VERIFY (ID: JT-VERIFY)

* **DoD:** Instruction sentinel, OOR, valid ARM, valid Thumb.
* *commit:* (already set)

### 5) ✅ JT-SCAN — Read-only batch (ID: JT-SCAN)

* **DoD:** 16-slot contract test passes; `summary.total == len(items)`.
* *commit:* (already set)

### 6) ✅ MMIO-HEUR — Precise MMIO heuristics (ID: MMIO-HEUR)

* Count only `LDR`/`STR`; ignore `LDM/STM`; extract from `[#imm]` or `=imm`.
* Respect `dry_run` & `ENABLE_WRITES=false`.
* **DoD:** Unit tests show reduced false positives; contract schema `mmio_annotate.v1.json` satisfied. _commit: 641ecf7_
* **Run:** `python -m pytest -q bridge/tests/unit/test_mmio_heuristics.py`

  What changed: Filtered MMIO counts to immediate load/stores and added targeted heuristics tests.

### 7) ✅ SCHEMA-STRICT — Enforce schemas & envelope (ID: SCHEMA-STRICT)

* All HTTP endpoints & MCP tools return `{ok, data|null, errors[]}` with `additionalProperties:false`.
* Negative tests (fehlende Felder) → 400 + envelope.
* **DoD:** `tests/contract/test_schemas.py` passes for all `/api/*.json`.
* *commit:* 2ed15d3*
* **Run:** `python -m pytest -q bridge/tests/contract/test_schemas.py`

### 8) ✅ OBS-LIMITS — Observability & limits (ID: OBS-LIMITS)

* Add `request_scope` metrics (request_id, timings, counters) + structured logs.
* Enforce `GHIDRA_MCP_MAX_WRITES_PER_REQUEST`, `GHIDRA_MCP_MAX_ITEMS_PER_BATCH`, timeouts.
* Audit JSONL when writes enabled (old→new name, comment diff, verify result).
* **DoD:** `tests/obs/test_limits_and_audit.py` green; sample audit file created in tmp. _commit: 08d9bd3_
* **Run:** `python -m pytest -q bridge/tests/obs/test_limits_and_audit.py`

  What changed: Added observability tests, wired request scopes to config-driven limits, and verified JT audit trail output.

### 9) ⬜ LEGACY-PARITY — Legacy API unchanged (ID: LEGACY-PARITY)

* Golden tests for selected legacy routes + shell probe.
* **DoD:** Golden + probe green; no response drift.
* **Run:** `python -m pytest -q bridge/tests/golden/test_legacy_apis.py && scripts/probe_legacy.sh`

### 10) ⬜ CI-TESTS — Gate builds on tests (ID: CI-TESTS)

* Extend GitHub Actions: run unit + contract + golden before Maven packaging.
* **DoD:** Workflow fails on schema drift; artifact only on green.
* **Run:** (via CI)

### 11) ⬜ DOCS-BOOTSTRAP — Developer docs & scripts (ID: DOCS-BOOTSTRAP)

* README Quickstart: Ports (`8081` Shim API, `8099` SSE), `/api/health.json`, curl examples.
* Add `bin/smoke.sh`.
* **DoD:** Fresh machine can follow README to green smoke.
* **Run:** `bin/smoke.sh`

### 12) ⬜ CONTROL-FILES — Orchestrating Codex runs (ID: CONTROL-FILES)

* Maintain `/.plan/tasks.manifest.json` order; **UTF-8 fix** for „→“.
* Keep `/.plan/state.json` in sync (siehe Task 0).
* **DoD:** Tests assert UTF-8 & sync; Codex follows the manifest sequence.
* **Run:** `python -m pytest -q bridge/tests/plan/test_manifest_and_state.py`

### 13) ⬜ OPTIONAL-ADAPTERS — x86/MIPS/RISCV (ID: OPTIONAL-ADAPTERS)

* Add adapters + tests after core stabilisiert.
* **DoD:** Adapter tests & docs.

