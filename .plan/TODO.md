# Codex Session Protocol (read this first, every run)

**This file is the single source of truth.** One task per run. Always **read _and_ update this file** and keep `/.plan/state.json` in sync.

**How to work**
1. Open `/.plan/TODO.md` and `/.plan/tasks.manifest.json`. **Follow the order** from the manifest’s `sequence`/`after` (or the order here if the manifest is absent).
2. Pick the **first** task still ⬜️ (todo). If the code already satisfies the DoD, mark ✅ with a one‑line note and short commit.
3. Implement **only** what this task’s DoD requires. Keep changes **non‑breaking**. No repo‑wide refactors unless the task explicitly says so.
4. Run the tests shown by this task (example: `python -m pytest -q ...`).
5. Commit **atomically** with message: `TASK_ID: short summary` (e.g. `SCHEMA-STRICT: enforce JSON envelopes`).
6. Update this file: change ⬜️ → ✅ (or ⛔ with a one‑line reason), add the **short SHA** right on the DoD line `_commit:af974cb_`, and add a 1–3 line “What changed”.
7. Also update `/.plan/state.json` by running `/.plan/sync_state.sh` (task status, `commit`, `updated_at`).
8. Reply with a **final run report**: task id, commit SHA, touched files, 1–3 line summary, and the exact test command that passed.

**Do not** reformat the repo, rename modules, or modify other tasks. One task per run, then stop.

---

## -1) ✅ OPENAPI-FREEZE — Guard OpenAPI snapshot (ID: OPENAPI-FREEZE)
**DoD:** Add golden snapshot + drift test for `/openapi.json`; README documents `UPDATE_SNAPSHOTS`. _commit:af974cb_
**What changed:** Snapshot `/openapi.json`, guard drift in golden test, and document update flag.

## 0) ☑ SYNC-STATE — Keep plan files in lockstep (ID: SYNC-STATE)
Mirror task status and short SHA from `/.plan/TODO.md` → `/.plan/state.json`. A tiny check ensures mismatch fails.
**DoD:** _commit:af974cb_ `python -m pytest -q tests/plan/test_state_sync.py` green.

---

## 1) ✅ API-MOUNT — Deterministic routes & MCP tools (ID: API-MOUNT)
**DoD:** `GET /openapi.json` 200; `POST /api/jt_slot_check.json` returns envelope. _commit:af974cb_
**What changed:** Routes mounted; integration test proves OpenAPI & envelope.

## 2) ✅ CLIENT-UNIFY — Single client + whitelist (ID: CLIENT-UNIFY)
**DoD:** Unit tests prove allow/deny surface (cached alias resolver). _commit:af974cb_
**What changed:** Shared client + whitelist; alias cache tests.

## 3) ✅ RANGE-CONTRACT — Enforce `[code_min, code_max)` (ID: RANGE-CONTRACT)
**DoD:** Upper‑bound off‑by‑one covered by tests. _commit:af974cb_
**What changed:** Adapters and tests treat upper bound as exclusive.

## 4) ✅ JT-VERIFY — Strict ARM/Thumb READ→VERIFY (ID: JT-VERIFY)
**DoD:** Instruction sentinel, OOR, valid ARM, valid Thumb. _commit:af974cb_
**What changed:** Probe + verify via disassembly/metadata; treat `0xE12FFF1C` as ARM sentinel.

## 5) ✅ JT-SCAN — Read‑only batch (ID: JT-SCAN)
**DoD:** 16‑slot contract passes; `summary.total == len(items)`. _commit:af974cb_
**What changed:** Batch `jt_scan` aggregates slot checks with accurate summary.

## 6) ✅ MMIO-HEUR — Precise MMIO heuristics (ID: MMIO-HEUR)
**DoD:** Unit tests show reduced false positives; request schema satisfied. _commit:af974cb_
**What changed:** Count only LDR/STR immediates; honor `dry_run` and `ENABLE_WRITES=false`.

## 7) ✅ SCHEMA-STRICT — Enforce schemas & envelope (ID: SCHEMA-STRICT)
**DoD:** `bridge/tests/contract/test_schemas.py` passes for all `/api/*.json`. _commit:af974cb_
**What changed:** Strict `{ok,data|null,errors[]}` envelopes with `additionalProperties:false`; invalid payloads → 400.

## 8) ✅ OBS-LIMITS — Observability & limits (ID: OBS-LIMITS)
**DoD:** `tests/obs/test_limits_and_audit.py` green; audit JSONL created under limits. _commit:af974cb_
**What changed:** `request_scope` metrics, write/batch/time limits, and audit when writes enabled.

## 9) ✅ LEGACY-PARITY — Legacy shim unchanged (ID: LEGACY-PARITY)
**DoD:** Golden + probe script green; no response drift. _commit:af974cb_
**What changed:** Golden snapshots & shell probe for legacy endpoints.

## 10) ✅ CI-TESTS — Gate builds on tests before packaging (ID: CI-TESTS)
**Goal:** CI must run unit + contract + golden tests **before** Maven packaging. Artifact is produced **only on green**.
**DoD:** CI workflow shows tests gating packaging on a PR. Include caching and Python setup. _commit:af974cb_
**Run:** via CI on PR.
**Steps:**
- Ensure workflow runs `python -m pytest -q bridge/tests/unit bridge/tests/contract bridge/tests/golden` before the Maven build.
- Fail the job on test or schema drift; upload artifacts only if tests pass.
**What changed:** GitHub Actions installs cached Python deps, runs the unit/contract/golden suites ahead of Maven, and requires the test job to succeed before packaging.

## 11) ✅ DOCS-BOOTSTRAP — Developer quickstart & smoke (ID: DOCS-BOOTSTRAP)
**Goal:** New machine → green smoke in minutes.
**DoD:** README quickstart (ports: `8081` shim, `8099` SSE; `/api/health.json`), `.env.sample`, and `bin/smoke.sh` that hits health + a sample POST. _commit:af974cb_
**Run:** `bin/smoke.sh`
**Steps:**
- Expand README with venv steps, server flags, curl examples, and troubleshooting.
- Provide `bin/smoke.sh` to: start server (if not running), `GET /api/health.json`, and one deterministic POST (e.g., `jt_slot_check`).
**What changed:** Quickstart now calls out shim/SSE ports and points smoke.sh at `/api/health.json` for the sanity check.

## 12) ✅ CONTROL-FILES — Orchestrate Codex sessions (ID: CONTROL-FILES)
**Goal:** Make plan files authoritative and self‑healing.
**DoD:** Tests assert manifest UTF‑8 correctness and `.plan/state.json` sync; Codex follows `tasks.manifest.json` order. _commit:a74a426_
**Run:** `python -m pytest -q bridge/tests/plan/test_manifest_and_state.py`
**Steps:**
- **Fix UTF‑8** in `/.plan/tasks.manifest.json` (e.g., `READ→VERIFY`).
- Add a small test that fails if `.plan/TODO.md` and `.plan/state.json` disagree on any task’s `status`/`commit`.
- Keep `/.ci/AGENT_LOCK` up to date (`expires_at` in the future, correct `branch`).
**What changed:** Extended manifest/state test to execute `bin/plan_check.py` and refreshed the agent lock.

## 13) ✅ OPTIONAL-ADAPTERS — x86/MIPS/RISCV (ID: OPTIONAL-ADAPTERS)
**Goal:** Add additional architecture adapters once the core is stable.
**DoD:** Adapter unit tests & brief docs. _commit:af974cb_
**Run:** `python -m pytest -q bridge/tests/unit/test_adapters_*.py`
**What changed:** Added an optional x86 adapter stub with lazy registry + env flag, unit coverage, and README docs.

### 14) ✅ WRITE-GUARDS — Writes disabled/enabled behave correctly (ID: WRITE-GUARDS)
**Goal:** Prove that write-capable endpoints honor `ENABLE_WRITES`/`dry_run`.
**Scope:** `jt_slot_process`, `mmio_annotate` (and any other write path).
**DoD:** _commit:af974cb_
- With `ENABLE_WRITES=false` or `dry_run=true`: no write attempts; response is 200 with deterministic envelope and an explanatory note.
- With `ENABLE_WRITES=true` & `dry_run=false`: write path is exercised; audit/log hook is hit (if present).
**Run:** `python -m pytest -q bridge/tests/unit/test_write_guards.py`
**Notes:** Add explicit unit tests using env patching/fixture; do not enable writes by default.
**What changed:** Added assertions ensuring dry-run or writes-disabled flows never invoke `record_write_attempt`, while the enabled path still records both rename and comment attempts.

### 15) ✅ SSE-HANDSHAKE — Minimal /sse stream health (ID: SSE-HANDSHAKE)
**Goal:** Catch wiring regressions the in-process registration can’t see.
**DoD:** Async test connects to `/sse` and receives at least one valid event frame (heartbeat or welcome). Clean shutdown. _commit:af974cb_
**Run:** `python -m pytest -q bridge/tests/integration/test_sse_handshake.py`
**What changed:** Added an ASGI-level integration test that drives the FastMCP SSE app and asserts the endpoint event frame.

### 16) ✅ JT-SCAN-CONSISTENCY — Hard invariants asserted (ID: JT-SCAN-CONSISTENCY)
**Goal:** Guard against accidental summary drift or snapshot-only coverage. _commit:af974cb_
**DoD:** Contract test asserts `summary.total == len(items)` and `summary.valid + summary.invalid == summary.total` for representative payloads.
**Run:** `python -m pytest -q bridge/tests/contract/test_jt_scan_consistency.py`
**What changed:** Added dedicated contract coverage over multiple `jt_scan` payloads to assert the summary invariants.

### 17) ✅ STRINGS-ASSERTS — Stronger verification on xref flow (ID: STRINGS-ASSERTS)
**Goal:** Ensure the strings feature actually respects client limits and disassembly paths.
**DoD:** Unit test asserts recorded `last_limit` and `disasm_calls` on the dummy client match expected values. _commit:af974cb_
**Run:** `python -m pytest -q bridge/tests/unit/test_strings_asserts.py`
**What changed:** Added focused unit coverage to record forwarded limits and invoked disassembly addresses.

### 18) ✅ SNAPSHOT-SAFEGUARD — Non-golden guard rails (ID: SNAPSHOT-SAFEGUARD)
**Goal:** Prevent “green by snapshot update”.
**DoD:** Add a small set of non-snapshot contract assertions for key endpoints (status code, envelope shape, critical counters) that must pass even when golden updates are allowed. _commit:af974cb_
**Run:** `python -m pytest -q bridge/tests/contract/test_safeguards.py`
**What changed:** Added snapshot-independent contract tests that assert envelope shape and key counters for critical endpoints.

### 19) ⬜ PLAN-CHECK — Single-script plan consistency + CI (ID: PLAN-CHECK)
**Goal:** Keep `/.plan/TODO.md`, `/.plan/state.json`, and `/.plan/tasks.manifest.json` in lockstep—without test bloat.
**DoD:**
- Add `bin/plan_check.py` (Stdlib only) to verify IDs, status mapping (✅/⬜/⛔ → done/todo|in-progress/blocked), and UTF‑8 (no `→`).
- Add a tiny CI job `.github/workflows/plan-check.yml` running `python3 bin/plan_check.py` on PRs touching `.plan/**`.
**Run:** `python3 bin/plan_check.py`

### 20) ✅ DEVSERVER-ENTRYPOINT — Provide uvicorn entrypoint (ID: DEVSERVER-ENTRYPOINT)
**DoD:** `uvicorn bridge.app:app` or `uvicorn bridge.app:create_app --factory` serves a Starlette app; integration test ensures `/openapi.json`. _commit:af974cb_
**Run:** `python -m pytest -q bridge/tests/integration/test_server_entrypoint.py`; `bash bin/smoke.sh`
**What changed:** Added Starlette factory/instance entrypoint and OpenAPI route, plus integration coverage exercising `/openapi.json`.

### 21) ✅ README-LEGACY-MAP — Legacy map & quickstart (ID: README-LEGACY-MAP)
**DoD:** README documents mapping between legacy objects and new deterministic endpoints; quickstart reaches shim + sample request in ≤3 commands. _commit:af974cb_
**What changed:** Added "Legacy ↔ Bridge mapping" section outlining envelopes, batching, and write guards, and rewrote the quickstart with a three-command flow.

### 22) ✅ STRINGS-COMPACT — Compact strings/xrefs (ID: STRINGS-COMPACT)
**DoD:** Provide a compact, token-friendly variant of the strings/xrefs feature that keeps determinism but minimizes payload size. Unit tests prove stable envelope/fields and a size bound; a contract test verifies deterministic ordering and invariants. README gets a Legacy ↔ Bridge row for the compact variant. _commit:af974cb_
**What changed:** Added `/api/strings_compact.json` with deterministic ordering plus schema/tests, and documented the compact mapping in README.
**Test:**
    python -m pytest -q bridge/tests/unit/test_strings_compact.py
    python -m pytest -q bridge/tests/contract/test_strings_compact_contract.py
    python3 bin/plan_check.py

### 23) ✅ SEARCH-STRINGS-ENDPOINT — Dedicated endpoint for searching all strings (ID: SEARCH-STRINGS-ENDPOINT)
**Goal:** Avoid information loss by searching the complete set of strings on the Ghidra side *before* applying pagination. This fixes a critical flaw where filtering only happens on a limited page of results.
**DoD:** _commit:cf6f65e_
- A new endpoint `/api/search_strings.json` and a corresponding MCP tool `search_strings` are created.
- The endpoint requires a `query` parameter and supports optional `limit` and `offset` for the *results*.
- The implementation calls the Java plugin's `/strings` endpoint, passing the `query` as the `filter` URL parameter.
- The response payload must include pagination metadata: `query`, `total_results`, `page`, and `limit`, in addition to the `items` list. This enables the LLM to make informed decisions about refining its search.
- New JSON schemas (`search_strings.request.v1.json` and `search_strings.v1.json`) are created and used for validation.
- Contract and schema tests are added to ensure the endpoint works as expected.
**Run:** `python -m pytest -q bridge/tests/contract/test_string_search.py`

**What changed:** Added `/api/search_strings.json`, Ghidra fetcher, MCP tool, schemas, and pagination-aware contract coverage.

### 24) ⬜ SEARCH-FUNCTIONS-ENDPOINT — Dedicated endpoint for searching functions (ID: SEARCH-FUNCTIONS-ENDPOINT)
**Goal:** Expose the existing server-side search for functions through a deterministic endpoint with informed pagination.
**DoD:**
- A new endpoint `/api/search_functions.json` and a corresponding MCP tool `search_functions` are created.
- The endpoint requires a `query` parameter and supports optional `limit` and `offset`.
- It calls the Java plugin's `/searchFunctions` endpoint.
- The response payload must include pagination metadata: `query`, `total_results`, `page`, and `limit`, in addition to the `items` list of function objects.
- New JSON schemas (`search_functions.request.v1.json` and `search_functions.v1.json`) are created and used for validation.
- Contract and schema tests are added to verify the functionality.
**Run:** `python -m pytest -q bridge/tests/contract/test_function_search.py`

### Notes for the current run
- If a task is already implemented, still write the short “What changed” line and attach the short SHA.
- Keep **all** responses deterministic: never return fields outside the schema, always wrap in the standard envelope.
- When writes are disabled, ensure write endpoints enforce `dry_run:true` and return a specific error otherwise.
