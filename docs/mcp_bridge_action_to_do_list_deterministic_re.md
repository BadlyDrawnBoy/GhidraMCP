# MCP Bridge – Action To‑Do List (Deterministic RE)

> **Purpose:** Concrete, actionable backlog for the Coding Agent. Focus: **bridge‑only**, deterministic composite endpoints, **non‑breaking** to the existing API, **test‑driven**.

---

## Legend

- ⬜️ open · 🟨 in progress · ✅ done
- **DoD** = Definition of Done

---

## 00) Agent bootstrap (project discovery)

1. ⬜️ **Discover runtime & entrypoint**
   - Identify Python version and dependency manager; locate server entrypoint (script or ASGI app) and document how to run it locally.
   - **DoD:** README section "Local Run" with exact commands; confirmed server boots.
2. ⬜️ **Environment variables & configuration**
   - Enumerate required env vars (e.g., upstream Ghidra HTTP base URL, ports, timeouts); create `.env.sample`.
   - **DoD:** `.env.sample` committed; README documents each variable.
3. ⬜️ **Health & smoke checks**
   - Add/verify a simple health route or MCP tool (ping upstream, version); provide curl example.
   - **DoD:** `curl` smoke test works against local server.
4. ⬜️ **Test harness**
   - Ensure `pytest` (or chosen runner) executes unit/contract suites; document how to run.
   - **DoD:** `pytest -q` (or equivalent) documented; baseline test run passes.
5. ⬜️ **Single‑branch PR setup**
   - Create feature branch and draft PR scaffolding; add `.ci/AGENT_LOCK` policy description.
   - **DoD:** PR description contains checklist & policy; lock file semantics documented.

## 0) Non‑breaking & parity (immediately)

1. ⬜️ **Inventory legacy APIs** (all existing MCP tools/routes with signature + example response)
   - **DoD:** Appendix A list complete and versioned in the repo.
2. ⬜️ **Golden snapshots** for legacy tools (contract tests)
   - **DoD:** Tests green; any behavioral change fails CI.
3. ⬜️ **Feature flag **`` (default `false`) + `dry_run:true` as request default
   - **DoD:** All write‑capable paths honor the flag & parameter.

---

## 1) API wiring (enable deterministic endpoints)

4. ⬜️ **Mount routes**: `/api/jt_slot_check.json`, `/api/jt_slot_process.json`, `/api/jt_scan.json`, `/api/string_xrefs.json`, `/api/mmio_annotate.json`
   - **DoD:** Server startup log shows mounted paths; curl probe returns a schema‑validated envelope JSON.
5. ⬜️ **Register MCP tools**: `jt_slot_check`, `jt_slot_process`, `jt_scan`, `string_xrefs_compact`, `mmio_annotate_compact`
   - **DoD:** Tools visible in capability listing; round‑trip returns an envelope.
6. ⬜️ **Enable schema validator** (server‑side, `additionalProperties:false`)
   - **DoD:** Invalid payloads → 400/error envelope; valid → 200/`ok:true`.

---

## 2) JT path (READ→VERIFY)

7. ⬜️ **Tighten ARM/Thumb adapter** (READ→VERIFY)
   - `probe_function(ptr)` → disassemble + optionally `ptr-1` (Thumb)
   - Always **verify** via `get_function_by_address`/disasm before marking as valid
   - **DoD:** Unit tests: instruction word → `ARM_INSTRUCTION`; out‑of‑range → error; valid start → ARM/Thumb correct.
8. ⬜️ **Unify range contract** (`[code_min, code_max)`)
   - **DoD:** Code + docs + tests consistent; off‑by‑one cases covered.
9. ⬜️ ``** write→verify**
   - Write only on definite function start; max 2 writes; verify after
   - **DoD:** Unit & contract tests green; writes appear in audit log.
10. ⬜️ **Batch **``
    - Sequential `slot_check`; `summary.total == items.length`
    - **DoD:** Contract test with 16 slots incl. mixed cases.

---

## 3) Strings & MMIO

11. ⬜️ ``** compact**
    - `get_xrefs_to` + small context (callsite/arg hint), honor limit
    - **DoD:** Contract test; large lists truncated; `count` correct.
12. ⬜️ ``** heuristics**
    - Count only `LDR`/`STR`; exclude `LDM/STM`; extract targets from `[#imm]`/`=imm` reliably
    - **DoD:** Unit tests for LDM/STM/indirect; lower false‑positive rate.

---

## 4) HTTP client & resolver

13. ⬜️ **POST alias resolver** (mirrors GET behavior)
    - Resolve varying plugin endpoints; cache
    - **DoD:** Negative tests (older alias names) pass.
14. ⬜️ **Finalize whitelist client**
    - **Allowed:** `read_dword`, `disassemble_function`, `get_function_by_address`, `get_xrefs_to`, `rename_function_by_address`, `set_*comment`
    - **Forbidden:** `read_bytes`, `read_cstring`, all `list_*`, `search_*`, `confirm:true`
    - **DoD:** Attempting forbidden calls yields a defined error code; tests green.

---

## 5) Observability & limits

15. ⬜️ ``** everywhere** (MCP tools & HTTP)
    - Timings (read/disasm/verify), rate‑limit, MaxWrites=2, MaxItems=256
    - **DoD:** Structured logs with `request_id` + counters; visible in smoke test.
16. ⬜️ **Write audit log**
    - old→new name, comment diff, verify result
    - **DoD:** One audit entry per successful write.

---

## 6) Tests & QA (extended)

17. ⬜️ **Golden files** for typical JT cases
    - instruction word, out‑of‑range, valid ARM, valid Thumb
    - **DoD:** Strict golden diffs.
18. ⬜️ **Contract suite** for all new endpoints
    - Envelope, `additionalProperties:false`, field types, limits
    - **DoD:** CI fails on schema drift.
19. ⬜️ **Integration (mocked Ghidra)**
    - happy/edge/fail; timeouts
    - **DoD:** Reproducible mocks; time budgets respected.

---

## 7) Orchestrator path (no LLM)

20. ⬜️ **Parse‑only aggregator**
    - Extract first balanced `{…}`, JSON‑parse, schema‑check, build aggregate
    - **DoD:** NON\_JSON/INVALID\_SCHEMA → `ok:false` items; `summary` correct.
21. ⬜️ **No context carry‑over**
    - Each task runs without history; deterministic behavior
    - **DoD:** E2E test: subagent chatter does not leak into the aggregate.

---

## 8) Docs & ops

22. ⬜️ **Update README**
    - Bridge‑only approach, new endpoints, schemas, flags, limits, examples
    - **DoD:** Consistent project page; reproducible quickstart.
23. ⬜️ **Release checklist**
    - Schema versioning (`…v1`), changelog, rollback path
    - **DoD:** Tag/release includes artifacts & migration notes.

---

## 9) Optional (later)

24. ⬜️ **Additional ArchAdapters** (x86/MIPS/RISC‑V)
25. ⬜️ **LLM layer (separate, small)**: naming/ranking → tiny JSON, no tools, `temperature=0`.

---

## Dependencies / order

- **Start:** 0 → 1 → 2 (7/8/9/10) → 3 → 4 → 5 → 6 → 7 → 8
- **Quick wins:** 4 (mount routes/tools), 7/8 (probe/range), 13 (POST alias), 20 (parse‑only aggregator).

---

## Acceptance criteria (cross‑cutting)

- Legacy parity guaranteed (golden tests).
- Each new route/tool returns **exactly one envelope JSON**; strict schemas; deterministic outputs.
- Write paths are guarded by flag/param; write→verify is mandatory.
- Forbidden list enforced; observability & limits active.

---

## Execution & PR strategy for the Coding Agent (single PR, sequenced tasks)

### Goals

- You can hand over **many tasks at once** without creating PR chaos.
- The agent executes them **in order**, on **one feature branch**, producing **one evolving PR**.

### Policy

1. **Single feature branch:** `feature/deterministic-bridge` (created once).
2. **Single PR:** Open a **draft PR** targeting `main`. The agent **must never** open additional PRs. All pushes update this PR.
3. **Task manifest:** Put a repo file `/.plan/tasks.manifest.json` listing tasks in order with IDs and dependencies, e.g.:
   ```json
   {"version":1,"sequence":[
     {"id":"NB-INV","title":"Inventory legacy APIs"},
     {"id":"API-MOUNT","title":"Mount deterministic routes","after":["NB-INV"]},
     {"id":"JT-VERIFY","title":"ARM/Thumb read→verify","after":["API-MOUNT"]}
   ]}
   ```
4. **Workspace lock:** The agent creates `.ci/AGENT_LOCK` with a TTL. If a lock exists and is fresh, abort. Prevents concurrent runs.
5. **Drift check per task:** Before each task: `git fetch --all`, rebase `feature/deterministic-bridge` on latest PR base; if conflicts, the agent stops and reports.
6. **Idempotent tasks:** Each task checks current state first (e.g., route already mounted? schema already present?) and **no‑ops** if done.
7. **Atomic commits:** One commit per task with prefix (`JT-VERIFY: …`). Avoid partial file edits spanning multiple tasks.
8. **Update PR body checklist:** The agent maintains a task checklist in the PR description, ticking items as they pass.
9. **CI gates:** Each task ends with unit/contract tests; the agent pushes only if tests pass locally.
10. **No multi‑branch fan‑out:** Absolutely no branching per task; always the same branch.
11. **Squash merge:** When done, merge the PR with **squash**; tag release.
12. **Artifacts:** Store golden files and schema versions in the PR under `/tests/golden/` and `/api/schemas/`.

### Definition of Done for the PR

- All tasks in `tasks.manifest.json` are checked off in the PR body.
- CI is green; one squash merge; release tag published.

### Why this avoids the “telephone game”

- Single branch + PR keeps a **single source of truth**.
- Lock + drift checks prevent parallel runs fighting each other.
- Idempotent tasks + manifest allow safe re‑runs.

