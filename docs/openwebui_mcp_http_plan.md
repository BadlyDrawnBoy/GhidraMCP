# OpenWebUI MCP/HTTP Integration & Refactor Tracker

This document restates the full bridge refactor brief, adds the OpenWebUI-specific requirements that surfaced during code review, and records the current completion status. It should guide follow-up work until the deterministic bridge fully replaces the monolithic `bridge_mcp_ghidra.py` entry point.

---

## 1. Scope & Goals (recap)

- Preserve every legacy MCP tool and HTTP route exposed by `bridge_mcp_ghidra.py`.
- Add deterministic composite endpoints (`jt_*`, `string_xrefs_compact`, `mmio_annotate_compact`) with strict JSON schemas and a shared `{ok,data,errors}` envelope.
- Separate the bridge into layers: adapters, whitelisted Ghidra client, feature logic, and API wrappers (MCP tools + HTTP routes).
- Keep the Ghidra Java plugin unchanged; all behavior lives in Python.
- Enforce testability through unit, contract, and golden tests with mocks for Ghidra interactions.
- Ensure all write paths are gated behind `ENABLE_WRITES` (default `false`) and per-request `dry_run` flags.

**Status:** Partially implemented. The new `bridge/` package reflects the layered architecture, but the legacy entry point still drives production traffic and no feature flags or parity tests exist yet.

---

## 2. Target Module Layout & Dependency Rules

```
bridge/
├─ app.py                 # ASGI + FastMCP wiring
├─ adapters/              # Architecture adapters (ARM/Thumb + fallback)
├─ ghidra/                # Whitelisted HTTP client + models
├─ features/              # JT, strings, MMIO feature logic
├─ api/                   # MCP tools, HTTP routes, schemas, validators
├─ utils/                 # Errors, hex helpers, logging, JSON extraction
└─ tests/                 # unit/, contract/, golden/
```

- `features/*` may depend on `ghidra/*`, `adapters/*`, and `utils/*` only.
- `api/*` may depend on `features/*` but never the other way around.
- `app.py` imports strictly from `api/*`.

**Status:** Implemented for the scaffolding that landed in the repository. The package structure matches the diagram, yet the `tests/` tree currently contains only `unit/test_adapters_arm_thumb.py`, leaving contract and golden tests outstanding.【F:bridge/tests/unit/test_adapters_arm_thumb.py†L1-L41】

---

## 3. Public API Expectations

### 3.1 MCP Tools

- `jt_slot_check`
- `jt_slot_process`
- `jt_scan`
- `string_xrefs_compact`
- `mmio_annotate_compact`

All tools must return the shared envelope and validate against their JSON schema before responding.

### 3.2 HTTP Routes

- `POST /api/jt_slot_check.json`
- `POST /api/jt_slot_process.json`
- `POST /api/jt_scan.json`
- `POST /api/string_xrefs.json`
- `POST /api/mmio_annotate.json`

### 3.3 Shim routes for OpenWebUI

- Preserve `/openapi.json`, `/health`, `/sse`, `/messages`, and `/messages/` exactly as today’s Starlette shim exposes them. The trailing-slash alias is mandatory so existing OpenWebUI deployments keep working.

**Status:** New MCP tools and HTTP routes are registered inside `bridge/api/tools.py` and `bridge/api/routes.py`, but they are not yet wired into the production server because `bridge_mcp_ghidra.py` still mounts the monolithic handlers. The legacy shim and routes remain in the old script and have not been extracted into the new package.

---

## 4. JSON Schemas & Validation

- Schemas live in `bridge/api/schemas/` with versions suffixed `.v1.json` and `additionalProperties:false` everywhere.
- Envelope schema defines `errors[]` items with `{code,message,details?}`.
- Validators cache compiled schemas for performance.

**Status:** Implemented. All schemas exist and the validator helper loads them on demand. Enforcement still depends on routing the production endpoints through the new API layer.

---

## 5. Feature Logic Requirements

### 5.1 Jump Tables (`features/jt.py`)

- `slot_check` performs address math, range checks, sentinel detection, and ARM/Thumb probing via adapters.
- `slot_process` orchestrates optional rename/comment writes, respecting feature flags and verifying the results.
- `scan` aggregates multiple slot checks and builds a summary.

### 5.2 Strings (`features/strings.py`)

- `xrefs_compact` fetches callers via `get_xrefs_to`, providing concise context (e.g., argument index or format hints) with strict limits.

### 5.3 MMIO (`features/mmio.py`)

- `annotate` scans disassembly for read/write/toggle patterns, summarises bitwise operations, and performs optional comment writes when `dry_run=False` and `ENABLE_WRITES` permits writes.

**Status:** Jump-table and MMIO helpers now deliver the planned analysis. MMIO annotations classify reads/writes/toggles, capture bitwise summaries, and verify optional disassembly comments under the shared feature flag. String helpers still need richer caller context to meet the roadmap.【F:bridge/features/mmio.py†L18-L196】【F:tests/test_mmio.py†L1-L80】

---

## 6. Architecture Adapters

- Provide `in_code_range`, `is_instruction_sentinel`, and `probe_function` for ARM/Thumb.
- Supply a fallback adapter that only enforces range checks.

**Status:** Implemented. `bridge/adapters/arm_thumb.py` and `bridge/adapters/fallback.py` expose the planned interfaces and are covered by the existing unit test.

---

## 7. Ghidra HTTP Client & Whitelist

- Implement `safe_get`/`safe_post` wrappers, read helpers, and endpoint alias resolution so the client remains compatible with multiple plugin versions.
- Maintain a whitelist that enumerates logical operation keys instead of raw URLs.

**Status:** Partially implemented. The new client centralizes HTTP calls, retries, and alias resolution, but the whitelist still lists literal endpoints and needs to align with logical operation keys. Additional negative tests are required to ensure forbidden calls are blocked.

---

## 8. Error Handling & Envelope

- Define canonical error codes: `ARM_INSTRUCTION`, `OUT_OF_RANGE`, `NO_FUNCTION_AT_TARGET`, `TOOL_BINDING_MISSING`, `WRITE_DISABLED_DRY_RUN`, `WRITE_VERIFY_FAILED`.
- Ensure every API response wraps data or errors in the shared envelope.

**Status:** Implemented for the new modules. Legacy entry points still bypass the envelope until they are migrated.

---

## 9. Observability & Limits

- Add structured logging (request IDs, timings, write counts, errors).
- Enforce `MaxWritesPerRequest`, `MaxItemsPerBatch`, and reasonable timeouts/rate limits.

**Status:** Logging helpers exist (`bridge/utils/logging.py`), but request-scoped logging, rate limits, and counters have not been hooked up in the feature modules.

---

## 10. Testing Roadmap

- **Unit tests:** adapters, JT edge cases, string context extraction, MMIO analysis, and whitelist enforcement.
- **Contract tests:** schema validation for each API endpoint.
- **Golden tests:** snapshot legacy outputs for parity checks during migration.
- **Integration tests:** mocked Ghidra server covering happy and failure paths.

**Status:** Only `test_adapters_arm_thumb.py` exists today. All other unit, contract, golden, and integration suites remain to be written.【F:bridge/tests/unit/test_adapters_arm_thumb.py†L1-L41】

---

## 11. Migration Sequence & Current Progress

| Step | Plan | Progress |
| ---- | ---- | -------- |
| 0 | Inventory legacy APIs, capture golden outputs, introduce `ENABLE_WRITES` flag | Not started. No feature flag or snapshots in repo. |
| 1 | Extract adapters and whitelisted client | **Done** (see `bridge/adapters/*`, `bridge/ghidra/client.py`). |
| 2 | Implement JT features (read-only, then writes) | Mostly complete; write verification still needs feature flags and integration tests. |
| 3 | Expose new MCP tools and HTTP routes | Implemented in `bridge/api/*`, but not mounted by the production entry point yet. |
| 4 | Add schemas and validators | **Done**. |
| 5 | Implement strings & MMIO features | Strings partial, MMIO placeholder. |
| 6 | Migrate `bridge_mcp_ghidra.py` to new modules, keeping CLI/shim parity | Not started; monolithic script untouched. |

---

## 12. Acceptance Criteria Checklist

- [ ] Legacy MCP tools/routes yield byte-identical responses (parity tests in place).
- [ ] New endpoints validate against strict schemas in production.
- [ ] Deterministic JT handling for instruction words and verified writes behind flags.
- [ ] Whitelist prevents forbidden Ghidra calls, including regression tests.
- [ ] Structured logs capture request IDs, timings, and write audits.
- [ ] Unit test coverage ≥80% for `features/*`; contract suite 100% green.

---

## 13. OpenWebUI-Specific Follow-Ups

### Shim extraction
- Create `bridge/shim.py` (name TBD) that re-hosts the current Starlette routes while preserving headers, status codes, and SSE streaming semantics.
- Mount both shim and deterministic API inside the same ASGI application so OpenWebUI and deterministic clients coexist.
- Validate `/openapi.json`, `/sse`, `/messages`, and `/messages/` manually or with regression tests after the move.

### CLI delegation
- Keep `bridge_mcp_ghidra.py` as the CLI surface, but delegate its argparse handling to a new module (e.g., `bridge.cli`).
- Preserve all existing flags (`--transport`, `--mcp-host`, `--mcp-port`, `--shim-host`, `--shim-port`, `--ghidra-server`, `--debug`) and environment overrides such as `GHIDRA_SERVER_URL`.
- Mirror the current SSE vs. stdio launch behavior by spinning up the FastMCP SSE server thread and shim host when requested.

### Endpoint alias resolver
- Ensure the new `GhidraClient` exposes logical endpoint names, caching resolved URLs much like today’s `ENDPOINT_CANDIDATES` map.
- Keep the whitelist aligned with the logical aliases so future plugin releases with renamed endpoints remain compatible.
- Add tests that exercise multiple candidate URLs to confirm caching works and forbidden endpoints are rejected.

---

## 14. Next Actions

1. Extract the shim and CLI wiring into the new package while keeping legacy behavior intact.
2. Introduce the `ENABLE_WRITES` flag and wrap write operations in JT/MMIO features with the proper gating.
3. Flesh out `features/mmio.py` and enhance string context extraction per the plan.
4. Mount the new MCP/HTTP API from `bridge/app.py` inside the production server and run parity tests against the legacy paths.
5. Build the promised unit, contract, and golden test suites before removing the monolithic logic.

Maintaining this tracker as implementation progresses will help ensure the migration stays aligned with the original brief and that OpenWebUI clients continue to function throughout the transition.
