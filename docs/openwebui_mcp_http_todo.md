# OpenWebUI MCP HTTP Refactor – Status & To-Do

## Completed so far
- [x] Modular bridge package with reusable FastMCP server wiring and Starlette route factory scaffolded in `bridge/app.py`.【F:bridge/app.py†L1-L36】
- [x] Deterministic HTTP routes and MCP tools implemented with schema validation wrappers for the jump-table, string, and MMIO workflows.【F:bridge/api/routes.py†L1-L139】【F:bridge/api/tools.py†L1-L136】
- [x] Strict JSON schemas (`*.v1.json`) added for every new envelope payload, enforcing `additionalProperties:false`.【F:bridge/api/schemas/jt_slot_check.v1.json†L1-L27】
- [x] ARM/Thumb adapter unit coverage landed, verifying range checks, sentinel detection, and probe behavior.【F:bridge/tests/unit/test_adapters_arm_thumb.py†L1-L24】
- [x] `features/strings.xrefs_compact` now enriches caller context with argument indices, call hints, and sanitized snippets, with unit coverage validating the behavior.【F:bridge/features/strings.py†L1-L172】【F:bridge/tests/unit/test_strings_feature.py†L1-L98】

## Outstanding work
- [x] Add the `ENABLE_WRITES` feature flag (default `false`) and enforce it across JT/MMIO write paths alongside the existing `dry_run` toggle as called out in the plan, with unit coverage for both JT processing and MMIO annotation.【F:docs/openwebui_mcp_http_plan.md†L9-L16】【F:bridge/features/jt.py†L91-L152】【F:bridge/features/mmio.py†L94-L132】【F:bridge/tests/unit/test_enable_writes_flag.py†L1-L117】
- [x] Flesh out `features/mmio.annotate` with the planned read/write/toggle analysis instead of the current deterministic placeholder response.【F:docs/openwebui_mcp_http_plan.md†L87-L95】【F:bridge/features/mmio.py†L1-L138】【F:bridge/tests/unit/test_mmio_feature.py†L1-L61】
- [x] Align the Ghidra client whitelist with logical endpoint keys (not literal URLs) and add negative tests to prove forbidden calls are blocked.【F:docs/openwebui_mcp_http_plan.md†L108-L114】【F:bridge/ghidra/whitelist.py†L1-L37】
- [x] Extract the existing Starlette shim (`/openapi.json`, `/sse`, `/messages`, `/messages/`, `/health`) and CLI startup logic from `bridge_mcp_ghidra.py` into the new package while preserving behavior and flags (`--transport`, `--mcp-host`, etc.).【F:docs/openwebui_mcp_http_plan.md†L171-L181】【F:bridge_mcp_ghidra.py†L1-L200】
- [x] Mount the deterministic API (`bridge/app.py`) inside the production entry point so both legacy and new endpoints are served, then run parity checks before switching defaults.【F:docs/openwebui_mcp_http_plan.md†L41-L66】【F:bridge/app.py†L9-L34】【F:bridge/shim.py†L1-L86】【F:bridge_mcp_ghidra.py†L1-L219】
- [ ] Wire structured request-scoped logging, counters, and safety limits (`MaxWritesPerRequest`, etc.) using the helpers in `bridge/utils/logging.py`.【F:docs/openwebui_mcp_http_plan.md†L126-L132】【F:bridge/utils/logging.py†L1-L19】【F:bridge/features/jt.py†L53-L186】
- [ ] Build out the promised automated coverage: unit tests for JT/string/MMIO edge cases and whitelist enforcement, contract tests that assert schema compliance, golden parity snapshots, and mocked-integration suites.【F:docs/openwebui_mcp_http_plan.md†L135-L156】【F:bridge/tests/unit/test_adapters_arm_thumb.py†L1-L24】
- [ ] Capture legacy responses and wire parity gates so the acceptance checklist items (byte-identical legacy outputs, schema validation in production, logging coverage) can be checked off.【F:docs/openwebui_mcp_http_plan.md†L160-L168】
