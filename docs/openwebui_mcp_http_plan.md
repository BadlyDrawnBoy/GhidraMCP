# OpenWebUI MCP/HTTP Integration Plan

## Architecture
- Introduce a dedicated shim module (e.g., `bridge/shim.py`) that encapsulates the existing FastAPI routes so OpenWebUI continues to hit the same URLs it does today.
  - Explicitly expose the shim routes `/openapi.json`, `/sse`, `/health`, `/messages`, and the mandatory `/messages/` alias so trailing-slash requests keep working.
- Ensure the shim keeps proxying its SSE traffic to the upstream FastMCP server exactly as the current `build_shim_app` helper does, including streaming semantics and any required headers.
- Keep response bodies, status codes, and headers byte-for-byte compatible with today’s shim so downstream OpenWebUI integrations remain stable during future refactors.
- Have the primary entry point (`app.py` or equivalent) compose both the legacy shim router and the new MCP/HTTP API wiring so the combined ASGI application exposes all endpoints without regression.

## Sequence
1. Extract the current shim construction logic into `bridge/shim.py`, preserving route parity with the existing deployment.
2. Update `app.py` (or the selected ASGI entry point) to mount/compose the shim router alongside the new MCP/HTTP API implementation so both sets of routes are live.
3. Confirm the shim continues to proxy `/sse` requests to the upstream FastMCP SSE server just like `build_shim_app` does today, including end-to-end smoke tests for `/openapi.json`, `/messages`, `/messages/`, and `/sse`. Add (manual or automated) regression checks for both `/messages` and `/messages/` during the migration.

## CLI compatibility
- Keep `bridge_mcp_ghidra.py` as the public entry point but have it delegate to the new bridge modules (for example `bridge.cli.main`). The wrapper must continue to register the same `argparse` options—`--ghidra-server`, `--transport`, `--mcp-host`, `--mcp-port`, `--shim-host`, `--shim-port`, and `--debug`—with the current defaults so existing scripts and deployment manifests remain valid.
- When `--transport sse` is selected, the CLI should spawn the FastMCP SSE server via the new module API in a daemon thread and then launch the shim ASGI app with `uvicorn` using the provided shim host/port. This mirrors the threading model in `bridge_mcp_ghidra.py` today and ensures OpenWebUI continues to reach the SSE endpoint on the same port. When `--transport stdio` is requested, the wrapper should skip the shim entirely and invoke the stdio runner from the new module.
- Preserve startup overrides: continue honoring the `GHIDRA_SERVER_URL` environment variable as an override for `--ghidra-server`, and keep the `--debug` flag (or equivalent logging toggle) wired through to the new modules so operators can raise log verbosity without editing code. Any new logging configuration should default to the current INFO level unless `--debug` is set.

## `ghidra/client.py`
- Introduce an alias and candidate resolution layer (mirroring the intent of the current `ENDPOINT_CANDIDATES`) that resolves logical endpoint keys to concrete URLs and caches the results so repeated lookups are fast and stable across requests.
- Route every feature—both existing bridge functionality and any new capabilities—through the resolver instead of hard-coding literal paths to ensure compatibility with different bridge plugin versions that may expose endpoints under new URLs.
- Maintain the whitelist in terms of the logical alias keys consumed by the resolver (rather than raw URLs) so filtering continues to work no matter which concrete endpoint URL is chosen for a given alias, preventing regressions when candidates change.
