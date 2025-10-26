# OpenWebUI MCP/HTTP Integration Plan

## Architecture
- Introduce a dedicated shim module (e.g., `bridge/shim.py`) that encapsulates the existing FastAPI routes (`/openapi.json`, `/sse`, `/messages`, `/health`, etc.) so OpenWebUI continues to hit the same URLs it does today.
- Ensure the shim keeps proxying its SSE traffic to the upstream FastMCP server exactly as the current `build_shim_app` helper does, including streaming semantics and any required headers.
- Have the primary entry point (`app.py` or equivalent) compose both the legacy shim router and the new MCP/HTTP API wiring so the combined ASGI application exposes all endpoints without regression.

## Sequence
1. Extract the current shim construction logic into `bridge/shim.py`, preserving route parity with the existing deployment.
2. Update `app.py` (or the selected ASGI entry point) to mount/compose the shim router alongside the new MCP/HTTP API implementation so both sets of routes are live.
3. Confirm the shim continues to proxy `/sse` requests to the upstream FastMCP SSE server just like `build_shim_app` does today, including end-to-end smoke tests for `/openapi.json`, `/messages`, and `/sse`.
