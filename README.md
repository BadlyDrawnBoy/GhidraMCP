# GhidraMCP (Hedera bridge edition)

> **Heads up:** this project started from [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) and still borrows its plugin packaging, but it has already drifted into a much more specialised bridge-focused experiment. Expect differences everywhere.

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)

## Personal disclaimer

I have absolutely **no idea** what I am doing here. The entire codebase, documentation, and direction are produced by AI assistants, and I am mostly along for the ride. Treat every commit with caution and double-check before trusting it in your workflow.

## What this repository contains now

* A Model Context Protocol (MCP) bridge that talks to a Ghidra HTTP plugin.
* Refactor work in progress to split the bridge into deterministic building blocks (adapters, Ghidra client, feature modules, schema-locked APIs).
* Legacy CLI and shim behaviour preserved from the upstream project so existing MCP clients keep working while the new stack is wired in.

Because the refactor is still underway, you will find both the legacy `bridge_mcp_ghidra.py` script and the new `bridge/` package living side by side. The plan is to migrate gradually without breaking existing tooling.

## Features (current state)

* Decompile and analyse binaries via Ghidra.
* Rename methods and data programmatically.
* List methods, classes, imports, exports, strings, and more.
* Experimental deterministic endpoints for jump tables, string xrefs, and MMIO helpers (still evolving).

### Deterministic jump table helpers

Jump-table specific requests (`jt_slot_check`, `jt_slot_process`, `jt_scan`) use a half-open range for code pointers:
`code_min` is inclusive while `code_max` is exclusive (`[code_min, code_max)`). Any pointer that equals or exceeds
`code_max` is rejected as out of range to avoid off-by-one spills into the next region.

`jt_slot_process` performs at most two write operations (rename + comment) and only after the candidate address is
re-confirmed as a valid ARM/Thumb function start. A second metadata fetch verifies the rename/comment before the
response is returned.

`jt_scan` walks slots sequentially and the returned summary always reports `total == len(items)` with separate
valid/invalid counters for deterministic auditing.

## Installation quick start

1. Install [Ghidra](https://ghidra-sre.org/) and the MCP [Python SDK](https://github.com/modelcontextprotocol/python-sdk).
2. Download the latest release artefacts (Ghidra plugin + Python bridge) or build them from source using Maven.
3. Import the plugin into Ghidra via `File → Install Extensions`, enable it, and configure the HTTP server port if needed.
4. Run the Python bridge using `python bridge_mcp_ghidra.py --transport sse --ghidra-server http://127.0.0.1:8080/` (adjust arguments for your setup).
5. Point your MCP client (Claude Desktop, Cline, OpenWebUI, etc.) at the SSE endpoint exposed by the bridge.

## Local run (deterministic bridge)

The modular bridge currently targets **Python 3.10+** and uses `pip` for dependency management. The entry point is the legacy
`bridge_mcp_ghidra.py` script, which now wires in the deterministic API (`bridge.app`) and SSE shim.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.sample .env  # optional: customise GHIDRA_SERVER_URL, safety limits, etc.
python bridge_mcp_ghidra.py --transport sse --ghidra-server http://127.0.0.1:8080/ \
  --mcp-port 8099 --shim-port 8081
```

With the server running locally you can hit the deterministic HTTP surface directly via the shim:

```bash
curl -s http://127.0.0.1:8081/api/health.json | jq
```

Expected output (when the upstream Ghidra HTTP plugin is offline) looks like this:

```json
{
  "ok": true,
  "data": {
    "service": "ghidra-mcp-bridge",
    "writes_enabled": false,
    "ghidra": {
      "base_url": "http://127.0.0.1:8080/",
      "reachable": false,
      "error": "[Errno 111] Connection refused"
    }
  },
  "errors": []
}
```

## Environment configuration

The bridge reads its configuration from environment variables (or a local `.env`). Copy `.env.sample` to `.env` and tweak as
needed:

- `GHIDRA_SERVER_URL` – Base URL of the Ghidra HTTP plugin (defaults to `http://127.0.0.1:8080/`).
- `GHIDRA_MCP_ENABLE_WRITES` – Set to `true` to allow deterministic write operations; keep `false` unless audit logging is in
  place.
- `GHIDRA_MCP_MAX_WRITES_PER_REQUEST` – Safety limit for how many write operations a deterministic request may perform.
- `GHIDRA_MCP_MAX_ITEMS_PER_BATCH` – Maximum number of items processed per deterministic batch.
- `MCP_MAX_LINES_SOFT`, `MCP_MAX_ITEMS_SOFT`, `MCP_MAX_ITEMS_HARD` – Legacy bridge safeguards controlling response truncation.
- `UPDATE_GOLDEN_SNAPSHOTS` – Enable (`1`) to refresh golden files while developing tests.

## Running the test suite

Install the development dependencies as shown above and execute:

```bash
pytest
```

The repository ships with contract, golden and unit tests covering the deterministic bridge paths. A clean checkout should pass
all tests before you push or open a PR.

## Contribution workflow (single-branch policy)

Active work on the deterministic bridge follows a single feature branch strategy:

- Branch: `feature/deterministic-bridge` (see `.github/pull_request_template.md` for the running checklist).
- Task manifest: `.plan/tasks.manifest.json` enumerates the ordered backlog items.
- Workspace lock: `.ci/AGENT_LOCK` prevents concurrent runs—refresh its JSON payload with your agent ID and expiry before
  pushing changes.

Always update the manifest and lock file as you progress so other agents can safely resume the same PR without drift.

## Building from source

Populate the required Ghidra JARs (either manually or via `python scripts/fetch_ghidra_jars.py`) and run:

```bash
mvn clean package assembly:single
```

The resulting ZIP contains the plugin artefacts (`lib/GhidraMCP.jar`, `extensions.properties`, `Module.manifest`).

## Status & roadmap

The detailed roadmap for the Hedera/OpenWebUI bridge lives in [`docs/openwebui_mcp_http_plan.md`](docs/openwebui_mcp_http_plan.md) with a live to-do tracker in [`docs/openwebui_mcp_http_todo.md`](docs/openwebui_mcp_http_todo.md). Expect the documentation to evolve as the AI agents figure out what to do next.

## Acknowledgements

Huge thanks to Laurie Wired for open-sourcing the original GhidraMCP project. Without that foundation this experiment would not exist—even if the current state is wildly different from upstream.
