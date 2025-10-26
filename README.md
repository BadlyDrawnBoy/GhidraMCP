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

## Installation quick start

1. Install [Ghidra](https://ghidra-sre.org/) and the MCP [Python SDK](https://github.com/modelcontextprotocol/python-sdk).
2. Download the latest release artefacts (Ghidra plugin + Python bridge) or build them from source using Maven.
3. Import the plugin into Ghidra via `File → Install Extensions`, enable it, and configure the HTTP server port if needed.
4. Run the Python bridge using `python bridge_mcp_ghidra.py --transport sse --ghidra-server http://127.0.0.1:8080/` (adjust arguments for your setup).
5. Point your MCP client (Claude Desktop, Cline, OpenWebUI, etc.) at the SSE endpoint exposed by the bridge.

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
