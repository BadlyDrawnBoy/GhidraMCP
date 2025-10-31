# GhidraMCP: A Deterministic Bridge for AI-Driven Reverse Engineering

> **Heads up:** This project is a evolution of the original [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP). While it still uses the Ghidra plugin as a foundation, the Python bridge has been completely rebuilt with a new philosophy.


## The "Why": Solving the Inefficiency of AI in Reverse Engineering

The motivation for this project was born from a practical problem: using high-level Large Language Models (LLMs) to analyze binaries is incredibly powerful but prohibitively expensive and unreliable.

Initial attempts using an orchestrator agent (e.g., Aider pair programming) to interact with the original Ghidra bridge quickly revealed a core flaw. The process was linear and conversational, consuming vast amounts of tokens for every step. An attempt to mitigate this with a multi-agent system—a high-level "Orchestrator" guiding cheaper "Sub-Agent" models—failed due to a classic **"Telephone Game" (Stille Post) problem**:

1.  The high-level agent formulates a strategic goal.
2.  A sub-agent translates this into a tool call and receives a plain-text, unstructured response from the bridge.
3.  The sub-agent must **interpret** this text, summarize it, and report back. A cheaper model is inherently bad at this, leading to information loss, misinterpretation, or hallucinations.
4.  With each step in the chain, precision is lost. The final report that reaches the orchestrator is often a distorted, unreliable version of the ground truth.

The core insight was that the data-gathering phase of reverse engineering should not be an analytical or conversational task. It should be a **purely mechanical, deterministic process.**

## The Solution: A Deterministic, Machine-Readable API

This version of GhidraMCP solves the "Telephone Game" by transforming the bridge from a conversational partner into a strict, reliable, and machine-readable API.

*   **Structured & predictable:** Every API response is a JSON object wrapped in a standard envelope: `{ "ok": boolean, "data": {...}|null, "errors": [...] }`. There is no ambiguity.
*   **Schema-enforced:** All requests and responses are validated against strict JSON schemas. This eliminates malformed data and ensures consistency.
*   **Separation of concerns:** The API allows for a clean split between **strategy** and **execution**.
    *   **Orchestrator (High-Cost LLM):** Used only for high-level strategic planning and final analysis of clean, structured data.
    *   **Executor (Cheap LLM or simple script):** Used for the mechanical task of calling API endpoints and collecting the structured results. It doesn't need to interpret anything; it just forwards data.

This architecture drastically reduces token consumption and eliminates the information loss that plagued the previous approach, making complex, automated analysis feasible.

## Vision & Future Outlook: Server-Side Workflows

The ultimate goal is to minimize the communication overhead between the orchestrator and the bridge even further. The current architecture paves the way for a **server-side workflow engine**—a "Loop Agent" that is not an AI, but a deterministic script runner living inside the bridge itself.

In this future state, an orchestrator would not make dozens of individual calls. Instead, it would design an entire analysis plan and submit it in a **single request**.

**Conceptual Example:** An LLM wants to find out how a program handles passwords. It would generate a single JSON workflow:

```json
{
  "tasks": [
    {
      "id": "find_string",
      "tool": "strings_compact",
      "params": { "limit": 1000 }
    },
    {
      "id": "get_xrefs",
      "tool": "string_xrefs_compact",
      "params": {
        "string_addr": "$tasks.find_string.data.items[?(@.s.includes('password'))].addr"
      }
    },
    {
      "id": "decompile_caller",
      "tool": "decompile_function_by_address",
      "params": {
        "address": "$tasks.get_xrefs.data.callers.addr"
      }
    }
  ]
}
```

The server would execute this entire sequence internally, using the output of one step as the input for the next (`$...`). It would then return a single, aggregated result. This approach would represent the pinnacle of token efficiency, reducing the entire analysis to just two LLM invocations: one for planning and one for final interpretation.

## Known Limitations & Development Focus

To maintain focus and avoid "feature creep," this project prioritizes correctness and reliability over adding an exhaustive list of features. The current development is centered on fixing a systemic architectural flaw known as the **"Filter after Paginate"** problem.

In many data-listing endpoints, a search or filter is only applied to a small, paginated subset of the total data, which can lead to incomplete or incorrect results.

Our roadmap to address this involves systematically implementing robust, server-side search capabilities for all relevant endpoints. This ensures that any query operates on the complete dataset within Ghidra, providing reliable and accurate information to the controlling AI.

For a detailed technical breakdown of this problem and the proposed solutions, please see the [**Project Roadmap document**](./docs/ROADMAP.md).

---

## Quickstart

Get a live server running and make a deterministic request in three commands:

```bash
# 1. Set up the environment
python -m venv .venv && source .venv/bin/activate && pip install -r requirements-dev.txt

# 2. Run the server (points to your Ghidra instance)
GHIDRA_SERVER_URL=http://127.0.0.1:8080/ python bridge_mcp_ghidra.py --transport sse

# 3. Make a test call to a deterministic endpoint
curl -s http://127.0.0.1:8081/api/jt_slot_check.json \
  -H 'content-type: application/json' \
  -d '{"jt_base":"0x00100000","slot_index":0,"code_min":"0x00100000","code_max":"0x0010FFFF"}' | jq
```

## Deterministic API Endpoints

The core of this project is its schema-locked, deterministic API. All endpoints share the same reliable response envelope.

| Feature Area | Endpoint / MCP Tool | Purpose |
| --- | --- | --- |
| Jump Tables | `/api/jt_slot_check.json` | Probes a single jump-table slot for target metadata. |
| | `/api/jt_slot_process.json` | Renames & annotates a jump-table target (honors `dry_run` and write limits). |
| | `/api/jt_scan.json` | Batch-scans slots with deterministic summaries (`total`, `valid`, `invalid`). |
| Strings | `/api/strings_compact.json` | Lists strings with truncated literals and accurate xref counts. |
| | `/api/string_xrefs.json` | Returns compact caller/xref context for a given string address. |
| MMIO | `/api/mmio_annotate.json` | Analyzes MMIO access patterns with capped samples. |
| Health | `/api/health.json` | Checks the health of the bridge and its connection to Ghidra. |

## Installation

1.  Install [Ghidra](https://ghidra-sre.org/).
2.  Download the latest release ZIP from this repository.
3.  Install the plugin in Ghidra via `File → Install Extensions...`.
4.  Ensure the `GhidraMCPPlugin` is enabled (`File → Configure... → Developer`).
5.  Optionally, configure the port in Ghidra via `Edit → Tool Options... → GhidraMCP HTTP Server`.

## Local Development

```bash
# 1. Set up virtual environment and install dependencies
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

# 2. (Optional) Customize configuration
cp .env.sample .env

# 3. Run the bridge server
python bridge_mcp_ghidra.py --transport sse --ghidra-server http://127.0.0.1:8080/
```

You can now hit the deterministic HTTP surface directly:
`curl -s http://127.0.0.1:8081/api/health.json | jq`

## Environment Configuration

Configure the bridge via a `.env` file or environment variables:

*   `GHIDRA_SERVER_URL`: URL of the Ghidra HTTP plugin (default: `http://127.0.0.1:8080/`).
*   `GHIDRA_MCP_ENABLE_WRITES`: **Must be set to `true` to allow write operations.** Defaults to `false` for safety.
*   `GHIDRA_MCP_AUDIT_LOG`: Optional path to a JSONL file to log all write operations.
*   `GHIDRA_MCP_MAX_WRITES_PER_REQUEST`: Safety limit for writes per request (default: `2`).
*   `GHIDRA_MCP_MAX_ITEMS_PER_BATCH`: Safety limit for items in a batch request (default: `256`).

## Running Tests

Install dev dependencies and run:

```bash
pytest```

To update golden snapshot files when API contracts change intentionally, run the specific test with the `UPDATE_SNAPSHOTS` flag:

```bash
UPDATE_SNAPSHOTS=1 pytest -q bridge/tests/golden/test_openapi_snapshot.py
```

## Acknowledgements

Huge thanks to Laurie Wired for open-sourcing the original GhidraMCP project. This experiment would not exist without that foundation.

Tested with **Ghidra 11.4.2**.

## Personal Disclaimer

I have absolutely **no idea** what I am doing here. The entire codebase, documentation, and direction are produced by AI assistants, and I am mostly along for the ride. Treat every commit with caution and double-check before trusting it in your workflow.
```
