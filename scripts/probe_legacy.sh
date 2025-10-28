#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$REPO_ROOT"

python - "$@" <<'PY'
from bridge.shim import build_openwebui_shim
from starlette.testclient import TestClient

expected = {
    "openapi_get": {
        "openapi": "3.1.0",
        "info": {"title": "Ghidra MCP Bridge (stub)", "version": "0.1"},
        "x-openwebui-mcp": {
            "transport": "sse",
            "sse_url": "/sse",
            "messages_url": "/messages",
        },
    },
    "openapi_post": {
        "jsonrpc": "2.0",
        "id": 123,
        "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {
                "experimental": {},
                "prompts": {"listChanged": False},
                "resources": {"subscribe": False, "listChanged": False},
                "tools": {"listChanged": False},
            },
            "serverInfo": {"name": "ghidra-mcp", "version": "1.14.1"},
        },
    },
    "health_get": {
        "ok": True,
        "type": "mcp-sse",
        "endpoints": {"sse": "/sse", "messages": "/messages"},
    },
    "root_post": {"jsonrpc": "2.0", "id": 0, "result": {"ok": True}},
}

app = build_openwebui_shim("http://127.0.0.1:8080")
with TestClient(app) as client:
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    assert resp.json() == expected["openapi_get"]

    resp = client.post("/openapi.json", json={"id": 123})
    assert resp.status_code == 200
    assert resp.json() == expected["openapi_post"]

    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == expected["health_get"]

    resp = client.post("/")
    assert resp.status_code == 200
    assert resp.json() == expected["root_post"]

print("legacy shim probe: ok")
PY
