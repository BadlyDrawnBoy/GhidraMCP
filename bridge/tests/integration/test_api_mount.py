"""Integration checks for HTTP and MCP wiring required by API-MOUNT."""
from __future__ import annotations

import asyncio

from starlette.applications import Starlette
from starlette.testclient import TestClient

from bridge.api.routes import make_routes
from bridge.app import MCP_SERVER, configure
from bridge.shim import build_openwebui_shim
from bridge.tests.golden.test_http_parity import GoldenStubGhidraClient


def _make_test_client() -> TestClient:
    def factory() -> GoldenStubGhidraClient:
        return GoldenStubGhidraClient()

    api_app = Starlette(routes=make_routes(factory, enable_writes=True))
    shim = build_openwebui_shim("http://upstream", extra_routes=api_app.routes)
    return TestClient(shim)


def test_openapi_and_jt_slot_check_envelope() -> None:
    with _make_test_client() as client:
        openapi = client.get("/openapi.json")
        assert openapi.status_code == 200
        assert openapi.json()["openapi"].startswith("3.")

        response = client.post(
            "/api/jt_slot_check.json",
            json={
                "jt_base": "0x00100000",
                "slot_index": 0,
                "code_min": "0x00100000",
                "code_max": "0x0010FFFF",
                "arch": "arm",
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["ok"] is True
        assert isinstance(body["data"], dict)
        assert body["errors"] == []


def test_configure_registers_required_tools() -> None:
    configure()
    tools = asyncio.run(MCP_SERVER.list_tools())
    names = {tool.name for tool in tools}
    assert {
        "jt_slot_check",
        "jt_slot_process",
        "jt_scan",
        "string_xrefs_compact",
        "mmio_annotate_compact",
    } <= names
