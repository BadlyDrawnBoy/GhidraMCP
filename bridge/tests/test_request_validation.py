from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from bridge.api.routes import make_routes
from bridge.tests.golden.test_http_parity import GoldenStubGhidraClient


@pytest.fixture()
def client() -> TestClient:
    def factory() -> GoldenStubGhidraClient:
        return GoldenStubGhidraClient()

    app = Starlette(routes=make_routes(factory, enable_writes=True))
    with TestClient(app) as test_client:
        yield test_client


def _valid_payloads() -> dict[str, dict[str, object]]:
    return {
        "/api/jt_slot_check.json": {
            "jt_base": "0x00100000",
            "slot_index": 0,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "arch": "arm",
        },
        "/api/jt_slot_process.json": {
            "jt_base": "0x00100000",
            "slot_index": 0,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "arch": "arm",
        },
        "/api/jt_scan.json": {
            "jt_base": "0x00100000",
            "start": 0,
            "count": 1,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "arch": "arm",
        },
        "/api/string_xrefs.json": {
            "string_addr": "0x00200000",
            "limit": 2,
        },
        "/api/mmio_annotate.json": {
            "function_addr": "0x00007000",
            "dry_run": True,
            "max_samples": 2,
        },
    }


@pytest.mark.parametrize(
    "path",
    list(_valid_payloads().keys()),
)
def test_rejects_additional_properties(client: TestClient, path: str) -> None:
    payload = dict(_valid_payloads()[path])
    payload["unexpected"] = "value"
    response = client.post(path, json=payload)
    assert response.status_code == 400
    body = response.json()
    assert body["ok"] is False
    assert body["errors"], "Expected an error payload"
    assert body["errors"][0]["code"].endswith("SCHEMA_INVALID")


def test_rejects_non_object_payload(client: TestClient) -> None:
    response = client.post(
        "/api/jt_slot_check.json",
        json=["jt_base", "0x00100000"],
    )
    assert response.status_code == 400
    body = response.json()
    assert body["ok"] is False
    assert body["errors"][0]["code"].endswith("INVALID_ARGUMENT")


def test_rejects_invalid_json(client: TestClient) -> None:
    response = client.post(
        "/api/jt_slot_check.json",
        data="{not-json",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400
    body = response.json()
    assert body["ok"] is False
    assert body["errors"][0]["code"].endswith("INVALID_ARGUMENT")
