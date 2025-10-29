from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from bridge.api.validators import validate_payload

def _assert_valid(schema_name: str, payload: dict) -> None:
    valid, errors = validate_payload(schema_name, payload)
    assert valid, f"Schema validation failed: {errors}"


def _assert_envelope(payload: dict) -> None:
    _assert_valid("envelope.v1.json", payload)


def test_jt_slot_check_contract(contract_client: TestClient) -> None:
    response = contract_client.post(
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
    _assert_envelope(body)
    _assert_valid("jt_slot_check.v1.json", body["data"])


def test_jt_slot_check_rejects_upper_bound(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/jt_slot_check.json",
        json={
            "jt_base": "0x00100000",
            "slot_index": 1,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "arch": "arm",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    _assert_envelope(body)
    _assert_valid("jt_slot_check.v1.json", body["data"])
    assert body["data"]["errors"] == ["OUT_OF_RANGE"]


def test_jt_slot_process_contract(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/jt_slot_process.json",
        json={
            "jt_base": "0x00100000",
            "slot_index": 0,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "rename_pattern": "slot_{slot}",
            "comment": "Processed",
            "dry_run": True,
            "arch": "arm",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    _assert_envelope(body)
    _assert_valid("jt_slot_process.v1.json", body["data"])


def test_jt_scan_contract(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/jt_scan.json",
        json={
            "jt_base": "0x00100000",
            "start": 0,
            "count": 16,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "arch": "arm",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    _assert_envelope(body)
    data = body["data"]
    _assert_valid("jt_scan.v1.json", data)
    items = data["items"]
    assert data["summary"]["total"] == len(items) == 16
    invalid = sum(1 for item in items if item["errors"])
    assert data["summary"]["invalid"] == invalid
    assert data["summary"]["valid"] == len(items) - invalid
    assert items[1]["errors"] == ["OUT_OF_RANGE"]
    assert items[2]["errors"] == ["ARM_INSTRUCTION"]
    assert items[3]["errors"] == ["TOOL_BINDING_MISSING"]
    assert items[4]["mode"] == "Thumb"


def test_string_xrefs_contract(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/string_xrefs.json",
        json={"string_addr": "0x00200000", "limit": 4},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    _assert_envelope(body)
    data = body["data"]
    _assert_valid("string_xrefs.v1.json", data)
    assert data["count"] == 8
    assert len(data["callers"]) == 4
    assert data["callers"][0]["addr"] == "0x00100000"


def test_mmio_annotate_contract(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/mmio_annotate.json",
        json={"function_addr": "0x00006000", "dry_run": True, "max_samples": 3},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    _assert_envelope(body)
    _assert_valid("mmio_annotate.v1.json", body["data"])


@pytest.mark.parametrize(
    "path,payload",
    [
        ("/api/jt_slot_check.json", {"jt_base": "0x1", "slot_index": 0, "code_min": "0x1", "code_max": "0x2", "extra": 1}),
        (
            "/api/jt_slot_process.json",
            {
                "jt_base": "0x1",
                "slot_index": 0,
                "code_min": "0x1",
                "code_max": "0x2",
                "rename_pattern": "slot_{slot}",
                "comment": "hi",
                "dry_run": True,
                "extra": 1,
            },
        ),
        (
            "/api/jt_scan.json",
            {
                "jt_base": "0x1",
                "start": 0,
                "count": 4,
                "code_min": "0x1",
                "code_max": "0x2",
                "extra": 1,
            },
        ),
        (
            "/api/string_xrefs.json",
            {"string_addr": "0x2", "limit": 1, "extra": 1},
        ),
        (
            "/api/mmio_annotate.json",
            {"function_addr": "0x1", "dry_run": True, "max_samples": 2, "extra": 1},
        ),
    ],
)
def test_contract_rejects_additional_properties(contract_client: TestClient, path: str, payload: dict) -> None:
    response = contract_client.post(path, json=payload)
    assert response.status_code == 400
    body = response.json()
    _assert_envelope(body)
    assert body["ok"] is False
    assert body["errors"], "Expected schema validation errors"
