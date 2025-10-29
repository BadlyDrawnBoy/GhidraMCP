from __future__ import annotations

from starlette.testclient import TestClient


def _assert_envelope(payload: dict) -> dict:
    assert set(payload.keys()) == {"ok", "data", "errors"}
    assert payload["ok"] is True
    assert payload["errors"] == []
    return payload["data"]


def test_jt_slot_check_safeguard(contract_client: TestClient) -> None:
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
    data = _assert_envelope(response.json())
    assert data["slot"] == 0
    assert data["mode"] == "ARM"
    assert data["errors"] == []
    assert data["target"] == "0x00102030"


def test_jt_scan_safeguard(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/jt_scan.json",
        json={
            "jt_base": "0x00100000",
            "start": 0,
            "count": 4,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "arch": "arm",
        },
    )
    assert response.status_code == 200
    data = _assert_envelope(response.json())
    summary = data["summary"]
    assert summary["total"] == 4
    assert summary["valid"] == 1
    assert summary["invalid"] == 3
    items = data["items"]
    assert len(items) == 4
    assert items[1]["errors"] == ["OUT_OF_RANGE"]
    assert items[2]["errors"] == ["ARM_INSTRUCTION"]
    assert items[3]["errors"] == ["TOOL_BINDING_MISSING"]


def test_string_xrefs_safeguard(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/string_xrefs.json",
        json={"string_addr": "0x00200000", "limit": 4},
    )
    assert response.status_code == 200
    data = _assert_envelope(response.json())
    assert data["count"] == 8
    callers = data["callers"]
    assert len(callers) == 4
    first = callers[0]
    assert first["addr"] == "0x00100000"
    assert "dispatch_handler" in first["context"]


def test_mmio_annotate_safeguard(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/mmio_annotate.json",
        json={"function_addr": "0x00006000", "dry_run": True, "max_samples": 3},
    )
    assert response.status_code == 200
    data = _assert_envelope(response.json())
    assert data["reads"] == 1
    assert data["writes"] == 1
    assert data["bitwise_or"] == 1
    assert data["bitwise_and"] == 1
    assert "dry-run requested" in data["notes"][0]
    assert "writes disabled" in data["notes"][1]

