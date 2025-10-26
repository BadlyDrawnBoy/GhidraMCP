from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from bridge.api.routes import make_routes
from bridge.api.validators import validate_payload


class StubGhidraClient:
    """Minimal stub that satisfies feature dependencies for contract tests."""

    def read_dword(self, address: int) -> int:
        return 0x00102030

    def get_function_by_address(self, address: int):
        return {"name": "target_func", "comment": "existing"}

    def rename_function(self, address: int, new_name: str) -> bool:
        return True

    def set_decompiler_comment(self, address: int, comment: str) -> bool:
        return True

    def get_xrefs_to(self, address: int, *, limit: int = 50):
        return [{"addr": 0x00005000, "context": "BL target_func"}]

    def disassemble_function(self, address: int):
        if address == 0x00005000:
            return [
                "00005000: BL target_func",
                "00005004: MOV R0, R1",
            ]
        return [
            "00006000: LDR R0, [R1, #0x10]",
            "00006004: STR R0, [R1, #0x10]",
            "00006008: ORR R0, R0, #0x1",
            "0000600C: AND R0, R0, #0xfffffffe",
            "00006010: EOR R0, R0, #0x1",
        ]

    def set_disassembly_comment(self, address: int, comment: str) -> bool:
        return True

    def close(self) -> None:
        return None


@pytest.fixture()
def contract_client() -> TestClient:
    def factory() -> StubGhidraClient:
        return StubGhidraClient()

    app = Starlette(routes=make_routes(factory, enable_writes=False))
    return TestClient(app)


def _assert_valid(schema_name: str, payload: dict) -> None:
    valid, errors = validate_payload(schema_name, payload)
    assert valid, f"Schema validation failed: {errors}"


def test_jt_slot_check_contract(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/jt_slot_check.json",
        json={
            "jt_base": "0x00100000",
            "slot_index": 0,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "arch": "fallback",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    _assert_valid("jt_slot_check.v1.json", body["data"])


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
            "arch": "fallback",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    _assert_valid("jt_slot_process.v1.json", body["data"])


def test_jt_scan_contract(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/jt_scan.json",
        json={
            "jt_base": "0x00100000",
            "start": 0,
            "count": 2,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "arch": "fallback",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    _assert_valid("jt_scan.v1.json", body["data"])


def test_string_xrefs_contract(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/string_xrefs.json",
        json={"string_addr": "0x00200000", "limit": 10},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    _assert_valid("string_xrefs.v1.json", body["data"])


def test_mmio_annotate_contract(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/mmio_annotate.json",
        json={"function_addr": "0x00006000", "dry_run": True, "max_samples": 3},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    _assert_valid("mmio_annotate.v1.json", body["data"])
