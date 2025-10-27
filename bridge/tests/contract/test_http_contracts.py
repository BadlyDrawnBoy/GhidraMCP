from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient
from typing import Dict, List, Optional

from bridge.api.routes import make_routes
from bridge.api.validators import validate_payload


class StubGhidraClient:
    """Minimal stub that satisfies feature dependencies for contract tests."""

    def __init__(self) -> None:
        self._jt_base = 0x00100000
        self._slot_values: List[Optional[int]] = [
            0x00102030,
            0x0010FFFF,
            0xE12FFF1C,
            None,
            0x00102031,
            0x00111000,
            0x00100000,
            0x00100004,
            0x00100008,
            0x0010000C,
            0x00100010,
            0x00100014,
            0x00100018,
            0x0010001C,
            0x00100020,
            0x00100024,
        ]
        valid_targets = {
            0x00102030: {"name": "target_func", "comment": "existing"},
            0x00100000: {"name": "sub_00100000", "comment": ""},
            0x00100004: {"name": "sub_00100004", "comment": ""},
            0x00100008: {"name": "sub_00100008", "comment": ""},
            0x0010000C: {"name": "sub_0010000c", "comment": ""},
            0x00100010: {"name": "sub_00100010", "comment": ""},
            0x00100014: {"name": "sub_00100014", "comment": ""},
            0x00100018: {"name": "sub_00100018", "comment": ""},
            0x0010001C: {"name": "sub_0010001c", "comment": ""},
            0x00100020: {"name": "sub_00100020", "comment": ""},
            0x00100024: {"name": "sub_00100024", "comment": ""},
        }
        self._functions: Dict[int, Dict[str, str]] = valid_targets
        self._xrefs: List[Dict[str, object]] = [
            {"addr": addr, "context": f"Call at {addr:08x}"}
            for addr in (
                0x00100000,
                0x00100004,
                0x00100008,
                0x0010000C,
                0x00100010,
                0x00100014,
                0x00100018,
                0x0010001C,
            )
        ]

    def read_dword(self, address: int) -> Optional[int]:
        index = (address - self._jt_base) // 4
        if 0 <= index < len(self._slot_values):
            return self._slot_values[index]
        return 0x00102030

    def get_function_by_address(self, address: int) -> Optional[Dict[str, str]]:
        meta = self._functions.get(address)
        return dict(meta) if meta else None

    def rename_function(self, address: int, new_name: str) -> bool:
        return True

    def set_decompiler_comment(self, address: int, comment: str) -> bool:
        return True

    def get_xrefs_to(self, address: int, *, limit: int = 50):
        return list(self._xrefs)

    def disassemble_function(self, address: int):
        if address == 0x00005000:
            return [
                "00005000: BL target_func",
                "00005004: MOV R0, R1",
            ]
        if address == 0x00006000:
            return [
                "00006000: LDR R0, [R1, #0x10]",
                "00006004: STR R0, [R1, #0x10]",
                "00006008: ORR R0, R0, #0x1",
                "0000600C: AND R0, R0, #0xfffffffe",
                "00006010: EOR R0, R0, #0x1",
            ]
        if address == 0x00007000:
            return [
                "00007000: LDR R0, [R1, #0x0]",
                "00007004: STR R2, [R3, #0x4]",
                "00007008: ORR R4, R4, #0x2",
                "0000700C: AND R5, R5, #0xfffffffd",
                "00007010: EOR R6, R6, #0x1",
                "00007014: MOV R7, R7",
            ]
        if address in self._functions:
            return [
                f"{address:08x}: PUSH {{lr}}",
                f"{address + 4:08x}: BL dispatch_handler",
            ]
        return []

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
