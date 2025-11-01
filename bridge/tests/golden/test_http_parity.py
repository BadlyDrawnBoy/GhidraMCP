from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from bridge.api.routes import make_routes


_DATA_DIR = Path(__file__).parent / "data"
_SNAPSHOT_PATH = _DATA_DIR / "http_snapshots.json"
_UPDATE_SNAPSHOTS = os.getenv("UPDATE_GOLDEN_SNAPSHOTS", "0").lower() in {
    "1",
    "true",
    "yes",
    "on",
}


class GoldenStubGhidraClient:
    """Stub client that emits deterministic data for golden snapshot tests."""

    def __init__(self) -> None:
        self._dwords: Dict[int, int] = {
            0x00100000: 0x00102004,
            0x00100004: 0x00102005,
        }
        self._functions: Dict[int, Dict[str, str]] = {
            0x00102004: {"name": "sub_102004", "comment": "initial"},
            0x00102005: {"name": "thumb_stub", "comment": ""},
        }
        self._disassembly: Dict[int, List[str]] = {
            0x00102004: [
                "00102004: PUSH {r4, lr}",
                "00102008: BL jump_table_target",
            ],
            0x00005000: [
                "00005000: BL log_debug",
                "00005004: MOV R0, R1",
                "00005008: ADR R1, 0x00200000",
                "0000500C: BL helper_printf",
            ],
            0x00006000: [
                "00006000: LDR R0, =0x00200000",
                "00006004: MOV R1, R4",
                "00006008: BL printf",
                "0000600C: MOV R7, #0x1",
            ],
            0x00007000: [
                "00007000: LDR R0, [R1, #0x0]",
                "00007004: STR R2, [R3, #0x4]",
                "00007008: ORR R4, R4, #0x2",
                "0000700C: AND R5, R5, #0xfffffffd",
                "00007010: EOR R6, R6, #0x1",
                "00007014: MOV R7, R7",
            ],
        }
        self._instruction_addresses = {
            0x00005000,
            0x00005004,
            0x00005008,
            0x0000500C,
            0x00006000,
            0x00006004,
            0x00006008,
            0x0000600C,
            0x00007000,
            0x00007004,
            0x00007008,
            0x0000700C,
            0x00007010,
            0x00007014,
        }
        self._strings: List[Dict[str, object]] = [
            {
                "literal": "Firmware build ready",
                "address": 0x00200020,
                "refs": 3,
            },
            {
                "literal": "Diagnostic mode enabled",
                "address": 0x00200000,
                "refs": 5,
            },
            {
                "literal": "Boot complete",
                "address": 0x00200010,
                "refs": 2,
            },
        ]
        self._imports: List[str] = [
            f"import_symbol_{i:04d} -> 0x{0x20000000 + i:08x}"
            for i in range(16)
        ]

    def read_dword(self, address: int) -> Optional[int]:
        return self._dwords.get(address)

    def get_function_by_address(self, address: int) -> Optional[Dict[str, str]]:
        return dict(self._functions.get(address, {})) or None

    def rename_function(self, address: int, new_name: str) -> bool:
        if address not in self._functions:
            return False
        self._functions[address]["name"] = new_name
        return True

    def set_decompiler_comment(self, address: int, comment: str) -> bool:
        if address not in self._functions:
            return False
        self._functions[address]["comment"] = comment
        return True

    def get_xrefs_to(self, address: int, *, limit: int = 50):
        return [
            {"addr": 0x00005000, "context": "BL log_debug"},
            {"addr": 0x00006000, "context": "BL printf"},
        ][:limit]

    def disassemble_function(self, address: int) -> List[str]:
        return list(self._disassembly.get(address, []))

    def set_disassembly_comment(self, address: int, comment: str) -> bool:
        return address in self._instruction_addresses

    def list_strings_compact(
        self, *, limit: int = 50, offset: int = 0
    ) -> List[Dict[str, object]]:
        if limit < 0:
            limit = 0
        start = max(offset, 0)
        end = start + limit
        return [dict(entry) for entry in self._strings[start:end]]

    def search_strings(self, query: str) -> List[Dict[str, object]]:
        normalized = query.lower()
        results: List[Dict[str, object]] = []
        for entry in self._strings:
            literal = str(entry.get("literal", ""))
            if not normalized or normalized in literal.lower():
                results.append(dict(entry))
        return results

    def search_functions(self, query: str) -> List[str]:
        """Return a predictable list of functions for testing."""
        all_functions = [
            f"func_{i:04d} @ 0x{0x00400000 + i * 0x100:08x}"
            for i in range(10)
        ]
        # Add the functions from self._functions as well
        for addr, meta in self._functions.items():
            all_functions.append(f"{meta['name']} @ 0x{addr:08x}")

        # Simple filter by query
        normalized_query = query.lower()
        return [f for f in all_functions if normalized_query in f.lower()]

    def search_imports(self, query: str) -> List[str]:
        normalized_query = query.lower()
        return [
            entry
            for entry in self._imports
            if not normalized_query or normalized_query in entry.lower()
        ]

    def close(self) -> None:  # pragma: no cover - interface requirement
        return None


class SnapshotStore:
    """Utility that manages reading/updating golden snapshots on disk."""

    def __init__(self, data: Dict[str, object], update: bool) -> None:
        self._data = data
        self._update = update

    def assert_match(self, key: str, payload: Dict[str, object]) -> None:
        if self._update:
            self._data[key] = payload
            return
        assert key in self._data, f"Missing golden snapshot for {key}"
        assert payload == self._data[key]

    def dump(self) -> None:
        if not self._update:
            return
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        with _SNAPSHOT_PATH.open("w", encoding="utf-8") as handle:
            json.dump(self._data, handle, indent=2, sort_keys=True)
            handle.write("\n")


@pytest.fixture(scope="module")
def snapshot_store() -> Iterable[SnapshotStore]:
    data: Dict[str, object] = {}
    if _SNAPSHOT_PATH.exists():
        with _SNAPSHOT_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    store = SnapshotStore(data, _UPDATE_SNAPSHOTS)
    yield store
    store.dump()


@pytest.fixture()
def golden_client() -> Iterable[TestClient]:
    def factory() -> GoldenStubGhidraClient:
        return GoldenStubGhidraClient()

    app = Starlette(routes=make_routes(factory, enable_writes=True))
    with TestClient(app) as client:
        yield client


def test_jt_slot_check_snapshot(golden_client: TestClient, snapshot_store: SnapshotStore) -> None:
    response = golden_client.post(
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
    snapshot_store.assert_match("jt_slot_check", response.json())


def test_jt_slot_process_dry_run_snapshot(
    golden_client: TestClient, snapshot_store: SnapshotStore
) -> None:
    response = golden_client.post(
        "/api/jt_slot_process.json",
        json={
            "jt_base": "0x00100000",
            "slot_index": 0,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "rename_pattern": "slot_{slot}_{target}",
            "comment": "Processed",
            "dry_run": True,
            "arch": "arm",
        },
    )
    assert response.status_code == 200
    snapshot_store.assert_match("jt_slot_process_dry_run", response.json())


def test_jt_slot_process_writes_snapshot(
    golden_client: TestClient, snapshot_store: SnapshotStore
) -> None:
    response = golden_client.post(
        "/api/jt_slot_process.json",
        json={
            "jt_base": "0x00100000",
            "slot_index": 0,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "rename_pattern": "slot_{slot}_{target}",
            "comment": "Processed",
            "dry_run": False,
            "arch": "arm",
        },
    )
    assert response.status_code == 200
    snapshot_store.assert_match("jt_slot_process_writes", response.json())


def test_jt_scan_snapshot(golden_client: TestClient, snapshot_store: SnapshotStore) -> None:
    response = golden_client.post(
        "/api/jt_scan.json",
        json={
            "jt_base": "0x00100000",
            "start": 0,
            "count": 2,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "arch": "arm",
        },
    )
    assert response.status_code == 200
    snapshot_store.assert_match("jt_scan", response.json())


def test_string_xrefs_snapshot(
    golden_client: TestClient, snapshot_store: SnapshotStore
) -> None:
    response = golden_client.post(
        "/api/string_xrefs.json",
        json={"string_addr": "0x00200000", "limit": 10},
    )
    assert response.status_code == 200
    snapshot_store.assert_match("string_xrefs", response.json())


def test_mmio_annotate_snapshot(
    golden_client: TestClient, snapshot_store: SnapshotStore
) -> None:
    response = golden_client.post(
        "/api/mmio_annotate.json",
        json={"function_addr": "0x00007000", "dry_run": True, "max_samples": 4},
    )
    assert response.status_code == 200
    snapshot_store.assert_match("mmio_annotate", response.json())
