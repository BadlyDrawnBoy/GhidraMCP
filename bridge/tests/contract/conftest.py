from __future__ import annotations

from typing import Dict, List, Optional

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from bridge.api.routes import make_routes


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
        self._strings: List[Dict[str, object]] = [
            {
                "literal": "Error: invalid checksum\n(retry)",
                "address": 0x00200000,
                "refs": 8,
            },
            {"literal": "Boot complete", "address": 0x00200030, "refs": 2},
            {
                "literal": "Status: ready for commands",
                "address": 0x00200010,
                "refs": 4,
            },
        ]
        self._imports: List[str] = [
            f"import_symbol_{i:04d} -> 0x{0x10000000 + i:08x}"
            for i in range(24)
        ]
        self._exports: List[str] = [
            f"export_symbol_{i:04d} -> 0x{0x20000000 + i:08x}"
            for i in range(24)
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

    def search_xrefs_to(self, address: int, query: str):
        normalized = query.lower()
        return [
            dict(entry)
            for entry in self._xrefs
            if not normalized or normalized in str(entry["context"]).lower()
        ]

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
            for i in range(20)
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

    def search_exports(self, query: str) -> List[str]:
        normalized_query = query.lower()
        return [
            entry
            for entry in self._exports
            if not normalized_query or normalized_query in entry.lower()
        ]

    def close(self) -> None:
        return None


@pytest.fixture()
def contract_client() -> TestClient:
    def factory() -> StubGhidraClient:
        return StubGhidraClient()

    app = Starlette(routes=make_routes(factory, enable_writes=False))
    return TestClient(app)
