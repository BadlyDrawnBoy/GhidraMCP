"""Unit tests for the jump table feature helpers."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import pytest

from bridge.features import jt
from bridge.utils.logging import SafetyLimitExceeded, request_scope


@dataclass
class StubAdapter:
    """Minimal adapter implementation with configurable behaviour."""

    in_range: bool = True
    sentinel: bool = False
    mode: Optional[str] = "ARM"
    target: Optional[int] = 0x401000
    probe_map: Dict[int, tuple[Optional[str], Optional[int]]] = field(default_factory=dict)
    sentinel_values: Dict[int, bool] = field(default_factory=dict)

    def in_code_range(self, ptr: int, code_min: int, code_max: int) -> bool:
        if not self.in_range:
            return False
        return code_min <= ptr < code_max

    def is_instruction_sentinel(self, raw: int) -> bool:
        if raw in self.sentinel_values:
            return self.sentinel_values[raw]
        return self.sentinel

    def probe_function(self, _client, ptr: int) -> tuple[Optional[str], Optional[int]]:
        if ptr in self.probe_map:
            return self.probe_map[ptr]
        return self.mode, self.target


@dataclass
class StubClient:
    """Fake Ghidra client that records the calls made by the feature layer."""

    read_result: Optional[int]
    metadata: List[Optional[Dict[str, object]]] = field(default_factory=list)
    read_values: List[Optional[int]] = field(default_factory=list)
    rename_result: bool = True
    comment_result: bool = True

    read_addresses: List[int] = field(default_factory=list, init=False)
    rename_calls: List[tuple[int, str]] = field(default_factory=list, init=False)
    comment_calls: List[tuple[int, str]] = field(default_factory=list, init=False)
    meta_calls: List[int] = field(default_factory=list, init=False)

    def read_dword(self, addr: int) -> Optional[int]:
        self.read_addresses.append(addr)
        if self.read_values:
            return self.read_values.pop(0)
        return self.read_result

    def get_function_by_address(self, addr: int) -> Optional[Dict[str, object]]:
        self.meta_calls.append(addr)
        if self.metadata:
            return self.metadata.pop(0)
        return None

    def rename_function(self, addr: int, name: str) -> bool:
        self.rename_calls.append((addr, name))
        return self.rename_result

    def set_decompiler_comment(self, addr: int, comment: str) -> bool:
        self.comment_calls.append((addr, comment))
        return self.comment_result


def test_slot_check_reports_missing_binding() -> None:
    client = StubClient(read_result=None)
    adapter = StubAdapter()

    result = jt.slot_check(
        client,
        jt_base=0x400000,
        slot_index=0,
        code_min=0x400000,
        code_max=0x500000,
        adapter=adapter,
    )

    assert result["errors"] == ["TOOL_BINDING_MISSING"]
    assert result["target"] is None


def test_slot_check_rejects_out_of_range_values() -> None:
    client = StubClient(read_result=0x600000)
    adapter = StubAdapter(in_range=False)

    result = jt.slot_check(
        client,
        jt_base=0x400000,
        slot_index=3,
        code_min=0x400000,
        code_max=0x410000,
        adapter=adapter,
    )

    assert result["errors"] == ["OUT_OF_RANGE"]


def test_slot_check_rejects_upper_bound_value() -> None:
    client = StubClient(read_result=0x410000)
    adapter = StubAdapter()

    result = jt.slot_check(
        client,
        jt_base=0x400000,
        slot_index=4,
        code_min=0x400000,
        code_max=0x410000,
        adapter=adapter,
    )

    assert result["errors"] == ["OUT_OF_RANGE"]


def test_slot_process_rejects_upper_bound_value() -> None:
    client = StubClient(read_result=0x410000)
    adapter = StubAdapter()

    result = jt.slot_process(
        client,
        jt_base=0x400000,
        slot_index=4,
        code_min=0x400000,
        code_max=0x410000,
        rename_pattern="new_{slot}",
        comment="note",
        adapter=adapter,
        dry_run=True,
        writes_enabled=False,
    )

    assert result["errors"] == ["OUT_OF_RANGE"]
    assert result["writes"] == {"renamed": False, "comment_set": False}
    assert client.rename_calls == []
    assert client.comment_calls == []


def test_slot_check_detects_instruction_sentinel() -> None:
    client = StubClient(read_result=0x400123)
    adapter = StubAdapter(sentinel=True)

    result = jt.slot_check(
        client,
        jt_base=0x400000,
        slot_index=1,
        code_min=0x400000,
        code_max=0x500000,
        adapter=adapter,
    )

    assert result["errors"] == ["ARM_INSTRUCTION"]
    assert result["target"] is None


def test_slot_process_dry_run_collects_metadata_without_writes() -> None:
    client = StubClient(
        read_result=0x400200,
        metadata=[{"name": "orig_name"}],
    )
    adapter = StubAdapter(mode="ARM", target=0x400200)

    result = jt.slot_process(
        client,
        jt_base=0x400000,
        slot_index=5,
        code_min=0x400000,
        code_max=0x500000,
        rename_pattern="new_{slot}",
        comment="note",
        adapter=adapter,
        dry_run=True,
        writes_enabled=False,
    )

    assert result["writes"] == {"renamed": False, "comment_set": False}
    assert result["verify"] == {"name": "orig_name", "comment_present": False}
    assert client.rename_calls == []
    assert client.comment_calls == []


def test_slot_process_performs_writes_and_verifies_results() -> None:
    client = StubClient(
        read_result=0x400200,
        metadata=[{"name": "orig_7"}, {"name": "new_7", "comment": "note"}],
    )
    adapter = StubAdapter(mode="ARM", target=0x400200)

    result = jt.slot_process(
        client,
        jt_base=0x400000,
        slot_index=7,
        code_min=0x400000,
        code_max=0x500000,
        rename_pattern="new_{slot}",
        comment="note",
        adapter=adapter,
        dry_run=False,
        writes_enabled=True,
    )

    assert result["errors"] == []
    assert result["writes"] == {"renamed": True, "comment_set": True}
    assert result["verify"] == {"name": "new_7", "comment_present": True}
    assert client.rename_calls == [(0x400200, "new_7")]
    assert client.comment_calls == [(0x400200, "note")]


def test_slot_process_records_write_counter() -> None:
    client = StubClient(
        read_result=0x400200,
        metadata=[{"name": "orig_9"}, {"name": "new_9", "comment": "note"}],
    )
    adapter = StubAdapter(mode="ARM", target=0x400200)

    with request_scope("jt_slot_process", max_writes=2) as ctx:
        result = jt.slot_process(
            client,
            jt_base=0x400000,
            slot_index=9,
            code_min=0x400000,
            code_max=0x500000,
            rename_pattern="new_{slot}",
            comment="note",
            adapter=adapter,
            dry_run=False,
            writes_enabled=True,
        )

    assert result["errors"] == []
    assert ctx.counters.get("writes") == 2


def test_slot_process_aborts_when_write_limit_exceeded() -> None:
    client = StubClient(
        read_result=0x400200,
        metadata=[{"name": "orig"}, {"name": "orig"}],
    )
    adapter = StubAdapter(mode="ARM", target=0x400200)

    with pytest.raises(SafetyLimitExceeded):
        with request_scope("jt_slot_process", max_writes=1):
            jt.slot_process(
                client,
                jt_base=0x400000,
                slot_index=11,
                code_min=0x400000,
                code_max=0x500000,
                rename_pattern="new_{slot}",
                comment="note",
                adapter=adapter,
                dry_run=False,
                writes_enabled=True,
            )

    assert client.rename_calls == [(0x400200, "new_11")]
    assert client.comment_calls == []
    assert client.meta_calls == [0x400200]


def test_slot_process_aborts_when_pre_verify_missing() -> None:
    client = StubClient(
        read_result=0x400200,
        metadata=[],
    )
    adapter = StubAdapter(mode="ARM", target=0x400200)

    result = jt.slot_process(
        client,
        jt_base=0x400000,
        slot_index=7,
        code_min=0x400000,
        code_max=0x500000,
        rename_pattern="new_{slot}",
        comment="note",
        adapter=adapter,
        dry_run=False,
        writes_enabled=True,
    )

    assert result["errors"] == ["NO_FUNCTION_AT_TARGET"]
    assert result["writes"] == {"renamed": False, "comment_set": False}
    assert client.rename_calls == []
    assert client.comment_calls == []


def test_slot_process_handles_format_errors() -> None:
    client = StubClient(
        read_result=0x400200,
        metadata=[{"name": "ignored"}],
    )
    adapter = StubAdapter(mode="ARM", target=0x400200)

    result = jt.slot_process(
        client,
        jt_base=0x400000,
        slot_index=9,
        code_min=0x400000,
        code_max=0x500000,
        rename_pattern="new_{missing}",
        comment="note",
        adapter=adapter,
        dry_run=False,
        writes_enabled=True,
    )

    assert result["errors"] == ["FORMAT_ERROR:'missing'"]
    assert client.rename_calls == []
    assert client.comment_calls == []


def test_slot_process_rejects_unknown_mode() -> None:
    client = StubClient(
        read_result=0x400200,
        metadata=[{"name": "orig"}],
    )
    adapter = StubAdapter(mode="MIPS", target=0x400200)

    result = jt.slot_process(
        client,
        jt_base=0x400000,
        slot_index=2,
        code_min=0x400000,
        code_max=0x500000,
        rename_pattern="new_{slot}",
        comment="note",
        adapter=adapter,
        dry_run=False,
        writes_enabled=True,
    )

    assert result["errors"] == ["NO_FUNCTION_AT_TARGET"]
    assert client.rename_calls == []
    assert client.comment_calls == []


def test_scan_batches_slot_checks_with_summary() -> None:
    client = StubClient(
        read_result=0,
        read_values=[0x400200, 0x410000, 0x400204],
    )
    adapter = StubAdapter(
        probe_map={
            0x400200: ("ARM", 0x400200),
            0x400204: ("Thumb", 0x400204),
        }
    )

    result = jt.scan(
        client,
        jt_base=0x400000,
        start=0,
        count=3,
        code_min=0x400000,
        code_max=0x410000,
        adapter=adapter,
    )

    assert result["summary"] == {"total": 3, "valid": 2, "invalid": 1}
    assert [item["slot"] for item in result["items"]] == [0, 1, 2]
    assert result["items"][0]["errors"] == []
    assert result["items"][1]["errors"] == ["OUT_OF_RANGE"]
    assert result["items"][2]["errors"] == []
