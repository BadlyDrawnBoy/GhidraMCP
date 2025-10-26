"""Tests covering jump-table write gating behaviour."""
from __future__ import annotations

from dataclasses import dataclass

from bridge.features import jt, mmio
from bridge.utils import config


@dataclass
class _StubAdapter:
    def in_code_range(self, ptr: int, code_min: int, code_max: int) -> bool:
        return True

    def is_instruction_sentinel(self, raw: int) -> bool:
        return False

    def probe_function(self, ptr: int):  # type: ignore[override]
        return "code", ptr


class _StubClient:
    def __init__(self) -> None:
        self.rename_calls = 0
        self.comment_calls = 0

    def read_dword(self, address: int) -> int:
        return 0x2000

    def get_function_by_address(self, address: int):
        return {"name": "target_func", "comment": ""}

    def rename_function(self, address: int, new_name: str) -> bool:
        self.rename_calls += 1
        return True

    def set_decompiler_comment(self, address: int, comment: str) -> bool:
        self.comment_calls += 1
        return True


def test_slot_process_respects_enable_writes_flag() -> None:
    client = _StubClient()
    adapter = _StubAdapter()
    original_flag = config.ENABLE_WRITES
    config.ENABLE_WRITES = False
    try:
        result = jt.slot_process(
            client,
            jt_base=0x1000,
            slot_index=0,
            code_min=0x0,
            code_max=0xFFFF,
            rename_pattern="handler_{slot}",
            comment="JT slot",
            adapter=adapter,
            dry_run=False,
        )
    finally:
        config.ENABLE_WRITES = original_flag

    assert result["errors"] == ["WRITE_DISABLED_DRY_RUN"]
    assert client.rename_calls == 0
    assert client.comment_calls == 0
