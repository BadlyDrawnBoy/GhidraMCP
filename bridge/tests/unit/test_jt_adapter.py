"""Unit tests for the ARM/Thumb jump-table adapter."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

import pytest

from bridge.adapters.arm_thumb import ARMThumbAdapter, BX_SENTINELS
from bridge.features.jt import slot_check
from bridge.utils.errors import ErrorCode


@dataclass
class StubGhidraClient:
    """Minimal stub used to exercise adapter behaviour."""

    dwords: Dict[int, int] = field(default_factory=dict)
    disassembly: Dict[int, List[str]] = field(default_factory=dict)
    functions: Dict[int, Dict[str, object]] = field(default_factory=dict)
    disassemble_calls: List[int] = field(default_factory=list)
    function_calls: List[int] = field(default_factory=list)

    def read_dword(self, address: int) -> int | None:
        return self.dwords.get(address)

    def disassemble_function(self, address: int) -> List[str]:
        self.disassemble_calls.append(address)
        return list(self.disassembly.get(address, ()))

    def get_function_by_address(self, address: int) -> Dict[str, object] | None:
        self.function_calls.append(address)
        return self.functions.get(address)


@pytest.fixture
def adapter() -> ARMThumbAdapter:
    return ARMThumbAdapter()


def _slot_addr(jt_base: int, slot_index: int) -> int:
    return jt_base + 4 * slot_index


def test_slot_check_flags_instruction_word(adapter: ARMThumbAdapter) -> None:
    jt_base = 0x2000
    addr = _slot_addr(jt_base, 0)
    client = StubGhidraClient(dwords={addr: min(BX_SENTINELS)})

    result = slot_check(
        client,
        jt_base=jt_base,
        slot_index=0,
        code_min=0x1000,
        code_max=0x4000,
        adapter=adapter,
    )

    assert result["errors"] == [ErrorCode.ARM_INSTRUCTION.value]
    assert client.disassemble_calls == []
    assert client.function_calls == []


def test_slot_check_out_of_range(adapter: ARMThumbAdapter) -> None:
    jt_base = 0x2000
    addr = _slot_addr(jt_base, 1)
    client = StubGhidraClient(dwords={addr: 0x5000})

    result = slot_check(
        client,
        jt_base=jt_base,
        slot_index=1,
        code_min=0x1000,
        code_max=0x3000,
        adapter=adapter,
    )

    assert result["errors"] == [ErrorCode.OUT_OF_RANGE.value]
    assert client.disassemble_calls == []
    assert client.function_calls == []


def test_slot_check_enforces_half_open_upper_bound(adapter: ARMThumbAdapter) -> None:
    jt_base = 0x2000
    addr = _slot_addr(jt_base, 4)
    code_min = 0x2400
    code_max = code_min + 4
    client = StubGhidraClient(dwords={addr: code_max})

    result = slot_check(
        client,
        jt_base=jt_base,
        slot_index=4,
        code_min=code_min,
        code_max=code_max,
        adapter=adapter,
    )

    assert result["errors"] == [ErrorCode.OUT_OF_RANGE.value]
    assert client.disassemble_calls == []
    assert client.function_calls == []


def test_slot_check_arm_candidate_verified(adapter: ARMThumbAdapter) -> None:
    jt_base = 0x2000
    addr = _slot_addr(jt_base, 2)
    target = 0x2400
    client = StubGhidraClient(
        dwords={addr: target},
        disassembly={target: ["push {lr}"]},
        functions={target: {"entry_point": target, "name": "func_2400"}},
    )

    result = slot_check(
        client,
        jt_base=jt_base,
        slot_index=2,
        code_min=0x2000,
        code_max=0x3000,
        adapter=adapter,
    )

    assert result["errors"] == []
    assert result["mode"] == "ARM"
    assert result["target"] == "0x00002400"
    assert client.disassemble_calls == [target]
    assert client.function_calls == [target]


def test_slot_check_thumb_candidate_verified(adapter: ARMThumbAdapter) -> None:
    jt_base = 0x2000
    addr = _slot_addr(jt_base, 3)
    thumb_ptr = 0x2601
    real_target = thumb_ptr - 1
    client = StubGhidraClient(
        dwords={addr: thumb_ptr},
        disassembly={real_target: ["push {r4, lr}"]},
        functions={real_target: {"entry_point": real_target, "name": "thumb_func"}},
    )

    result = slot_check(
        client,
        jt_base=jt_base,
        slot_index=3,
        code_min=0x2000,
        code_max=0x3000,
        adapter=adapter,
    )

    assert result["errors"] == []
    assert result["mode"] == "Thumb"
    assert result["target"] == "0x00002600"
    assert client.disassemble_calls[0] == thumb_ptr
    assert client.disassemble_calls[-1] == real_target
    assert client.function_calls == [real_target]


def test_slot_check_accepts_lower_bound(adapter: ARMThumbAdapter) -> None:
    jt_base = 0x2000
    addr = _slot_addr(jt_base, 5)
    code_min = 0x2800
    code_max = code_min + 8
    client = StubGhidraClient(
        dwords={addr: code_min},
        disassembly={code_min: ["push {lr}"]},
        functions={code_min: {"entry_point": code_min, "name": "lower_bound"}},
    )

    result = slot_check(
        client,
        jt_base=jt_base,
        slot_index=5,
        code_min=code_min,
        code_max=code_max,
        adapter=adapter,
    )

    assert result["errors"] == []
    assert result["mode"] == "ARM"
    assert result["target"] == "0x00002800"
    assert client.disassemble_calls == [code_min]
    assert client.function_calls == [code_min]
