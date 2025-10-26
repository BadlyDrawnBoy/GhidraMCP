"""Unit tests for the MMIO feature helpers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple

from bridge.features import mmio
from bridge.utils import config
from bridge.utils.hex import int_to_hex


@dataclass
class FakeInstruction:
    address: int
    text: str


class FakeGhidraClient:
    """Minimal stub emulating the pieces of :class:`GhidraClient` that we use."""

    def __init__(self, instructions: Iterable[Tuple[int, str]]) -> None:
        self._instructions = [FakeInstruction(addr, text) for addr, text in instructions]
        self._comments: Dict[int, str] = {}
        self.calls: Dict[str, int] = {"disassemble": 0, "set_comment": 0}

    def disassemble_function(self, address: int) -> List[str]:  # pragma: no cover - simple glue
        self.calls["disassemble"] += 1
        lines: List[str] = []
        for inst in self._instructions:
            comment = self._comments.get(inst.address)
            suffix = f" ; {comment}" if comment else ""
            lines.append(f"{int_to_hex(inst.address)}: {inst.text}{suffix}")
        return lines

    def set_disassembly_comment(self, address: int, comment: str) -> bool:
        self.calls["set_comment"] += 1
        self._comments[address] = comment
        return True


def _make_client() -> FakeGhidraClient:
    instructions = [
        (0x1000, "LDR R0, [0x40020000]"),
        (0x1004, "ORR R0, R0, #0x4"),
        (0x1008, "STR R0, [0x40020000]"),
        (0x100C, "EOR R0, R0, #0x2"),
        (0x1010, "AND R0, R0, #0xFF"),
        (0x1014, "STR R1, [0x40020004]"),
    ]
    return FakeGhidraClient(instructions)


def test_mmio_annotate_collects_statistics_without_writes() -> None:
    client = _make_client()
    result = mmio.annotate(client, function_addr=0x1000, dry_run=True, max_samples=4)

    assert result["reads"] == 1
    assert result["writes"] == 2
    assert result["toggles"] == 1
    assert result["bitwise_or"] == 0x4
    assert result["bitwise_and"] == 0xFF
    assert len(result["samples"]) == 4
    assert result["samples"][0] == {
        "addr": "0x00001000",
        "op": "READ",
        "target": "0x40020000",
    }
    assert client.calls["set_comment"] == 0


def test_mmio_annotate_writes_comments_when_enabled() -> None:
    client = _make_client()
    original_flag = config.ENABLE_WRITES
    config.ENABLE_WRITES = True
    try:
        result = mmio.annotate(client, function_addr=0x1000, dry_run=False, max_samples=2)
    finally:
        config.ENABLE_WRITES = original_flag

    assert client.calls["set_comment"] == 2
    assert result["annotated"] == 2
