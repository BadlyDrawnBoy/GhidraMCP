"""MMIO annotation helpers."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Dict, Iterable, List, Optional

from ..ghidra.client import GhidraClient
from ..utils.config import ENABLE_WRITES
from ..utils.errors import ErrorCode
from ..utils.hex import int_to_hex


class WritesDisabledError(RuntimeError):
    """Raised when a write is requested but writes are disabled."""


_ADDRESS_RE = re.compile(r"^\s*([0-9A-Fa-f]+):\s*(.+?)\s*$")
_HEX_RE = re.compile(r"0x[0-9a-fA-F]+")


@dataclass(slots=True)
class _Operation:
    addr: int
    op: str
    target: Optional[int]

    def to_sample(self) -> Dict[str, str]:
        return {
            "addr": int_to_hex(self.addr),
            "op": self.op,
            "target": int_to_hex(self.target) if self.target is not None else "0x00000000",
        }


def _parse_line(line: str) -> Optional[tuple[int, str, str]]:
    match = _ADDRESS_RE.match(line)
    if not match:
        return None
    try:
        addr = int(match.group(1), 16)
    except ValueError:
        return None
    instruction = match.group(2).strip()
    if not instruction:
        return None
    parts = instruction.split(None, 1)
    mnemonic = parts[0].upper()
    operands = parts[1] if len(parts) > 1 else ""
    if "." in mnemonic:
        mnemonic = mnemonic.split(".", 1)[0]
    return addr, mnemonic, operands


def _classify(mnemonic: str) -> Optional[str]:
    if mnemonic.startswith("LD"):
        return "READ"
    if mnemonic.startswith("ST"):
        return "WRITE"
    if mnemonic.startswith("ORR") or mnemonic == "OR" or mnemonic.startswith("ORI"):
        return "OR"
    if mnemonic.startswith("AND") or mnemonic.startswith("BIC"):
        return "AND"
    if mnemonic.startswith("EOR") or mnemonic.startswith("XOR"):
        return "TOGGLE"
    return None


def _extract_target(operands: str) -> Optional[int]:
    match = _HEX_RE.search(operands)
    if not match:
        return None
    try:
        return int(match.group(0), 16)
    except ValueError:
        return None


def _collect_operations(disassembly: Iterable[str]) -> List[_Operation]:
    operations: List[_Operation] = []
    for line in disassembly:
        parsed = _parse_line(line)
        if not parsed:
            continue
        addr, mnemonic, operands = parsed
        op = _classify(mnemonic)
        if not op:
            continue
        target = _extract_target(operands)
        operations.append(_Operation(addr=addr, op=op, target=target))
    return operations


def annotate(
    client: GhidraClient,
    *,
    function_addr: int,
    dry_run: bool = True,
    max_samples: int = 8,
    writes_enabled: bool = ENABLE_WRITES,
) -> Dict[str, object]:
    if not dry_run and not writes_enabled:
        raise WritesDisabledError(ErrorCode.WRITE_DISABLED_DRY_RUN.value)

    disassembly = client.disassemble_function(function_addr)
    operations = _collect_operations(disassembly)

    reads = sum(1 for op in operations if op.op == "READ")
    writes = sum(1 for op in operations if op.op == "WRITE")
    bitwise_or = sum(1 for op in operations if op.op == "OR")
    bitwise_and = sum(1 for op in operations if op.op == "AND")
    toggles = sum(1 for op in operations if op.op == "TOGGLE")

    samples = [op.to_sample() for op in operations[:max_samples]]

    annotated = 0
    if not dry_run and writes_enabled and samples:
        for op in operations[:max_samples]:
            comment = _format_comment(op)
            if client.set_disassembly_comment(op.addr, comment):
                annotated += 1

    return {
        "function": int_to_hex(function_addr),
        "reads": reads,
        "writes": writes,
        "bitwise_or": bitwise_or,
        "bitwise_and": bitwise_and,
        "toggles": toggles,
        "annotated": annotated,
        "samples": samples,
    }


def _format_comment(operation: _Operation) -> str:
    target = int_to_hex(operation.target) if operation.target is not None else "0x00000000"
    if operation.op == "READ":
        action = "read"
    elif operation.op == "WRITE":
        action = "write"
    elif operation.op == "OR":
        action = "bitwise OR"
    elif operation.op == "AND":
        action = "bitwise AND"
    else:
        action = "toggle"
    return f"MMIO {action} target {target}"


__all__ = ["annotate", "WritesDisabledError"]
