"""MMIO annotation helpers backed by the disassembly endpoint."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Dict, Iterable, List, Optional

from ..ghidra.client import GhidraClient
from ..utils.hex import int_to_hex

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------

# Writes are disabled by default so that analysis can safely run in read-only
# scenarios (e.g., schema validation during tests or local dry runs). Set to
# ``True`` when writes should be attempted.
ENABLE_WRITES = False

COMMENT_PREFIX = "[MMIO]"


# ---------------------------------------------------------------------------
# parsing helpers
# ---------------------------------------------------------------------------

LINE_RE = re.compile(r"^(?P<addr>0x[0-9a-fA-F]+):\s*(?P<body>[^;]*?)(?:\s*;\s*(?P<comment>.*))?$")
BRACKET_RE = re.compile(r"\[(.*?)\]")
ADDRESS_TOKEN_RE = re.compile(r"(?:0x|DAT_)([0-9a-fA-F]+)")
IMM_HEX_RE = re.compile(r"#?-?0x[0-9a-fA-F]+")
IMM_DEC_RE = re.compile(r"#-?\d+")
REGISTER_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9]*")

READ_MNEMONICS = {
    "ldr",
    "ldrb",
    "ldrh",
    "ldrd",
    "ldrsb",
    "ldrsh",
    "ldrsw",
    "ldur",
    "ldp",
}

WRITE_MNEMONICS = {
    "str",
    "strb",
    "strh",
    "strd",
    "stur",
    "stp",
}

OR_MNEMONICS = {"orr", "or", "orrs", "orr.w"}
AND_MNEMONICS = {"and", "ands", "bic", "bic.w"}
TOGGLE_MNEMONICS = {"eor", "xor", "eors", "eor.w", "xors"}


@dataclass(slots=True)
class InstructionRow:
    """Parsed representation of a disassembly line."""

    address: int
    mnemonic: str
    operands: str
    comment: str

    @property
    def dest_register(self) -> Optional[str]:
        if not self.operands:
            return None
        first, *_ = [part.strip() for part in self.operands.split(",", 1)]
        if not first:
            return None
        match = REGISTER_RE.match(first)
        return match.group(0).upper() if match else None

    @property
    def memory_targets(self) -> List[int]:
        targets: List[int] = []
        for bracket_content in BRACKET_RE.findall(self.operands):
            for match in ADDRESS_TOKEN_RE.finditer(bracket_content):
                try:
                    targets.append(int(match.group(1), 16))
                except ValueError:
                    continue
        return targets

    def immediate_value(self) -> Optional[int]:
        match = IMM_HEX_RE.search(self.operands)
        if match:
            token = match.group(0).lstrip("#")
            try:
                return int(token, 16)
            except ValueError:
                return None
        match = IMM_DEC_RE.search(self.operands)
        if match:
            token = match.group(0).lstrip("#")
            try:
                return int(token, 10)
            except ValueError:
                return None
        return None


@dataclass(slots=True)
class _MMIOOperation:
    address: int
    op: str
    target: int
    comment: str


def _parse_disassembly(lines: Iterable[str]) -> List[InstructionRow]:
    instructions: List[InstructionRow] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        match = LINE_RE.match(line)
        if not match:
            continue
        addr_str = match.group("addr")
        body = match.group("body").strip()
        comment = match.group("comment") or ""
        mnemonic, _, operands = body.partition(" ")
        if not mnemonic:
            continue
        try:
            address = int(addr_str, 16)
        except ValueError:
            continue
        instructions.append(
            InstructionRow(
                address=address,
                mnemonic=mnemonic.strip().lower(),
                operands=operands.strip(),
                comment=comment.strip(),
            )
        )
    return instructions


def _format_comment(op: str, target: int, immediate: Optional[int] = None) -> str:
    base = f"{COMMENT_PREFIX} {op} {int_to_hex(target)}"
    if immediate is not None:
        base = f"{base} ({int_to_hex(immediate)})"
    return base


def annotate(
    client: GhidraClient,
    *,
    function_addr: int,
    dry_run: bool = True,
    max_samples: int = 8,
) -> Dict[str, object]:
    lines = client.disassemble_function(function_addr)
    instructions = _parse_disassembly(lines)

    reads = writes = toggles = 0
    bitwise_or = 0
    bitwise_and: Optional[int] = None
    register_targets: Dict[str, int] = {}
    operations: List[_MMIOOperation] = []

    for instr in instructions:
        mnemonic = instr.mnemonic
        dest_reg = instr.dest_register
        targets = instr.memory_targets
        handled = False

        if mnemonic in READ_MNEMONICS and targets:
            target = targets[0]
            reads += 1
            if dest_reg:
                register_targets[dest_reg] = target
            operations.append(
                _MMIOOperation(
                    address=instr.address,
                    op="READ",
                    target=target,
                    comment=_format_comment("READ", target),
                )
            )
            handled = True

        if mnemonic in WRITE_MNEMONICS and targets:
            target = targets[0]
            writes += 1
            operations.append(
                _MMIOOperation(
                    address=instr.address,
                    op="WRITE",
                    target=target,
                    comment=_format_comment("WRITE", target),
                )
            )
            handled = True

        if mnemonic in OR_MNEMONICS:
            target = register_targets.get(dest_reg) if dest_reg else None
            if target is not None:
                immediate = instr.immediate_value()
                if immediate is not None:
                    bitwise_or |= immediate
                operations.append(
                    _MMIOOperation(
                        address=instr.address,
                        op="OR",
                        target=target,
                        comment=_format_comment("OR", target, immediate),
                    )
                )
                handled = True

        if mnemonic in AND_MNEMONICS:
            target = register_targets.get(dest_reg) if dest_reg else None
            if target is not None:
                immediate = instr.immediate_value()
                if immediate is not None:
                    bitwise_and = immediate if bitwise_and is None else bitwise_and & immediate
                operations.append(
                    _MMIOOperation(
                        address=instr.address,
                        op="AND",
                        target=target,
                        comment=_format_comment("AND", target, immediate),
                    )
                )
                handled = True

        if mnemonic in TOGGLE_MNEMONICS:
            target = register_targets.get(dest_reg) if dest_reg else None
            if target is not None:
                toggles += 1
                operations.append(
                    _MMIOOperation(
                        address=instr.address,
                        op="TOGGLE",
                        target=target,
                        comment=_format_comment("TOGGLE", target),
                    )
                )
                handled = True

        if not handled and dest_reg and dest_reg in register_targets:
            register_targets.pop(dest_reg, None)

    samples: List[Dict[str, str]] = []
    annotated = 0

    if max_samples > 0:
        for op in operations[:max(0, max_samples)]:
            samples.append(
                {"addr": int_to_hex(op.address), "op": op.op, "target": int_to_hex(op.target)}
            )

    if not dry_run and ENABLE_WRITES and samples:
        expected_comments: Dict[int, str] = {}
        for op in operations[: len(samples)]:
            if client.set_disassembly_comment(op.address, op.comment):
                expected_comments[op.address] = op.comment
        if expected_comments:
            refreshed = _parse_disassembly(client.disassemble_function(function_addr))
            comment_lookup = {row.address: row.comment for row in refreshed}
            for addr, text in expected_comments.items():
                if comment_lookup.get(addr) == text:
                    annotated += 1
    elif not dry_run and not ENABLE_WRITES:
        annotated = 0

    return {
        "function": int_to_hex(function_addr),
        "reads": reads,
        "writes": writes,
        "bitwise_or": bitwise_or,
        "bitwise_and": bitwise_and if bitwise_and is not None else 0,
        "toggles": toggles,
        "annotated": annotated,
        "samples": samples,
    }


__all__ = ["annotate", "ENABLE_WRITES"]
