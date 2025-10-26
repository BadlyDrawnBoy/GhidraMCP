"""Jump table helpers for deterministic endpoints."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from ..adapters import ArchAdapter
from ..ghidra.client import GhidraClient
from ..utils.config import ENABLE_WRITES
from ..utils.errors import ErrorCode
from ..utils.hex import int_to_hex, slot_address


@dataclass(slots=True)
class JTSlotResult:
    slot: int
    slot_addr: str
    raw: str
    mode: str
    target: Optional[str]
    notes: List[str]
    errors: List[str]

    def to_dict(self) -> Dict[str, object]:
        return {
            "slot": self.slot,
            "slot_addr": self.slot_addr,
            "raw": self.raw,
            "mode": self.mode,
            "target": self.target,
            "notes": self.notes,
            "errors": self.errors,
        }


@dataclass(slots=True)
class JTProcessResult(JTSlotResult):
    renamed: bool
    comment_set: bool
    verify_name: Optional[str]
    comment_present: bool

    def to_dict(self) -> Dict[str, object]:
        payload = super().to_dict()
        payload.update(
            {
                "writes": {"renamed": self.renamed, "comment_set": self.comment_set},
                "verify": {"name": self.verify_name, "comment_present": self.comment_present},
            }
        )
        return payload


def slot_check(
    client: GhidraClient,
    *,
    jt_base: int,
    slot_index: int,
    code_min: int,
    code_max: int,
    adapter: ArchAdapter,
) -> Dict[str, object]:
    addr = slot_address(jt_base, slot_index)
    raw_val = client.read_dword(addr)
    result = JTSlotResult(
        slot=slot_index,
        slot_addr=int_to_hex(addr),
        raw=int_to_hex(raw_val) if raw_val is not None else "0x00000000",
        mode="none",
        target=None,
        notes=[],
        errors=[],
    )
    if raw_val is None:
        result.errors.append(ErrorCode.TOOL_BINDING_MISSING.value)
        return result.to_dict()
    if not adapter.in_code_range(raw_val, code_min, code_max):
        result.errors.append(ErrorCode.OUT_OF_RANGE.value)
        return result.to_dict()
    if adapter.is_instruction_sentinel(raw_val):
        result.errors.append(ErrorCode.ARM_INSTRUCTION.value)
        return result.to_dict()
    mode, target = adapter.probe_function(raw_val)
    if mode and target is not None:
        result.mode = mode
        result.target = int_to_hex(target)
    else:
        result.errors.append(ErrorCode.NO_FUNCTION_AT_TARGET.value)
    return result.to_dict()


def slot_process(
    client: GhidraClient,
    *,
    jt_base: int,
    slot_index: int,
    code_min: int,
    code_max: int,
    rename_pattern: str,
    comment: str,
    adapter: ArchAdapter,
    dry_run: bool = True,
    writes_enabled: bool = ENABLE_WRITES,
) -> Dict[str, object]:
    check = slot_check(
        client,
        jt_base=jt_base,
        slot_index=slot_index,
        code_min=code_min,
        code_max=code_max,
        adapter=adapter,
    )
    result = JTProcessResult(
        slot=check["slot"],
        slot_addr=check["slot_addr"],
        raw=check["raw"],
        mode=check["mode"],
        target=check["target"],
        notes=check.get("notes", []),
        errors=list(check.get("errors", [])),
        renamed=False,
        comment_set=False,
        verify_name=None,
        comment_present=False,
    )
    if result.errors or not result.target:
        if dry_run is False and not result.errors:
            result.errors.append(ErrorCode.NO_FUNCTION_AT_TARGET.value)
        return result.to_dict()
    if not dry_run and not writes_enabled:
        result.errors.append(ErrorCode.WRITE_DISABLED_DRY_RUN.value)
        return result.to_dict()
    target_int = int(result.target, 16)
    if dry_run:
        meta = client.get_function_by_address(target_int)
        result.verify_name = meta.get("name") if meta else None
        return result.to_dict()
    try:
        new_name = rename_pattern.format(slot=result.slot, target=result.target)
    except KeyError as exc:
        result.errors.append(f"FORMAT_ERROR:{exc}")
        return result.to_dict()
    if client.rename_function(target_int, new_name):
        result.renamed = True
    else:
        result.errors.append(ErrorCode.WRITE_VERIFY_FAILED.value)
    if client.set_decompiler_comment(target_int, comment):
        result.comment_set = True
    else:
        result.errors.append(ErrorCode.WRITE_VERIFY_FAILED.value)
    meta = client.get_function_by_address(target_int)
    if meta:
        result.verify_name = meta.get("name")
        result.comment_present = bool(meta.get("comment")) if isinstance(meta, dict) else False
    else:
        result.errors.append(ErrorCode.WRITE_VERIFY_FAILED.value)
    return result.to_dict()


def scan(
    client: GhidraClient,
    *,
    jt_base: int,
    start: int,
    count: int,
    code_min: int,
    code_max: int,
    adapter: ArchAdapter,
) -> Dict[str, object]:
    items: List[Dict[str, object]] = []
    valid = invalid = 0
    for offset in range(start, start + count):
        item = slot_check(
            client,
            jt_base=jt_base,
            slot_index=offset,
            code_min=code_min,
            code_max=code_max,
            adapter=adapter,
        )
        items.append(item)
        if item["errors"]:
            invalid += 1
        else:
            valid += 1
    summary = {"total": len(items), "valid": valid, "invalid": invalid}
    return {
        "range": {"start": start, "count": count},
        "summary": summary,
        "items": items,
    }


__all__ = ["slot_check", "slot_process", "scan"]
