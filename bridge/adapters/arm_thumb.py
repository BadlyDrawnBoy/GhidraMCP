"""ARM/Thumb adapter implementation."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import ArchAdapter, ProbeResult

BX_SENTINELS = {0xE12FFF1C, 0xE12FFF33}


@dataclass(slots=True)
class ARMThumbAdapter(ArchAdapter):
    code_alignment: int = 4

    def in_code_range(self, ptr: int, code_min: int, code_max: int) -> bool:
        return code_min <= ptr < code_max

    def is_instruction_sentinel(self, raw: int) -> bool:
        return raw in BX_SENTINELS

    def probe_function(
        self, client, ptr: int, code_min: int, code_max: int
    ) -> tuple[str | None, int | None]:
        candidates: list[tuple[str, int]] = []
        if self.in_code_range(ptr, code_min, code_max):
            candidates.append(("ARM", ptr))
        thumb_target = ptr - 1
        if ptr & 1 and thumb_target >= 0 and self.in_code_range(thumb_target, code_min, code_max):
            candidates.append(("Thumb", thumb_target))
        seen: set[int] = set()
        for mode, target in candidates:
            if target < 0 or target in seen:
                continue
            seen.add(target)
            if self._verify_candidate(client, target):
                return mode, target
        return None, None

    def _verify_candidate(self, client, target: int) -> bool:
        disasm = client.disassemble_function(target)
        if disasm:
            meta = client.get_function_by_address(target)
            if meta:
                entry_point: Any = meta.get("entry_point") or meta.get("address")
                if isinstance(entry_point, int) and entry_point != target:
                    return False
            return True
        meta = client.get_function_by_address(target)
        if not meta:
            return False
        entry_point: Any = meta.get("entry_point") or meta.get("address")
        if not isinstance(entry_point, int) or entry_point != target:
            return False
        return True


__all__ = ["ARMThumbAdapter", "ProbeResult"]
