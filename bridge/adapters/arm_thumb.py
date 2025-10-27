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

    def probe_function(self, client, ptr: int) -> tuple[str | None, int | None]:
        candidates: list[tuple[str, int]] = []
        if ptr % self.code_alignment == 0:
            candidates.append(("ARM", ptr))
        if ptr % self.code_alignment == 1 and ptr > 0:
            candidates.append(("Thumb", ptr - 1))
        for mode, target in candidates:
            if self._verify_candidate(client, target):
                return mode, target
        return None, None

    def _verify_candidate(self, client, target: int) -> bool:
        disasm = client.disassemble_function(target)
        if not disasm:
            return False
        meta = client.get_function_by_address(target)
        if not meta:
            return False
        entry_point: Any = meta.get("entry_point") or meta.get("address")
        if isinstance(entry_point, int) and entry_point != target:
            return False
        return True


__all__ = ["ARMThumbAdapter", "ProbeResult"]
