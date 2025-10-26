"""ARM/Thumb adapter implementation."""
from __future__ import annotations

from dataclasses import dataclass

from . import ArchAdapter, ProbeResult

BX_SENTINELS = {0xE12FFF1C, 0xE12FFF33}


@dataclass(slots=True)
class ARMThumbAdapter(ArchAdapter):
    code_alignment: int = 4

    def in_code_range(self, ptr: int, code_min: int, code_max: int) -> bool:
        return code_min <= ptr <= code_max

    def is_instruction_sentinel(self, raw: int) -> bool:
        return raw in BX_SENTINELS

    def probe_function(self, ptr: int) -> tuple[str | None, int | None]:
        if ptr % self.code_alignment == 0:
            return "ARM", ptr
        if ptr % self.code_alignment == 1:
            return "Thumb", ptr - 1
        return None, None


__all__ = ["ARMThumbAdapter", "ProbeResult"]
