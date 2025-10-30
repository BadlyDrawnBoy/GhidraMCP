"""x86 adapter stub used when optional adapters are enabled."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import ArchAdapter, ProbeResult


@dataclass(slots=True)
class X86Adapter(ArchAdapter):
    """Minimal x86 adapter that mirrors the ARM baseline contract."""

    code_alignment: int = 1

    def in_code_range(self, ptr: int, code_min: int, code_max: int) -> bool:
        return code_min <= ptr < code_max

    def is_instruction_sentinel(self, raw: int) -> bool:  # pragma: no cover - no sentinel
        return False

    def probe_function(
        self, client, ptr: int, code_min: int, code_max: int
    ) -> tuple[str | None, int | None]:
        if not self.in_code_range(ptr, code_min, code_max):
            return None, None

        if client.disassemble_function(ptr):
            return "x86", ptr

        meta = client.get_function_by_address(ptr)
        if isinstance(meta, dict):
            entry_point: Any = meta.get("entry_point") or meta.get("address")
            if isinstance(entry_point, int) and entry_point == ptr:
                return "x86", ptr

        return None, None


__all__ = ["X86Adapter", "ProbeResult"]
