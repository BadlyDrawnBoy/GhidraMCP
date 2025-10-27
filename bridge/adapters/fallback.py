"""Fallback architecture adapter that only performs range checking."""
from __future__ import annotations

from dataclasses import dataclass

from . import ArchAdapter


@dataclass(slots=True)
class FallbackAdapter(ArchAdapter):
    def in_code_range(self, ptr: int, code_min: int, code_max: int) -> bool:
        return code_min <= ptr < code_max

    def is_instruction_sentinel(self, raw: int) -> bool:  # pragma: no cover - trivial
        return False

    def probe_function(self, client, ptr: int) -> tuple[str | None, int | None]:  # pragma: no cover - fallback does nothing
        return None, None


__all__ = ["FallbackAdapter"]
