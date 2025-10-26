"""Architecture adapter interfaces."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Tuple


class ArchAdapter(Protocol):
    """Strategy interface for architecture specific behaviour."""

    def in_code_range(self, ptr: int, code_min: int, code_max: int) -> bool:
        ...

    def is_instruction_sentinel(self, raw: int) -> bool:
        ...

    def probe_function(self, ptr: int) -> Tuple[str | None, int | None]:
        ...


@dataclass(slots=True)
class ProbeResult:
    mode: str | None
    target: int | None
