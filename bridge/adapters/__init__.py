"""Architecture adapter interfaces."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, Tuple

if TYPE_CHECKING:  # pragma: no cover - import only used for typing
    from ..ghidra.client import GhidraClient


class ArchAdapter(Protocol):
    """Strategy interface for architecture specific behaviour."""

    def in_code_range(self, ptr: int, code_min: int, code_max: int) -> bool:
        ...

    def is_instruction_sentinel(self, raw: int) -> bool:
        ...

    def probe_function(self, client: "GhidraClient", ptr: int) -> Tuple[str | None, int | None]:
        ...


@dataclass(slots=True)
class ProbeResult:
    mode: str | None
    target: int | None
