"""Architecture adapter interfaces and registry helpers."""
from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import TYPE_CHECKING, Dict, Mapping, Protocol, Tuple

if TYPE_CHECKING:  # pragma: no cover - import only used for typing
    from ..ghidra.client import GhidraClient


class ArchAdapter(Protocol):
    """Strategy interface for architecture specific behaviour."""

    def in_code_range(self, ptr: int, code_min: int, code_max: int) -> bool:
        ...

    def is_instruction_sentinel(self, raw: int) -> bool:
        ...

    def probe_function(
        self, client: "GhidraClient", ptr: int, code_min: int, code_max: int
    ) -> Tuple[str | None, int | None]:
        ...


@dataclass(slots=True)
class ProbeResult:
    mode: str | None
    target: int | None


# Optional adapters are registered via module paths to keep imports lazy.
_OPTIONAL_ADAPTERS: Dict[str, str] = {
    "x86": "bridge.adapters.x86:X86Adapter",
    "i386": "bridge.adapters.x86:X86Adapter",
}


def optional_adapter_names() -> Mapping[str, str]:
    """Return a mapping of optional adapter names to their import paths."""

    return dict(_OPTIONAL_ADAPTERS)


def load_optional_adapter(name: str) -> ArchAdapter:
    """Instantiate an optional adapter by name without eager imports."""

    key = name.lower()
    module_spec = _OPTIONAL_ADAPTERS[key]
    module_name, attr = module_spec.split(":", 1)
    module = import_module(module_name)
    adapter_cls = getattr(module, attr)
    return adapter_cls()


__all__ = [
    "ArchAdapter",
    "ProbeResult",
    "load_optional_adapter",
    "optional_adapter_names",
]
