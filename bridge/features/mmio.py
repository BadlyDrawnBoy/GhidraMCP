"""MMIO annotation helpers (placeholder implementation)."""
from __future__ import annotations

from typing import Dict, List

from ..ghidra.client import GhidraClient
from ..utils.config import ENABLE_WRITES
from ..utils.errors import ErrorCode
from ..utils.hex import int_to_hex


class WritesDisabledError(RuntimeError):
    """Raised when a write is requested but writes are disabled."""


def annotate(
    client: GhidraClient,
    *,
    function_addr: int,
    dry_run: bool = True,
    max_samples: int = 8,
    writes_enabled: bool = ENABLE_WRITES,
) -> Dict[str, object]:
    if not dry_run and not writes_enabled:
        raise WritesDisabledError(ErrorCode.WRITE_DISABLED_DRY_RUN.value)
    # The detailed analysis requires instruction decoding which will be implemented
    # in a future iteration. For now we return a deterministic placeholder so the
    # API surface is wired and covered by schema validation.
    return {
        "function": int_to_hex(function_addr),
        "reads": 0,
        "writes": 0,
        "bitwise_or": 0,
        "bitwise_and": 0,
        "toggles": 0,
        "annotated": 0 if dry_run else 0,
        "samples": [],
    }


__all__ = ["annotate", "WritesDisabledError"]
