"""Runtime configuration helpers for the bridge server."""
from __future__ import annotations

import os
from typing import Final


def _parse_bool(value: str | None, *, default: bool = False) -> bool:
    if value is None:
        return default
    value = value.strip().lower()
    return value in {"1", "true", "yes", "on"}


def _env(name: str, *, default: bool = False) -> bool:
    return _parse_bool(os.getenv(name), default=default)


ENABLE_WRITES: Final[bool] = _env("GHIDRA_MCP_ENABLE_WRITES", default=False)


__all__ = ["ENABLE_WRITES"]
