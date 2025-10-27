"""Runtime configuration helpers for the bridge server."""
from __future__ import annotations

import os
from typing import Final


def _parse_bool(value: str | None, *, default: bool = False) -> bool:
    if value is None:
        return default
    value = value.strip().lower()
    return value in {"1", "true", "yes", "on"}


def _parse_int(value: str | None, *, default: int) -> int:
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_bool(name: str, *, default: bool = False) -> bool:
    return _parse_bool(os.getenv(name), default=default)


def _env_int(name: str, *, default: int) -> int:
    return _parse_int(os.getenv(name), default=default)


ENABLE_WRITES: Final[bool] = _env_bool("GHIDRA_MCP_ENABLE_WRITES", default=False)
MAX_WRITES_PER_REQUEST: Final[int] = _env_int("GHIDRA_MCP_MAX_WRITES_PER_REQUEST", default=2)
MAX_ITEMS_PER_BATCH: Final[int] = _env_int("GHIDRA_MCP_MAX_ITEMS_PER_BATCH", default=256)


__all__ = ["ENABLE_WRITES", "MAX_WRITES_PER_REQUEST", "MAX_ITEMS_PER_BATCH"]
