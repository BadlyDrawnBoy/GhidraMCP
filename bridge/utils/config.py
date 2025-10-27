"""Runtime configuration helpers for the bridge server."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Final, Optional


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

_audit_log_env = os.getenv("GHIDRA_MCP_AUDIT_LOG", "").strip()
AUDIT_LOG_PATH: Final[Optional[Path]] = (
    Path(_audit_log_env).expanduser() if _audit_log_env else None
)


__all__ = [
    "AUDIT_LOG_PATH",
    "ENABLE_WRITES",
    "MAX_ITEMS_PER_BATCH",
    "MAX_WRITES_PER_REQUEST",
]
