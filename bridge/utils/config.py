"""Runtime configuration flags for bridge features."""
from __future__ import annotations

# Feature writes are disabled by default to keep automated analysis read-only.
ENABLE_WRITES: bool = False

__all__ = ["ENABLE_WRITES"]
