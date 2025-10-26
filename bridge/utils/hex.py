"""Hex helpers shared across bridge features."""
from __future__ import annotations

from typing import Iterable


def int_to_hex(value: int) -> str:
    """Return a canonical hex string for addresses or values."""

    return f"0x{value:08x}" if value >= 0 else f"-0x{abs(value):08x}"


def parse_hex(value: str) -> int:
    """Parse a hex string into an integer."""

    value = value.strip()
    if value.lower().startswith("0x"):
        return int(value, 16)
    return int(value, 16)


def slot_address(jt_base: int, slot_index: int) -> int:
    """Calculate the absolute address of a jump-table slot."""

    return jt_base + 4 * slot_index


def clamp_collection(items: Iterable, limit: int):
    """Yield items up to *limit* entries."""

    count = 0
    for item in items:
        if count >= limit:
            break
        count += 1
        yield item
