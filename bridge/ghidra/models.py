"""Lightweight type hints for Ghidra responses."""
from __future__ import annotations

from typing import TypedDict, NotRequired


class FunctionMeta(TypedDict, total=False):
    name: str
    entry_point: int
    address: NotRequired[int]


class Xref(TypedDict):
    addr: int
    context: str
