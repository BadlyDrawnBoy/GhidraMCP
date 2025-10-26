"""Compact string cross reference helpers."""
from __future__ import annotations

from typing import Dict, List

from ..ghidra.client import GhidraClient
from ..utils.hex import int_to_hex


def xrefs_compact(client: GhidraClient, *, string_addr: int, limit: int = 50) -> Dict[str, object]:
    refs = client.get_xrefs_to(string_addr, limit=limit)
    callers: List[Dict[str, str]] = [
        {"addr": int_to_hex(ref["addr"]), "context": ref.get("context", "")}
        for ref in refs[:limit]
    ]
    return {"string": int_to_hex(string_addr), "count": len(callers), "callers": callers}


__all__ = ["xrefs_compact"]
