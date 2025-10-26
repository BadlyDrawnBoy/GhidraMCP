"""Whitelist definitions for allowed Ghidra REST endpoints."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable


@dataclass(frozen=True)
class WhitelistEntry:
    method: str
    path: str


DEFAULT_WHITELIST: Dict[str, Iterable[WhitelistEntry]] = {
    "GET": (
        WhitelistEntry("GET", "read_dword"),
        WhitelistEntry("GET", "decompileByAddress"),
        WhitelistEntry("GET", "decompile_by_addr"),
        WhitelistEntry("GET", "disassemble"),
        WhitelistEntry("GET", "disassemble_function"),
        WhitelistEntry("GET", "disasmByAddr"),
        WhitelistEntry("GET", "function_by_addr"),
        WhitelistEntry("GET", "get_function_by_address"),
        WhitelistEntry("GET", "functionMeta"),
        WhitelistEntry("GET", "functions"),
        WhitelistEntry("GET", "list_functions"),
        WhitelistEntry("GET", "strings"),
        WhitelistEntry("GET", "list_strings"),
        WhitelistEntry("GET", "xrefs_to"),
        WhitelistEntry("GET", "get_xrefs_to"),
    ),
    "POST": (
        WhitelistEntry("POST", "rename_function_by_address"),
        WhitelistEntry("POST", "set_decompiler_comment"),
        WhitelistEntry("POST", "set_disassembly_comment"),
    ),
}
