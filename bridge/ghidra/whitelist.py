"""Whitelist definitions for allowed Ghidra REST endpoints."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Tuple


@dataclass(frozen=True)
class WhitelistEntry:
    """Represents a logical operation and the aliases it may resolve to."""

    method: str
    key: str
    aliases: Tuple[str, ...]

    def allows(self, path: str) -> bool:
        """Return ``True`` when ``path`` is one of the whitelisted aliases."""

        return path in self.aliases


DEFAULT_WHITELIST: Dict[str, Iterable[WhitelistEntry]] = {
    "GET": (
        WhitelistEntry("GET", "READ_DWORD", ("read_dword",)),
        WhitelistEntry(
            "GET",
            "DISASSEMBLE",
            ("disassemble", "disassemble_function", "disasmByAddr"),
        ),
        WhitelistEntry(
            "GET",
            "FUNC_BY_ADDR",
            ("function_by_addr", "get_function_by_address", "functionMeta"),
        ),
        WhitelistEntry("GET", "GET_XREFS_TO", ("get_xrefs_to", "xrefs_to")),
        WhitelistEntry(
            "GET",
            "SEARCH_STRINGS",
            ("search_strings", "strings"),
        ),
    ),
    "POST": (
        WhitelistEntry(
            "POST",
            "RENAME_FUNCTION",
            ("rename_function_by_address", "renameFunctionByAddress"),
        ),
        WhitelistEntry(
            "POST",
            "SET_DECOMPILER_COMMENT",
            ("set_decompiler_comment", "setDecompilerComment"),
        ),
        WhitelistEntry(
            "POST",
            "SET_DISASSEMBLY_COMMENT",
            ("set_disassembly_comment", "setDisassemblyComment"),
        ),
    ),
}
