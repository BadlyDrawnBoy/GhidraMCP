"""Compact string cross reference helpers."""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ..ghidra.client import GhidraClient
from ..utils.hex import int_to_hex, parse_hex
from ..utils.logging import enforce_batch_limit, increment_counter


_REGISTER_ARG_ORDER = {
    # ARM / Thumb
    "r0": 0,
    "r1": 1,
    "r2": 2,
    "r3": 3,
    # AArch64
    "x0": 0,
    "x1": 1,
    "x2": 2,
    "x3": 3,
    "x4": 4,
    "x5": 5,
    "x6": 6,
    "x7": 7,
    "w0": 0,
    "w1": 1,
    "w2": 2,
    "w3": 3,
    "w4": 4,
    "w5": 5,
    "w6": 6,
    "w7": 7,
    # RISC-V
    "a0": 0,
    "a1": 1,
    "a2": 2,
    "a3": 3,
    "a4": 4,
    "a5": 5,
    "a6": 6,
    "a7": 7,
    # x86-64 System V
    "rdi": 0,
    "rsi": 1,
    "rdx": 2,
    "rcx": 3,
    "r8": 4,
    "r9": 5,
    # x86-32 fastcall / MS x64
    "edi": 0,
    "esi": 1,
    "edx": 2,
    "ecx": 3,
}

_CALL_PATTERN = re.compile(r"\b(?:call|bl|blx|jal|jalr)\b", re.IGNORECASE)
_CALL_TARGET_PATTERN = re.compile(
    r"\b(?:call|bl|blx|jal|jalr)\b\s+([A-Za-z0-9_.$@+-]+)", re.IGNORECASE
)


def _normalize_context(text: str, *, max_len: int = 140) -> str:
    normalized = " ".join(text.strip().split())
    return normalized[:max_len]


def _find_instruction_index(lines: Sequence[str], address: int) -> Optional[int]:
    if not lines:
        return None
    target_hex = f"{address:08X}"
    alt_hex = target_hex.lstrip("0") or "0"
    for idx, line in enumerate(lines):
        head, _, _ = line.partition(":")
        token = head.strip().upper()
        if token.startswith("0X"):
            token = token[2:]
        if token in {target_hex, alt_hex}:
            return idx
    return None


def _collect_snippet(lines: Sequence[str], start: int) -> List[str]:
    snippet = [lines[start]]
    for offset in range(1, 5):
        if start + offset >= len(lines):
            break
        candidate = lines[start + offset]
        if _CALL_PATTERN.search(candidate):
            snippet.append(candidate)
            break
        if len(snippet) == 1:
            snippet.append(candidate)
            # keep looking in case of call later but avoid long tails
    return snippet


def _guess_arg_index(snippet: Iterable[str]) -> Optional[int]:
    for line in snippet:
        lower = line.lower()
        for reg, index in _REGISTER_ARG_ORDER.items():
            if re.search(rf"\b{re.escape(reg)}\b", lower):
                return index
    return None


def _guess_hint(snippet: Sequence[str]) -> Optional[str]:
    for line in snippet:
        match = _CALL_TARGET_PATTERN.search(line)
        if match:
            return match.group(1)
    for line in snippet:
        lower = line.lower()
        for keyword in ("printf", "sprintf", "snprintf", "log", "error", "panic", "print"):
            if keyword in lower:
                return keyword
    return None


def _extract_context(
    client: GhidraClient,
    *,
    string_addr: int,
    ref_addr: int,
    fallback: str,
) -> Tuple[str, Optional[int], Optional[str]]:
    disasm = client.disassemble_function(ref_addr)
    lines = [_normalize_context(line) for line in disasm if line.strip()]
    if not lines:
        return (_normalize_context(fallback) if fallback else "", None, None)

    idx = _find_instruction_index(lines, ref_addr)
    if idx is None:
        string_hex = f"{string_addr:08X}"
        for i, line in enumerate(lines):
            if string_hex in line.replace("0x", "0X").upper():
                idx = i
                break
    if idx is None:
        return (_normalize_context(fallback) if fallback else "", None, None)

    snippet_lines = _collect_snippet(lines, idx)
    snippet = " | ".join(snippet_lines)
    snippet = _normalize_context(snippet)
    arg_index = _guess_arg_index(snippet_lines)
    hint = _guess_hint(snippet_lines)
    return (snippet or _normalize_context(fallback), arg_index, hint)


def xrefs_compact(client: GhidraClient, *, string_addr: int, limit: int = 50) -> Dict[str, object]:
    increment_counter("strings.xrefs.calls")
    enforce_batch_limit(limit, counter="strings.xrefs.limit")
    refs = client.get_xrefs_to(string_addr, limit=limit)
    total = len(refs)
    callers: List[Dict[str, object]] = []
    for ref in refs[:limit]:
        addr = ref.get("addr")
        if addr is None:
            continue
        context, arg_index, hint = _extract_context(
            client,
            string_addr=string_addr,
            ref_addr=addr,
            fallback=ref.get("context", ""),
        )
        entry: Dict[str, object] = {"addr": int_to_hex(addr), "context": context}
        if arg_index is not None:
            entry["arg_index"] = arg_index
        if hint:
            entry["hint"] = hint
        callers.append(entry)
        increment_counter("strings.xrefs.callers")
    return {
        "string": int_to_hex(string_addr),
        "count": total,
        "callers": callers,
    }


_ELLIPSIS = "…"


def _normalize_literal(value: str) -> str:
    normalized = " ".join(value.replace("\n", " ").replace("\r", " ").split())
    return normalized


def _truncate_literal(value: str, *, max_len: int = 120) -> str:
    if len(value) <= max_len:
        return value
    if max_len <= 0:
        return ""
    return value[: max_len - 1] + _ELLIPSIS


def strings_compact_view(
    entries: Sequence[Mapping[str, object]]
) -> Dict[str, object]:
    """Normalize raw string metadata into the compact response structure."""

    normalized: List[Tuple[int, Dict[str, object]]] = []
    for raw in entries:
        literal_raw = raw.get("literal")
        if literal_raw is None:
            literal_raw = raw.get("string")
        if literal_raw is None:
            literal_raw = raw.get("s", "")
        literal = _normalize_literal(str(literal_raw))
        literal = _truncate_literal(literal)

        address_raw = raw.get("address")
        if address_raw is None:
            address_raw = raw.get("addr")
        if address_raw is None:
            raise ValueError("Missing address for compact string entry")
        if isinstance(address_raw, str):
            address = parse_hex(address_raw)
        elif isinstance(address_raw, int):
            address = address_raw
        else:
            raise ValueError("Invalid address type for compact string entry")

        refs_raw = None
        if "refs" in raw:
            refs_raw = raw.get("refs")
        elif "xref_count" in raw:
            refs_raw = raw.get("xref_count")
        elif "count" in raw:
            refs_raw = raw.get("count")
        elif "callers" in raw and isinstance(raw["callers"], (list, tuple, set)):
            refs_raw = len(raw["callers"])
        if refs_raw is None:
            refs = 0
        elif isinstance(refs_raw, (list, tuple, set)):
            refs = len(refs_raw)
        else:
            refs = int(refs_raw)
        if refs < 0:
            refs = 0

        normalized.append(
            (
                int(address),
                {
                    "s": literal,
                    "addr": int_to_hex(int(address)),
                    "refs": refs,
                },
            )
        )

    normalized.sort(key=lambda item: item[0])
    items = [payload for _, payload in normalized]
    return {"total": len(items), "items": items}


__all__ = ["strings_compact_view", "xrefs_compact"]
