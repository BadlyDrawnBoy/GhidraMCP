#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "mcp>=1.14.0,<2",
#     "requests>=2,<3",
#     "httpx>=0.27,<1",
#     "uvicorn>=0.31",
#     "starlette>=0.36",
# ]
# ///

# NOTE: Placeholders like `address_from` or `offset` in tool arguments are not
#       interpreted by this bridge script itself. They are intended for MCP clients
#       or runners (like Aider) that perform pre-processing and substitute
#       the results of previous tool calls.

import logging
import os
import re
from typing import Optional, Dict, Any, List
from urllib.parse import urljoin

import requests
from mcp.server.fastmcp import FastMCP

from bridge.cli import build_parser as build_cli_parser, run as run_cli
from bridge.shim import build_openwebui_shim

# ──────────────────────────────────────────────────────────────────────────────
# Logging & Defaults
# ──────────────────────────────────────────────────────────────────────────────

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger("ghidra-mcp")
logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
logger.setLevel(logging.INFO)


# ──────────────────────────────────────────────────────────────────────────────
# Safety / Context budget controls
# ──────────────────────────────────────────────────────────────────────────────
MAX_LINES_SOFT = int(os.getenv("MCP_MAX_LINES_SOFT", "200"))       # friendly cap
MAX_ITEMS_SOFT = int(os.getenv("MCP_MAX_ITEMS_SOFT", "256"))      # per-call default cap
MAX_ITEMS_HARD = int(os.getenv("MCP_MAX_ITEMS_HARD", "2000"))     # absolute refusal threshold

CONFIRMATION_TEMPLATE = (
    "--- CONFIRMATION REQUEST ---\n"
    "REASON: {reason}\n"
    "PLAN: {plan}\n"
    "SCOPE: {scope}\n"
    "IMPACT: {impact}\n"
    "AWAITING_APPROVAL: YES\n"
    "--- END CONFIRMATION REQUEST ---"
)

def confirmation(reason: str, plan: str, scope: str, impact: str) -> List[str]:
    return [CONFIRMATION_TEMPLATE.format(reason=reason, plan=plan, scope=scope, impact=impact)]


def _clamp_lines(lines: List[str], max_lines: int = MAX_LINES_SOFT) -> List[str]:
    return lines if len(lines) <= max_lines else lines[:max_lines] + [f"...CLIPPED ({len(lines)-max_lines} more lines)"]


# ──────────────────────────────────────────────────────────────────────────────
# Endpoint resolver & paged helper
# ──────────────────────────────────────────────────────────────────────────────

# Aliases for endpoint compatibility (different plugin builds expose different paths)
ENDPOINT_CANDIDATES: Dict[str, List[str]] = {
    # Strongly typed address-based endpoints
    "DECOMPILE_BY_ADDR": ["decompile_by_addr", "decompileByAddress"],
    "DISASSEMBLE":       ["disassemble", "disassemble_function", "disasmByAddr"],
    "FUNC_BY_ADDR":      ["function_by_addr", "get_function_by_address", "functionMeta"],
    # Common listings
    "LIST_FUNCTIONS":    ["functions", "list_functions"],
    "STRINGS":           ["strings", "list_strings"],
    "DATA_WINDOW":       ["data_window", "list_data_window", "dataWindow"],
    # Paged data groups
    "DATA":              ["data", "list_data_items"],
    "METHODS":           ["methods"],
    "CLASSES":           ["classes"],
    "SEGMENTS":          ["segments"],
    "IMPORTS":           ["imports"],
    "EXPORTS":           ["exports"],
    "NAMESPACES":        ["namespaces"],
    "XREFS_TO":          ["xrefs_to"],
    "XREFS_FROM":        ["xrefs_from"],
    "FUNCTION_XREFS":    ["function_xrefs", "get_function_xrefs"],
    "SEARCH_FUNCTIONS":  ["searchFunctions", "search_functions_by_name"],
}

_endpoint_cache: Dict[str, str] = {}


def _is_error(lines: List[str]) -> bool:
    return bool(lines) and isinstance(lines[0], str) and lines[0].startswith("ERROR:")


def resolve_get(ep_key: str, params: Dict[str, Any]) -> List[str]:
    """Resolve a logical endpoint key to a working HTTP endpoint, with caching."""
    chosen = _endpoint_cache.get(ep_key)
    if chosen:
        res = safe_get(chosen, params)
        if not _is_error(res):
            return res
    last_error = [f"ERROR: no candidates for {ep_key}"]
    cands = ENDPOINT_CANDIDATES.get(ep_key)
    if cands is None:
        # Fallback: treat ep_key as literal endpoint path
        return safe_get(ep_key, params)
    for cand in cands:
        res = safe_get(cand, params)
        if not _is_error(res):
            _endpoint_cache[ep_key] = cand
            logger.debug(f"Resolved endpoint '{ep_key}' to '{cand}'")
            return res
        last_error = res
    return last_error


def _paged(endpoint_key: str, params: Dict[str, Any], step: int = 128, max_items: int = MAX_ITEMS_SOFT) -> List[str]:
    """Generic pagination helper with endpoint-key aware resolution."""
    out: List[str] = []
    offset = int(params.get("offset", 0))
    limit_req = int(params.get("limit", max_items))
    remaining = min(limit_req, max_items)
    while remaining > 0:
        take = min(step, remaining)
        if endpoint_key in ENDPOINT_CANDIDATES:
            page = resolve_get(endpoint_key, {**params, "offset": offset, "limit": take})
        else:
            # Treat as literal path if the key is not in candidates
            page = safe_get(endpoint_key, {**params, "offset": offset, "limit": take})
        out.extend(page)
        if _is_error(page) or len(page) < take or (page and "CLIPPED" in page[-1]):
            break
        offset += take
        remaining -= take
        if len(out) >= max_items:
            break
    return out


# ──────────────────────────────────────────────────────────────────────────────
# MCP-Server (läuft als SSE auf Backend-Port, z. B. 8099)
# ──────────────────────────────────────────────────────────────────────────────

mcp = FastMCP("ghidra-mcp")
ghidra_server_url: str = DEFAULT_GHIDRA_SERVER  # wird in main() gesetzt


def start_mcp_sse(host: str, port: int):
    """Startet den MCP-Server im SSE-Modus (blockiert Thread)."""
    mcp.settings.log_level = "INFO"
    mcp.settings.host = host
    mcp.settings.port = int(port)
    logger.info(f"[MCP] Starting SSE on http://{host}:{port}/sse")
    mcp.run(transport="sse")


# ──────────────────────────────────────────────────────────────────────────────
# HTTP-Client Utils zur Ghidra-Bridge
# ──────────────────────────────────────────────────────────────────────────────

def safe_get(endpoint: str, params: Optional[Dict[str, Any]] = None) -> List[str]:
    if params is None:
        params = {}
    url = urljoin(ghidra_server_url, endpoint)
    logger.debug(f"GET {url} {params}")
    try:
        r = requests.get(url, params=params, timeout=30)
        r.encoding = "utf-8"
        if r.ok:
            resp = r.text.splitlines()
            return _clamp_lines(resp)
        else:
            return [f"ERROR: {r.status_code}: {r.text.strip()}"]
    except Exception as e:
        return [f"ERROR: Request failed: {e}"]


def safe_post(endpoint: str, data: Dict[str, Any] | str) -> str:
    url = urljoin(ghidra_server_url, endpoint)
    logger.debug(f"POST {url} {('dict' if isinstance(data, dict) else 'str')} payload")
    try:
        if isinstance(data, dict):
            r = requests.post(url, data=data, timeout=30)
        else:
            r = requests.post(url, data=data.encode("utf-8"), timeout=30)
        r.encoding = "utf-8"
        if r.ok:
            return r.text.strip()
        else:
            return f"ERROR: {r.status_code}: {r.text.strip()}"
    except Exception as e:
        return f"ERROR: Request failed: {e}"


# ──────────────────────────────────────────────────────────────────────────────
# MCP-Tools
# ──────────────────────────────────────────────────────────────────────────────

@mcp.tool()
def read_dword(address: str) -> List[str]:
    """Read a 32-bit little‑endian value at virtual address (hex 0x...). Returns ["0x????????"]."""
    try:
        val = safe_get("read_dword", {"address": address})
        return val if isinstance(val, list) else [str(val)]
    except Exception as e:
        return [f"ERROR: read_dword failed for {address}: {e}"]


@mcp.tool()
def read_bytes(address: str, length: int = 16) -> List[str]:
    """Read raw bytes at address; returns one or more hex lines."""
    try:
        return safe_get("read_bytes", {"address": address, "length": int(length)})
    except Exception as e:
        return [f"ERROR: read_bytes failed for {address}: {e}"]


@mcp.tool()
def read_cstring(address: str, max_len: int = 256) -> List[str]:
    """Read a zero‑terminated string starting at address."""
    try:
        return safe_get("read_cstring", {"address": address, "max_len": int(max_len)})
    except Exception as e:
        return [f"ERROR: read_cstring failed for {address}: {e}"]


@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    out = resolve_get("DECOMPILE_BY_ADDR", {"address": address})
    if not _is_error(out):
        return "\n".join(out)
    # Heuristic retry: force disassembly then decompile again
    _ = resolve_get("DISASSEMBLE", {"address": address})
    out = resolve_get("DECOMPILE_BY_ADDR", {"address": address})
    return "\n".join(out) if out and not _is_error(out) else "ERROR: decompile_by_addr failed"


@mcp.tool()
def disassemble_function(address: str) -> str:
    return "\n".join(resolve_get("DISASSEMBLE", {"address": address}))


@mcp.tool()
def get_function_by_address(address: str) -> List[str]:
    return resolve_get("FUNC_BY_ADDR", {"address": address})


@mcp.tool()
def list_functions(offset: int = 0, limit: int = 100, confirm: bool = False) -> List[str]:
    """Paginated function list with confirmation gate to prevent huge context dumps."""
    if limit > MAX_ITEMS_HARD and not confirm:
        return confirmation(
            reason=f"list_functions request too large (limit={limit} > HARD {MAX_ITEMS_HARD})",
            plan="Retry with a smaller limit (≤256) or set confirm=true.",
            scope=f"offset={offset}, limit={limit}",
            impact="Large function listings tend to explode response size and model context."
        )
    eff_limit = min(limit, MAX_ITEMS_SOFT) if not confirm else min(limit, MAX_ITEMS_HARD)
    return resolve_get("LIST_FUNCTIONS", {"offset": int(offset), "limit": int(eff_limit)})


@mcp.tool()
def list_data_window(start: str, end: str) -> List[str]:
    """Small address window [start,end) for literal pool checks (≤0x40 bytes recommended)."""
    try:
        if int(start, 16) >= int(end, 16):
            return ["ERROR: start must be < end"]
    except Exception:
        pass
    return resolve_get("DATA_WINDOW", {"start": start, "end": end})


@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: Optional[str] = None, confirm: bool = False) -> List[str]:
    if limit > MAX_ITEMS_HARD and not confirm:
        return confirmation(
            reason=f"list_strings too large (limit={limit} > HARD {MAX_ITEMS_HARD})",
            plan="Retry with a smaller limit (≤256) or set confirm=true.",
            scope=f"offset={offset}, limit={limit}, filter={filter}",
            impact="Large string dumps blow context; chunk instead."
        )
    eff_limit = min(limit, MAX_ITEMS_SOFT) if not confirm else min(limit, MAX_ITEMS_HARD)
    params: Dict[str, Any] = {"offset": offset, "limit": eff_limit}
    if filter:
        params["filter"] = filter
    return _paged("STRINGS", params)


@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100, confirm: bool = False) -> List[str]:
    if limit > MAX_ITEMS_HARD and not confirm:
        return confirmation(
            reason=f"list_methods too large (limit={limit} > {MAX_ITEMS_HARD})",
            plan="Use smaller limit (≤256) or confirm=true.",
            scope=f"offset={offset}, limit={limit}",
            impact="Large listings blow context."
        )
    eff = min(limit, MAX_ITEMS_SOFT) if not confirm else min(limit, MAX_ITEMS_HARD)
    return _paged("METHODS", {"offset": int(offset), "limit": eff}, step=128, max_items=eff)


@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100, confirm: bool = False) -> List[str]:
    if limit > MAX_ITEMS_HARD and not confirm:
        return confirmation(
            reason=f"list_classes too large (limit={limit} > {MAX_ITEMS_HARD})",
            plan="Use smaller limit (≤256) or confirm=true.",
            scope=f"offset={offset}, limit={limit}",
            impact="Large listings blow context."
        )
    eff = min(limit, MAX_ITEMS_SOFT) if not confirm else min(limit, MAX_ITEMS_HARD)
    return _paged("CLASSES", {"offset": int(offset), "limit": eff}, step=128, max_items=eff)


@mcp.tool()
def decompile_function(name: str) -> str:
    """Decompile by *name* and return C-like pseudocode (if plugin provides it)."""
    return safe_post("decompile", name)


@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})


@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    return safe_post("renameData", {"address": address, "newName": new_name})


@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100, confirm: bool = False) -> List[str]:
    if limit > MAX_ITEMS_HARD and not confirm:
        return confirmation(
            reason=f"list_segments too large (limit={limit} > {MAX_ITEMS_HARD})",
            plan="Use smaller limit (≤256) or confirm=true.",
            scope=f"offset={offset}, limit={limit}",
            impact="Large listings blow context."
        )
    eff = min(limit, MAX_ITEMS_SOFT) if not confirm else min(limit, MAX_ITEMS_HARD)
    return _paged("SEGMENTS", {"offset": int(offset), "limit": eff}, step=128, max_items=eff)


@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100, confirm: bool = False) -> List[str]:
    if limit > MAX_ITEMS_HARD and not confirm:
        return confirmation(
            reason=f"list_imports too large (limit={limit} > {MAX_ITEMS_HARD})",
            plan="Use smaller limit (≤256) or confirm=true.",
            scope=f"offset={offset}, limit={limit}",
            impact="Large listings blow context."
        )
    eff = min(limit, MAX_ITEMS_SOFT) if not confirm else min(limit, MAX_ITEMS_HARD)
    return _paged("IMPORTS", {"offset": int(offset), "limit": eff}, step=128, max_items=eff)


@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100, confirm: bool = False) -> List[str]:
    if limit > MAX_ITEMS_HARD and not confirm:
        return confirmation(
            reason=f"list_exports too large (limit={limit} > {MAX_ITEMS_HARD})",
            plan="Use smaller limit (≤256) or confirm=true.",
            scope=f"offset={offset}, limit={limit}",
            impact="Large listings blow context."
        )
    eff = min(limit, MAX_ITEMS_SOFT) if not confirm else min(limit, MAX_ITEMS_HARD)
    return _paged("EXPORTS", {"offset": int(offset), "limit": eff}, step=128, max_items=eff)


@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100, confirm: bool = False) -> List[str]:
    if limit > MAX_ITEMS_HARD and not confirm:
        return confirmation(
            reason=f"list_namespaces too large (limit={limit} > {MAX_ITEMS_HARD})",
            plan="Use smaller limit (≤256) or confirm=true.",
            scope=f"offset={offset}, limit={limit}",
            impact="Large listings blow context."
        )
    eff = min(limit, MAX_ITEMS_SOFT) if not confirm else min(limit, MAX_ITEMS_HARD)
    return _paged("NAMESPACES", {"offset": int(offset), "limit": eff}, step=128, max_items=eff)


@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100, confirm: bool = False) -> List[str]:
    """List data labels/values with pagination. Guarded to avoid huge dumps."""
    if limit > MAX_ITEMS_HARD and not confirm:
        return confirmation(
            reason=f"list_data_items request too large (limit={limit} > HARD {MAX_ITEMS_HARD})",
            plan="Retry with a smaller limit or set confirm=true for a one-time large page.",
            scope=f"offset={offset}, limit={limit}",
            impact="Large listing may blow context; chunking is safer."
        )
    eff_limit = min(limit, MAX_ITEMS_SOFT) if not confirm else min(limit, MAX_ITEMS_HARD)
    return _paged("DATA", {"offset": int(offset), "limit": int(eff_limit)}, step=128, max_items=eff_limit)


@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100, confirm: bool = False) -> List[str]:
    """Search functions by substring (server-side if available)."""
    if not query:
        return ["ERROR: query string is required"]
    if limit > MAX_ITEMS_HARD and not confirm:
        return confirmation(
            reason=f"search_functions_by_name too large (limit={limit} > HARD {MAX_ITEMS_HARD})",
            plan="Use a smaller limit (≤256) or set confirm=true.",
            scope=f"query={query}, offset={offset}, limit={limit}",
            impact="Broad function searches can blow context."
        )
    eff_limit = min(limit, MAX_ITEMS_SOFT) if not confirm else min(limit, MAX_ITEMS_HARD)
    return _paged("SEARCH_FUNCTIONS", {"query": query, "offset": offset, "limit": eff_limit}, step=128, max_items=eff_limit)


@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })


@mcp.tool()
def get_current_address() -> str:
    return "\n".join(safe_get("get_current_address"))


@mcp.tool()
def get_current_function() -> str:
    return "\n".join(safe_get("get_current_function"))


@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})


@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})


@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    return safe_post("rename_function_by_address", {
        "function_address": function_address,
        "new_name": new_name
    })


@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    return safe_post("set_function_prototype", {
        "function_address": function_address,
        "prototype": prototype
    })


@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    return safe_post("set_local_variable_type", {
        "function_address": function_address,
        "variable_name": variable_name,
        "new_type": new_type
    })


@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100, confirm: bool = False) -> List[str]:
    if limit > MAX_ITEMS_HARD and not confirm:
        return confirmation(
            reason=f"get_xrefs_to too large (limit={limit} > HARD {MAX_ITEMS_HARD})",
            plan="Use a smaller limit (≤256) or set confirm=true; prefer address-scoped work.",
            scope=f"address={address}, offset={offset}, limit={limit}",
            impact="Mass xref dumps blow context."
        )
    eff_limit = min(limit, MAX_ITEMS_SOFT) if not confirm else min(limit, MAX_ITEMS_HARD)
    return _paged("XREFS_TO", {"address": address, "offset": offset, "limit": eff_limit}, step=128, max_items=eff_limit)


@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100, confirm: bool = False) -> List[str]:
    if limit > MAX_ITEMS_HARD and not confirm:
        return confirmation(
            reason=f"get_xrefs_from too large (limit={limit} > HARD {MAX_ITEMS_HARD})",
            plan="Use a smaller limit (≤256) or set confirm=true.",
            scope=f"address={address}, offset={offset}, limit={limit}",
            impact="Mass xref dumps blow context."
        )
    eff_limit = min(limit, MAX_ITEMS_SOFT) if not confirm else min(limit, MAX_ITEMS_HARD)
    return _paged("XREFS_FROM", {"address": address, "offset": offset, "limit": eff_limit}, step=128, max_items=eff_limit)


@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100, confirm: bool = False) -> List[str]:
    if limit > MAX_ITEMS_HARD and not confirm:
        return confirmation(
            reason=f"get_function_xrefs too large (limit={limit} > HARD {MAX_ITEMS_HARD})",
            plan="Use a smaller limit (≤256) or set confirm=true.",
            scope=f"name={name}, offset={offset}, limit={limit}",
            impact="Mass xref dumps blow context."
        )
    eff_limit = min(limit, MAX_ITEMS_SOFT) if not confirm else min(limit, MAX_ITEMS_HARD)
    return _paged("FUNCTION_XREFS", {"name": name, "offset": offset, "limit": eff_limit}, step=128, max_items=eff_limit)


@mcp.tool()
def search_strings(query: str, case: bool = False, regex: bool = False,
                   start: str | None = None, end: str | None = None,
                   section: str | None = None, max_hits: int = 256,
                   confirm: bool = False) -> List[str]:
    if max_hits > MAX_ITEMS_HARD and not confirm:
        return confirmation(
            reason=f"search_strings max_hits too large ({max_hits} > HARD {MAX_ITEMS_HARD})",
            plan="Use smaller max_hits (≤256) or set confirm=true.",
            scope=f"query={query!r}, window={start}..{end}, section={section}",
            impact="Large searches can blow context."
        )
    flags = 0 if case else re.IGNORECASE
    pat = re.compile(query if regex else re.escape(query), flags)
    step = min(128, MAX_LINES_SOFT)
    offset, hits = 0, []

    def in_window(addr_hex: str) -> bool:
        try:
            if not addr_hex.lower().startswith("0x"):
                return True
            addr = int(addr_hex, 16)
            if start and addr < int(start, 16):
                return False
            if end and addr >= int(end, 16):
                return False
            return True
        except Exception:
            return True

    while len(hits) < max_hits:
        page = resolve_get("STRINGS", {"offset": offset, "limit": step})
        if not page or _is_error(page):
            break
        clipped = page and isinstance(page[-1], str) and page[-1].startswith("...CLIPPED")
        for line in page:
            if section and section not in line:
                continue
            addr_hex = line.split("\t")[0].strip() if "\t" in line else line[:18].strip()
            if not in_window(addr_hex):
                continue
            if pat.search(line):
                hits.append(line)
                if len(hits) >= max_hits:
                    break
        if len(page) < step or clipped:
            break
        offset += step
    return hits or ["No matches found (within filters)"]


@mcp.tool()
def find_text_window(q: str, start: str, end: str, case: bool = False, regex: bool = False, max_hits: int = 128) -> List[str]:
    flags = 0 if case else re.IGNORECASE
    pat = re.compile(q if regex else re.escape(q), flags)
    out, page = [], resolve_get("DATA_WINDOW", {"start": start, "end": end})
    if _is_error(page):
        return page
    for line in page:
        if pat.search(line):
            out.append(line)
            if len(out) >= max_hits:
                break
    return out or ["No matches in window"]


# ──────────────────────────────────────────────────────────────────────────────
# Main / CLI
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = build_cli_parser(DEFAULT_GHIDRA_SERVER)
    args = parser.parse_args()

    def _set_ghidra_url(url: str) -> None:
        global ghidra_server_url
        ghidra_server_url = url

    run_cli(
        args,
        logger=logger,
        default_ghidra_server=DEFAULT_GHIDRA_SERVER,
        set_ghidra_url=_set_ghidra_url,
        start_sse=start_mcp_sse,
        run_stdio=mcp.run,
        shim_factory=build_openwebui_shim,
    )


if __name__ == "__main__":
    main()

