"""HTTP client wrapper around the Ghidra MCP bridge plugin."""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
import logging
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional
from urllib.parse import urljoin

import httpx

from .models import FunctionMeta, Xref
from .whitelist import DEFAULT_WHITELIST, WhitelistEntry
from ..utils.logging import current_request, increment_counter, scoped_timer

logger = logging.getLogger("ghidra.bridge.client")


ENDPOINT_CANDIDATES: Mapping[str, Iterable[str]] = {
    "DISASSEMBLE": ("disassemble", "disassemble_function", "disasmByAddr"),
    "FUNC_BY_ADDR": ("function_by_addr", "get_function_by_address", "functionMeta"),
    "GET_XREFS_TO": ("get_xrefs_to", "xrefs_to"),
}

POST_ENDPOINT_CANDIDATES: Mapping[str, Iterable[str]] = {
    "RENAME_FUNCTION": (
        "rename_function_by_address",
        "renameFunctionByAddress",
    ),
    "SET_DECOMPILER_COMMENT": (
        "set_decompiler_comment",
        "setDecompilerComment",
    ),
    "SET_DISASSEMBLY_COMMENT": (
        "set_disassembly_comment",
        "setDisassemblyComment",
    ),
}


@dataclass(slots=True)
class EndpointResolver:
    candidates: Mapping[str, Iterable[str]]
    _cache: MutableMapping[str, str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._cache = {}

    def resolve(self, key: str, requester: "EndpointRequester") -> List[str]:
        cached = self._cache.get(key)
        if cached:
            result = requester.request(cached)
            if not _is_error(result):
                return result
        last_error: List[str] = [f"ERROR: no candidates for {key}"]
        for candidate in self.candidates.get(key, (key,)):
            result = requester.request(candidate)
            if not _is_error(result):
                self._cache[key] = candidate
                return result
            last_error = result
        return last_error


class EndpointRequester:
    def __init__(
        self,
        client: "GhidraClient",
        method: str,
        *,
        key: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.client = client
        self.method = method
        self.key = key
        self.params = params or {}
        self.data = data if data is not None else {}

    def request(self, path: str) -> List[str]:
        if self.method == "GET":
            return self.client._request_lines("GET", path, key=self.key, params=self.params)
        if self.method == "POST":
            return self.client._request_lines(
                "POST", path, key=self.key, data=self.data
            )
        raise ValueError(f"Unsupported method {self.method}")


def _is_error(lines: List[str]) -> bool:
    return bool(lines) and lines[0].startswith("ERROR:")


def _has_confirm_true(
    params: Optional[Mapping[str, Any]], data: Optional[Mapping[str, Any]]
) -> bool:
    def _matches(mapping: Optional[Mapping[str, Any]]) -> bool:
        if not mapping:
            return False
        for key, value in mapping.items():
            if key.lower() == "confirm" and str(value).lower() in {"true", "1", "yes"}:
                return True
        return False

    return _matches(params) or _matches(data)


class GhidraClient:
    """Small wrapper that handles whitelist enforcement and alias resolution."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 30.0,
        whitelist: Optional[Mapping[str, Iterable[WhitelistEntry]]] = None,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        self.base_url = base_url if base_url.endswith("/") else f"{base_url}/"
        self.timeout = timeout
        self._session = httpx.Client(timeout=timeout, transport=transport)
        self._whitelist = whitelist or DEFAULT_WHITELIST
        self._get_resolver = EndpointResolver(ENDPOINT_CANDIDATES)
        self._post_resolver = EndpointResolver(POST_ENDPOINT_CANDIDATES)

    # ------------------------------------------------------------------
    # low level
    # ------------------------------------------------------------------

    def _is_allowed(self, method: str, *, key: Optional[str] = None, path: Optional[str] = None) -> bool:
        entries = self._whitelist.get(method.upper(), ())
        if key is not None:
            for entry in entries:
                if entry.key == key:
                    if path is None:
                        return True
                    return entry.allows(path)
            return False
        if path is not None:
            return any(entry.allows(path) for entry in entries)
        raise ValueError("Either key or path must be provided for whitelist checks")

    def _request_lines(
        self,
        method: str,
        path: str,
        *,
        key: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        if not self._is_allowed(method, key=key, path=path):
            logger.error("Attempted to call non-whitelisted endpoint %s %s", method, path)
            return [f"ERROR: endpoint {method} {path} not allowed"]
        if _has_confirm_true(params=params, data=data):
            logger.error(
                "Attempted to call endpoint %s %s with confirm=true, blocking for safety",
                method,
                path,
            )
            return [f"ERROR: endpoint {method} {path} not allowed"]
        url = urljoin(self.base_url, path)
        context = current_request()
        timer_extra: Dict[str, Any]
        if context is not None:
            timer_extra = context.extra(
                event="timer",
                operation=f"ghidra.{method.lower()}",
                path=path,
            )
        else:  # pragma: no cover - request scope always set in integration tests
            timer_extra = {"event": "timer", "operation": f"ghidra.{method.lower()}", "path": path}
        with scoped_timer(logger, f"ghidra.{method.lower()}", extra=timer_extra):
            try:
                response = self._session.request(method, url, params=params, data=data)
            except httpx.HTTPError as exc:  # pragma: no cover - transport errors are environment specific
                return [f"ERROR: Request failed: {exc}"]
        if response.is_error:
            return [f"ERROR: {response.status_code}: {response.text.strip()}"]
        text = response.text
        lines = text.replace("\r\n", "\n").splitlines()
        return lines

    # ------------------------------------------------------------------
    # public helpers
    # ------------------------------------------------------------------

    def read_dword(self, address: int) -> Optional[int]:
        increment_counter("ghidra.read")
        result = self._request_lines(
            "GET",
            "read_dword",
            key="READ_DWORD",
            params={"address": f"0x{address:08x}"},
        )
        if _is_error(result) or not result:
            logger.warning("read_dword failed for 0x%08x: %s", address, result[:1])
            return None
        line = result[0].strip()
        try:
            return int(line, 16)
        except ValueError:
            logger.warning("Unexpected read_dword payload %s", line)
            return None

    def disassemble_function(self, address: int) -> List[str]:
        increment_counter("ghidra.disasm")
        requester = EndpointRequester(
            self,
            "GET",
            key="DISASSEMBLE",
            params={"address": f"0x{address:08x}"},
        )
        lines = self._get_resolver.resolve("DISASSEMBLE", requester)
        return [] if _is_error(lines) else lines

    def get_function_by_address(self, address: int) -> Optional[FunctionMeta]:
        increment_counter("ghidra.verify")
        requester = EndpointRequester(
            self,
            "GET",
            key="FUNC_BY_ADDR",
            params={"address": f"0x{address:08x}"},
        )
        lines = self._get_resolver.resolve("FUNC_BY_ADDR", requester)
        if _is_error(lines):
            return None
        meta: Dict[str, Any] = {}
        for line in lines:
            if ":" in line:
                key, value = line.split(":", 1)
            elif "=" in line:
                key, value = line.split("=", 1)
            else:
                continue
            meta[key.strip()] = value.strip()
        if "entry_point" in meta:
            try:
                meta["entry_point"] = int(meta["entry_point"], 16)
            except ValueError:
                pass
        if "address" in meta:
            try:
                meta["address"] = int(meta["address"], 16)
            except ValueError:
                pass
        return meta if meta else None

    def get_xrefs_to(self, address: int, *, limit: int = 50) -> List[Xref]:
        increment_counter("ghidra.xrefs")
        requester = EndpointRequester(
            self,
            "GET",
            key="GET_XREFS_TO",
            params={"address": f"0x{address:08x}", "limit": int(limit)},
        )
        lines = self._get_resolver.resolve("GET_XREFS_TO", requester)
        if _is_error(lines):
            return []
        out: List[Xref] = []
        for line in lines:
            parts = line.split("|", 1)
            if not parts:
                continue
            addr_str = parts[0].strip()
            context = parts[1].strip() if len(parts) > 1 else ""
            try:
                addr_val = int(addr_str, 16)
            except ValueError:
                continue
            out.append({"addr": addr_val, "context": context})
        return out

    def search_strings(self, query: str) -> List[Dict[str, Any]]:
        increment_counter("ghidra.search_strings")
        lines = self._request_lines(
            "GET",
            "strings",
            key="SEARCH_STRINGS",
            params={"filter": query, "limit": 100000, "offset": 0},
        )
        if _is_error(lines):
            return []
        results: List[Dict[str, Any]] = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            address_part, _, literal_part = stripped.partition(":")
            if not address_part:
                continue
            address = address_part.strip()
            literal_text = literal_part.strip()
            literal = literal_text
            if literal_text:
                try:
                    literal = ast.literal_eval(literal_text)
                except (ValueError, SyntaxError):
                    literal = literal_text.strip('"')
            results.append({"address": address, "literal": literal})
        return results

    def search_imports(self, query: str) -> List[str]:
        """Search for imported symbols matching the provided filter."""

        increment_counter("ghidra.search_imports")
        lines = self._request_lines(
            "GET",
            "imports",
            key="SEARCH_IMPORTS",
            params={"filter": query, "limit": 999999, "offset": 0},
        )
        if _is_error(lines):
            return []
        return [line.strip() for line in lines if line.strip()]

    def search_exports(self, query: str) -> List[str]:
        """Search for exported symbols matching the provided filter."""

        increment_counter("ghidra.search_exports")
        lines = self._request_lines(
            "GET",
            "exports",
            key="SEARCH_EXPORTS",
            params={"filter": query, "limit": 999999, "offset": 0},
        )
        if _is_error(lines):
            return []
        return [line.strip() for line in lines if line.strip()]

    def search_functions(self, query: str) -> List[str]:
        """
        Search for functions matching the query.
        
        Args:
            query: Search query string
            
        Returns:
            List of strings in format "function_name @ 0xaddress"
        """
        increment_counter("ghidra.search_functions")
        lines = self._request_lines(
            "GET",
            "searchFunctions",
            key="SEARCH_FUNCTIONS",
            params={"query": query, "limit": 999999},
        )
        if _is_error(lines):
            return []
        return [line.strip() for line in lines if line.strip()]

    def rename_function(self, address: int, new_name: str) -> bool:
        increment_counter("ghidra.rename")
        requester = EndpointRequester(
            self,
            "POST",
            key="RENAME_FUNCTION",
            data={"function_address": f"0x{address:08x}", "new_name": new_name},
        )
        response = self._post_resolver.resolve("RENAME_FUNCTION", requester)
        return not _is_error(response)

    def set_decompiler_comment(self, address: int, comment: str) -> bool:
        increment_counter("ghidra.decompiler_comment")
        requester = EndpointRequester(
            self,
            "POST",
            key="SET_DECOMPILER_COMMENT",
            data={"address": f"0x{address:08x}", "comment": comment},
        )
        response = self._post_resolver.resolve("SET_DECOMPILER_COMMENT", requester)
        return not _is_error(response)

    def set_disassembly_comment(self, address: int, comment: str) -> bool:
        increment_counter("ghidra.disassembly_comment")
        requester = EndpointRequester(
            self,
            "POST",
            key="SET_DISASSEMBLY_COMMENT",
            data={"address": f"0x{address:08x}", "comment": comment},
        )
        response = self._post_resolver.resolve(
            "SET_DISASSEMBLY_COMMENT", requester
        )
        return not _is_error(response)

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "GhidraClient":  # pragma: no cover - convenience wrapper
        return self

    def __exit__(self, *exc_info: Any) -> None:  # pragma: no cover - convenience wrapper
        self.close()


__all__ = ["GhidraClient", "ENDPOINT_CANDIDATES", "POST_ENDPOINT_CANDIDATES"]
