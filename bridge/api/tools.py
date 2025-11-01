"""MCP tool surface for the deterministic bridge endpoints."""
from __future__ import annotations

import logging
from typing import Callable, Dict

from mcp.server.fastmcp import FastMCP

from ..features import functions, imports as import_features, jt, mmio, strings
from ..ghidra.client import GhidraClient
from ..utils.config import ENABLE_WRITES
from ..utils.errors import ErrorCode
from ..utils.logging import (
    SafetyLimitExceeded,
    enforce_batch_limit,
    increment_counter,
    request_scope,
)
from ..utils.hex import parse_hex
from ._shared import adapter_for_arch, envelope_error, envelope_ok, with_client
from .validators import validate_payload


def register_tools(
    server: FastMCP,
    *,
    client_factory: Callable[[], GhidraClient],
    enable_writes: bool = ENABLE_WRITES,
) -> None:
    tool_client = with_client(client_factory)
    logger = logging.getLogger("bridge.mcp.tools")

    @server.tool()
    @tool_client
    def jt_slot_check(
        client,
        jt_base: str,
        slot_index: int,
        code_min: str,
        code_max: str,
        arch: str = "auto",
    ) -> Dict[str, object]:
        request_payload = {
            "jt_base": jt_base,
            "slot_index": slot_index,
            "code_min": code_min,
            "code_max": code_max,
            "arch": arch,
        }
        valid, errors = validate_payload("jt_slot_check.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))

        adapter = adapter_for_arch(arch)
        with request_scope(
            "jt_slot_check",
            logger=logger,
            extra={"tool": "jt_slot_check"},
        ):
            data = jt.slot_check(
                client,
                jt_base=parse_hex(jt_base),
                slot_index=slot_index,
                code_min=parse_hex(code_min),
                code_max=parse_hex(code_max),
                adapter=adapter,
            )
        valid, errors = validate_payload("jt_slot_check.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def jt_slot_process(
        client,
        jt_base: str,
        slot_index: int,
        code_min: str,
        code_max: str,
        rename_pattern: str,
        comment: str,
        dry_run: bool = True,
        arch: str = "auto",
    ) -> Dict[str, object]:
        request_payload = {
            "jt_base": jt_base,
            "slot_index": slot_index,
            "code_min": code_min,
            "code_max": code_max,
            "rename_pattern": rename_pattern,
            "comment": comment,
            "dry_run": dry_run,
            "arch": arch,
        }
        valid, errors = validate_payload("jt_slot_process.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))

        adapter = adapter_for_arch(arch)
        try:
            with request_scope(
                "jt_slot_process",
                logger=logger,
                extra={"tool": "jt_slot_process"},
                max_writes=2,
            ):
                data = jt.slot_process(
                    client,
                    jt_base=parse_hex(jt_base),
                    slot_index=slot_index,
                    code_min=parse_hex(code_min),
                    code_max=parse_hex(code_max),
                    rename_pattern=rename_pattern,
                    comment=comment,
                    adapter=adapter,
                    dry_run=dry_run,
                    writes_enabled=enable_writes,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.SAFETY_LIMIT, str(exc))
        valid, errors = validate_payload("jt_slot_process.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def jt_scan(
        client,
        jt_base: str,
        start: int,
        count: int,
        code_min: str,
        code_max: str,
        arch: str = "auto",
    ) -> Dict[str, object]:
        request_payload = {
            "jt_base": jt_base,
            "start": start,
            "count": count,
            "code_min": code_min,
            "code_max": code_max,
            "arch": arch,
        }
        valid, errors = validate_payload("jt_scan.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))

        adapter = adapter_for_arch(arch)
        with request_scope(
            "jt_scan",
            logger=logger,
            extra={"tool": "jt_scan"},
        ):
            data = jt.scan(
                client,
                jt_base=parse_hex(jt_base),
                start=start,
                count=count,
                code_min=parse_hex(code_min),
                code_max=parse_hex(code_max),
                adapter=adapter,
            )
        valid, errors = validate_payload("jt_scan.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def string_xrefs_compact(
        client,
        string_addr: str,
        limit: int = 50,
    ) -> Dict[str, object]:
        request_payload = {
            "string_addr": string_addr,
            "limit": limit,
        }
        valid, errors = validate_payload("string_xrefs.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))

        with request_scope(
            "string_xrefs",
            logger=logger,
            extra={"tool": "string_xrefs_compact"},
        ):
            data = strings.xrefs_compact(
                client,
                string_addr=parse_hex(string_addr),
                limit=limit,
            )
        valid, errors = validate_payload("string_xrefs.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def search_strings(
        client,
        query: str,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, object]:
        request_payload = {"query": query, "limit": limit, "offset": offset}
        valid, errors = validate_payload("search_strings.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))

        try:
            with request_scope(
                "search_strings",
                logger=logger,
                extra={"tool": "search_strings"},
            ):
                data = strings.search_strings(
                    client,
                    query=query,
                    limit=int(limit),
                    offset=int(offset),
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.SAFETY_LIMIT, str(exc))

        valid, errors = validate_payload("search_strings.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def strings_compact(
        client,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, object]:
        request_payload = {"limit": limit, "offset": offset}
        valid, errors = validate_payload("strings_compact.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))

        try:
            enforce_batch_limit(limit, counter="strings.compact.limit")
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.SAFETY_LIMIT, str(exc))

        with request_scope(
            "strings_compact",
            logger=logger,
            extra={"tool": "strings_compact"},
        ):
            increment_counter("strings.compact.calls")
            raw_entries: list[dict[str, object]] = []
            fetcher = getattr(client, "list_strings_compact", None)
            if callable(fetcher):
                result = fetcher(limit=limit, offset=offset)
                raw_entries = [] if result is None else list(result)
            else:
                fallback = getattr(client, "list_strings", None)
                if callable(fallback):
                    try:
                        result = fallback(limit=limit, offset=offset)
                    except TypeError:
                        result = fallback(limit=limit)
                    raw_entries = [] if result is None else list(result)
            try:
                data = strings.strings_compact_view(raw_entries)
            except (TypeError, ValueError) as exc:
                return envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc))

        valid, errors = validate_payload("strings_compact.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def search_imports(
        client,
        query: str,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, object]:
        """Search imported symbols matching a query with pagination support."""

        request_payload = {"query": query, "limit": limit, "offset": offset}
        valid, errors = validate_payload(
            "search_imports.request.v1.json", request_payload
        )
        if not valid:
            return envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))

        try:
            with request_scope(
                "search_imports",
                logger=logger,
                extra={"tool": "search_imports"},
            ):
                data = import_features.search_imports(
                    client,
                    query=query,
                    limit=limit,
                    offset=offset,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.SAFETY_LIMIT, str(exc))

        valid, errors = validate_payload("search_imports.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def search_functions(
        client,
        query: str,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, object]:
        """
        Search for functions matching a query with pagination support.
        
        Args:
            query: Search query string (function name pattern)
            limit: Maximum number of results to return (default: 100)
            offset: Number of results to skip for pagination (default: 0)
            
        Returns:
            Dictionary with query, total_results, page, limit, and items array.
            Each item contains name and address fields.
        """
        request_payload = {"query": query, "limit": limit, "offset": offset}
        valid, errors = validate_payload("search_functions.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))

        try:
            with request_scope(
                "search_functions",
                logger=logger,
                extra={"tool": "search_functions"},
            ):
                data = functions.search_functions(
                    client,
                    query=query,
                    limit=limit,
                    offset=offset,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.SAFETY_LIMIT, str(exc))

        valid, errors = validate_payload("search_functions.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def mmio_annotate_compact(
        client,
        function_addr: str,
        dry_run: bool = True,
        max_samples: int = 8,
    ) -> Dict[str, object]:
        request_payload = {
            "function_addr": function_addr,
            "dry_run": dry_run,
            "max_samples": max_samples,
        }
        valid, errors = validate_payload("mmio_annotate.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))

        try:
            with request_scope(
                "mmio_annotate",
                logger=logger,
                extra={"tool": "mmio_annotate_compact"},
            ):
                data = mmio.annotate(
                    client,
                    function_addr=parse_hex(function_addr),
                    dry_run=dry_run,
                    max_samples=max_samples,
                    writes_enabled=enable_writes,
                )
        except mmio.WritesDisabledError:
            return envelope_error(
                ErrorCode.WRITE_DISABLED_DRY_RUN,
                "Writes are disabled while dry_run is false.",
            )
        valid, errors = validate_payload("mmio_annotate.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
        return envelope_ok(data)


__all__ = ["register_tools"]
