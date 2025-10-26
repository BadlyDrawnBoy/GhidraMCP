"""MCP tool surface for the deterministic bridge endpoints."""
from __future__ import annotations

from typing import Callable, Dict

from mcp.server.fastmcp import FastMCP

from ..features import jt, mmio, strings
from ..ghidra.client import GhidraClient
from ..utils.config import ENABLE_WRITES
from ..utils.errors import ErrorCode
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
        adapter = adapter_for_arch(arch)
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
        adapter = adapter_for_arch(arch)
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
        adapter = adapter_for_arch(arch)
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
    def mmio_annotate_compact(
        client,
        function_addr: str,
        dry_run: bool = True,
        max_samples: int = 8,
    ) -> Dict[str, object]:
        try:
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
