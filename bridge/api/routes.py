"""Starlette routes exposing deterministic HTTP endpoints."""
from __future__ import annotations

import json
import logging
from functools import wraps
from typing import Callable, Dict, Tuple

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ..features import jt, mmio, strings
from ..ghidra.client import GhidraClient
from ..utils.config import ENABLE_WRITES, MAX_WRITES_PER_REQUEST
from ..utils.errors import ErrorCode
from ..utils.hex import parse_hex
from ..utils.logging import SafetyLimitExceeded, request_scope
from ._shared import adapter_for_arch, envelope_error, envelope_ok
from .validators import validate_payload


async def _validated_json_body(
    request: Request, schema: str
) -> Tuple[Dict[str, object] | None, JSONResponse | None]:
    try:
        data = await request.json()
    except json.JSONDecodeError as exc:
        return (
            None,
            JSONResponse(
                envelope_error(ErrorCode.INVALID_ARGUMENT, f"Invalid JSON payload: {exc.msg}"),
                status_code=400,
            ),
        )
    if not isinstance(data, dict):
        return (
            None,
            JSONResponse(
                envelope_error(ErrorCode.INVALID_ARGUMENT, "Payload must be a JSON object."),
                status_code=400,
            ),
        )
    valid, errors = validate_payload(schema, data)
    if not valid:
        return (
            None,
            JSONResponse(
                envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors)),
                status_code=400,
            ),
        )
    return data, None


def _with_client(factory: Callable[[], GhidraClient], *, enable_writes: bool):
    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request):
            request.state.enable_writes = enable_writes
            client = factory()
            try:
                return await func(request, client)
            finally:
                client.close()

        return wrapper

    return decorator


def make_routes(
    client_factory: Callable[[], GhidraClient], *, enable_writes: bool = ENABLE_WRITES
):
    logger = logging.getLogger("bridge.api")
    with_client = _with_client(client_factory, enable_writes=enable_writes)

    async def health_route(request: Request):
        request.state.enable_writes = enable_writes
        client = client_factory()
        try:
            with request_scope(
                "health",
                logger=logger,
                extra={"path": "/api/health.json"},
            ):
                upstream = {
                    "base_url": client.base_url,
                    "reachable": False,
                }
                try:
                    response = client._session.get(client.base_url, timeout=2.0)
                except httpx.HTTPError as exc:
                    upstream["error"] = str(exc)
                else:
                    upstream["reachable"] = response.is_success
                    upstream["status_code"] = response.status_code
                payload = {
                    "service": "ghidra-mcp-bridge",
                    "writes_enabled": enable_writes,
                    "ghidra": upstream,
                }
                return JSONResponse(envelope_ok(payload))
        finally:
            client.close()

    @with_client
    async def jt_slot_check_route(request: Request, client: GhidraClient):
        with request_scope(
            "jt_slot_check",
            logger=logger,
            extra={"path": "/api/jt_slot_check.json"},
        ):
            data, error = await _validated_json_body(
                request, "jt_slot_check.request.v1.json"
            )
            if error is not None:
                return error
            assert data is not None
            try:
                adapter = adapter_for_arch(str(data.get("arch", "auto")))
                payload = jt.slot_check(
                    client,
                    jt_base=parse_hex(str(data["jt_base"])),
                    slot_index=int(data["slot_index"]),
                    code_min=parse_hex(str(data["code_min"])),
                    code_max=parse_hex(str(data["code_max"])),
                    adapter=adapter,
                )
            except (KeyError, ValueError) as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc)), status_code=400
                )
            except SafetyLimitExceeded as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.SAFETY_LIMIT, str(exc)), status_code=400
                )
            valid, errors = validate_payload("jt_slot_check.v1.json", payload)
            response = (
                envelope_ok(payload)
                if valid
                else envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
            )
            return JSONResponse(response)

    @with_client
    async def jt_slot_process_route(request: Request, client: GhidraClient):
        with request_scope(
            "jt_slot_process",
            logger=logger,
            extra={"path": "/api/jt_slot_process.json"},
            max_writes=MAX_WRITES_PER_REQUEST,
        ):
            data, error = await _validated_json_body(
                request, "jt_slot_process.request.v1.json"
            )
            if error is not None:
                return error
            assert data is not None
            try:
                adapter = adapter_for_arch(str(data.get("arch", "auto")))
                payload = jt.slot_process(
                    client,
                    jt_base=parse_hex(str(data["jt_base"])),
                    slot_index=int(data["slot_index"]),
                    code_min=parse_hex(str(data["code_min"])),
                    code_max=parse_hex(str(data["code_max"])),
                    rename_pattern=str(data.get("rename_pattern", "{target}")),
                    comment=str(data.get("comment", "")),
                    adapter=adapter,
                    dry_run=bool(data.get("dry_run", True)),
                    writes_enabled=enable_writes,
                )
            except (KeyError, ValueError) as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc)), status_code=400
                )
            except SafetyLimitExceeded as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.SAFETY_LIMIT, str(exc)), status_code=400
                )
            valid, errors = validate_payload("jt_slot_process.v1.json", payload)
            response = (
                envelope_ok(payload)
                if valid
                else envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
            )
            return JSONResponse(response)

    @with_client
    async def jt_scan_route(request: Request, client: GhidraClient):
        with request_scope(
            "jt_scan",
            logger=logger,
            extra={"path": "/api/jt_scan.json"},
        ):
            data, error = await _validated_json_body(request, "jt_scan.request.v1.json")
            if error is not None:
                return error
            assert data is not None
            try:
                adapter = adapter_for_arch(str(data.get("arch", "auto")))
                payload = jt.scan(
                    client,
                    jt_base=parse_hex(str(data["jt_base"])),
                    start=int(data["start"]),
                    count=int(data["count"]),
                    code_min=parse_hex(str(data["code_min"])),
                    code_max=parse_hex(str(data["code_max"])),
                    adapter=adapter,
                )
            except (KeyError, ValueError) as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc)), status_code=400
                )
            except SafetyLimitExceeded as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.SAFETY_LIMIT, str(exc)), status_code=400
                )
            valid, errors = validate_payload("jt_scan.v1.json", payload)
            response = (
                envelope_ok(payload)
                if valid
                else envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
            )
            return JSONResponse(response)

    @with_client
    async def string_xrefs_route(request: Request, client: GhidraClient):
        with request_scope(
            "string_xrefs",
            logger=logger,
            extra={"path": "/api/string_xrefs.json"},
        ):
            data, error = await _validated_json_body(
                request, "string_xrefs.request.v1.json"
            )
            if error is not None:
                return error
            assert data is not None
            try:
                payload = strings.xrefs_compact(
                    client,
                    string_addr=parse_hex(str(data["string_addr"])),
                    limit=int(data.get("limit", 50)),
                )
            except (KeyError, ValueError) as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc)), status_code=400
                )
            except SafetyLimitExceeded as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.SAFETY_LIMIT, str(exc)), status_code=400
                )
            valid, errors = validate_payload("string_xrefs.v1.json", payload)
            response = (
                envelope_ok(payload)
                if valid
                else envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
            )
            return JSONResponse(response)

    @with_client
    async def mmio_annotate_route(request: Request, client: GhidraClient):
        with request_scope(
            "mmio_annotate",
            logger=logger,
            extra={"path": "/api/mmio_annotate.json"},
        ):
            data, error = await _validated_json_body(
                request, "mmio_annotate.request.v1.json"
            )
            if error is not None:
                return error
            assert data is not None
            try:
                payload = mmio.annotate(
                    client,
                    function_addr=parse_hex(str(data["function_addr"])),
                    dry_run=bool(data.get("dry_run", True)),
                    max_samples=int(data.get("max_samples", 8)),
                    writes_enabled=enable_writes,
                )
            except mmio.WritesDisabledError:
                return JSONResponse(
                    envelope_error(
                        ErrorCode.WRITE_DISABLED_DRY_RUN,
                        "Writes are disabled while dry_run is false.",
                    ),
                    status_code=400,
                )
            except (KeyError, ValueError) as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc)), status_code=400
                )
            except SafetyLimitExceeded as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.SAFETY_LIMIT, str(exc)), status_code=400
                )
            valid, errors = validate_payload("mmio_annotate.v1.json", payload)
            response = (
                envelope_ok(payload)
                if valid
                else envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
            )
            return JSONResponse(response)

    return [
        Route("/api/health.json", health_route, methods=["GET"]),
        Route("/api/jt_slot_check.json", jt_slot_check_route, methods=["POST"]),
        Route("/api/jt_slot_process.json", jt_slot_process_route, methods=["POST"]),
        Route("/api/jt_scan.json", jt_scan_route, methods=["POST"]),
        Route("/api/string_xrefs.json", string_xrefs_route, methods=["POST"]),
        Route("/api/mmio_annotate.json", mmio_annotate_route, methods=["POST"]),
    ]


__all__ = ["make_routes"]
