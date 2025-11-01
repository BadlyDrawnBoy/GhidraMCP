"""Application wiring for the modular bridge server."""
from __future__ import annotations

import asyncio
import logging
import os
import uuid
from dataclasses import dataclass
from types import MethodType

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import SseServerTransport
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from .api.routes import make_routes
from .api.tools import register_tools
from .ghidra.client import GhidraClient
from .utils.logging import configure_root

MCP_SERVER = FastMCP("ghidra-bridge")
_ghidra_server_url = os.getenv("GHIDRA_SERVER_URL", "http://127.0.0.1:8080/")
_CONFIGURED = False


@dataclass(slots=True)
class BridgeState:
    """Mutable diagnostics for guarding the SSE endpoint."""

    active_sse_id: str | None = None
    connects: int = 0


_BRIDGE_STATE = BridgeState()
_STATE_LOCK = asyncio.Lock()
_SSE_LOGGER = logging.getLogger("bridge.sse")


def _build_openapi_schema(routes: list[Route]) -> dict[str, object]:
    paths: dict[str, dict[str, object]] = {}
    for route in routes:
        # Only document standard HTTP routes.
        if not isinstance(route, Route):  # pragma: no cover - defensive
            continue
        if route.path == "/openapi.json":
            continue
        methods = sorted(route.methods or set())
        if not methods:
            continue
        operations = paths.setdefault(route.path, {})
        for method in methods:
            operations[method.lower()] = {
                "summary": route.name or getattr(route.endpoint, "__name__", "handler"),
            }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Ghidra MCP Bridge API",
            "version": "1.0.0",
        },
        "paths": paths,
    }


def set_ghidra_base_url(url: str) -> None:
    """Override the default Ghidra server used by API client factories."""

    global _ghidra_server_url
    _ghidra_server_url = url


def _client_factory() -> GhidraClient:
    return GhidraClient(_ghidra_server_url)


def configure() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    configure_root()
    register_tools(MCP_SERVER, client_factory=_client_factory)
    _CONFIGURED = True


def _guarded_sse_app(self: FastMCP) -> Starlette:
    """Return an SSE app that enforces a single active connection."""

    configure()
    transport = SseServerTransport(self.settings.message_path)

    async def handle_get(request: Request) -> None:
        client = request.client or ("unknown", 0)
        user_agent = request.headers.get("user-agent", "")
        async with _STATE_LOCK:
            if _BRIDGE_STATE.active_sse_id is not None:
                _SSE_LOGGER.warning(
                    "sse.reject",
                    extra={
                        "client_host": client[0],
                        "client_port": client[1],
                        "user_agent": user_agent,
                        "active_sse_id": _BRIDGE_STATE.active_sse_id,
                    },
                )
                return JSONResponse(
                    {"error": "sse_already_active", "detail": "Another client is connected."},
                    status_code=409,
                )
            connection_id = uuid.uuid4().hex
            _BRIDGE_STATE.active_sse_id = connection_id
            _BRIDGE_STATE.connects += 1

        _SSE_LOGGER.info(
            "sse.connect",
            extra={
                "client_host": client[0],
                "client_port": client[1],
                "user_agent": user_agent,
                "connection_id": connection_id,
                "connects": _BRIDGE_STATE.connects,
            },
        )

        try:
            async with transport.connect_sse(
                request.scope,
                request.receive,
                request._send,  # type: ignore[arg-type]
            ) as streams:
                await self._mcp_server.run(
                    streams[0],
                    streams[1],
                    self._mcp_server.create_initialization_options(),
                )
        finally:
            async with _STATE_LOCK:
                if _BRIDGE_STATE.active_sse_id == connection_id:
                    _BRIDGE_STATE.active_sse_id = None
            _SSE_LOGGER.info(
                "sse.disconnect",
                extra={
                    "client_host": client[0],
                    "client_port": client[1],
                    "user_agent": user_agent,
                    "connection_id": connection_id,
                },
            )

    async def handle_post(request: Request) -> JSONResponse:
        client = request.client or ("unknown", 0)
        user_agent = request.headers.get("user-agent", "")
        _SSE_LOGGER.info(
            "sse.method_not_allowed",
            extra={
                "client_host": client[0],
                "client_port": client[1],
                "user_agent": user_agent,
            },
        )
        return JSONResponse(
            {"error": "method_not_allowed", "allow": "GET"},
            status_code=405,
            headers={"Allow": "GET"},
        )

    return Starlette(
        debug=self.settings.debug,
        routes=[
            Route(self.settings.sse_path, endpoint=handle_get, methods=["GET"]),
            Route(self.settings.sse_path, endpoint=handle_post, methods=["POST"]),
            Mount(self.settings.message_path, app=transport.handle_post_message),
        ],
    )


def build_api_app() -> Starlette:
    configure()
    routes = list(make_routes(_client_factory))
    schema = _build_openapi_schema(routes)

    async def openapi(_: Request) -> JSONResponse:
        return JSONResponse(schema)

    routes.append(Route("/openapi.json", openapi, methods=["GET"], name="openapi"))
    return Starlette(routes=routes)


def create_app() -> Starlette:
    """Factory compatible with ``uvicorn --factory``."""

    return build_api_app()


app = build_api_app()


# Install the guarded SSE app on import so both tests and runtime honour it.
MCP_SERVER.sse_app = MethodType(_guarded_sse_app, MCP_SERVER)


__all__ = [
    "MCP_SERVER",
    "app",
    "build_api_app",
    "configure",
    "create_app",
    "set_ghidra_base_url",
]
