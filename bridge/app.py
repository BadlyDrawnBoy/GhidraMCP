"""Application wiring for the modular bridge server."""
from __future__ import annotations

import os
from typing import Callable

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from .api.routes import make_routes
from .api.tools import register_tools
from .ghidra.client import GhidraClient
from .utils.logging import configure_root

MCP_SERVER = FastMCP("ghidra-bridge")
_ghidra_server_url = os.getenv("GHIDRA_SERVER_URL", "http://127.0.0.1:8080/")
_CONFIGURED = False


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


__all__ = [
    "MCP_SERVER",
    "app",
    "build_api_app",
    "configure",
    "create_app",
    "set_ghidra_base_url",
]
