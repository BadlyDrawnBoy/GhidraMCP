"""Application wiring for the modular bridge server."""
from __future__ import annotations

import os
from typing import Callable

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette

from .api.routes import make_routes
from .api.tools import register_tools
from .ghidra.client import GhidraClient
from .utils.logging import configure_root

MCP_SERVER = FastMCP("ghidra-bridge")
DEFAULT_GHIDRA_URL = os.getenv("GHIDRA_SERVER_URL", "http://127.0.0.1:8080/")
_CONFIGURED = False


def _client_factory() -> GhidraClient:
    return GhidraClient(DEFAULT_GHIDRA_URL)


def configure() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    configure_root()
    register_tools(MCP_SERVER, client_factory=_client_factory)
    _CONFIGURED = True


def build_api_app() -> Starlette:
    configure()
    routes = make_routes(_client_factory)
    return Starlette(routes=routes)


__all__ = ["MCP_SERVER", "configure", "build_api_app"]
