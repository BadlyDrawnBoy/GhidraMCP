"""Reusable CLI helpers for bridge entry points."""
from __future__ import annotations

import argparse
import logging
import os
import threading
from typing import Callable

import uvicorn
from starlette.applications import Starlette


ShimFactory = Callable[[str], Starlette]
StartSSE = Callable[[str, int], None]
RunStdIO = Callable[[], None]
SetGhidraURL = Callable[[str], None]


def build_parser(default_ghidra_server: str) -> argparse.ArgumentParser:
    """Create an argument parser mirroring the legacy CLI flags."""
    parser = argparse.ArgumentParser(
        description="Ghidra MCP Bridge with SSE and OpenWebUI shim"
    )
    parser.add_argument(
        "--ghidra-server",
        type=str,
        default=default_ghidra_server,
        help=f"Ghidra-Bridge URL, default: {default_ghidra_server}",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="sse",
        choices=["stdio", "sse"],
        help="MCP-Transport (Open WebUI braucht SSE).",
    )
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host für internen MCP-SSE-Server (Upstream), default: 127.0.0.1",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        default=8099,
        help="Port für internen MCP-SSE-Server (Upstream), default: 8099",
    )
    parser.add_argument(
        "--shim-host",
        type=str,
        default="127.0.0.1",
        help="Host für Shim/Proxy (für Open WebUI), default: 127.0.0.1",
    )
    parser.add_argument(
        "--shim-port",
        type=int,
        default=8081,
        help="Port für Shim/Proxy (für Open WebUI), default: 8081",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser


def run(
    args: argparse.Namespace,
    *,
    logger: logging.Logger,
    default_ghidra_server: str,
    set_ghidra_url: SetGhidraURL,
    start_sse: StartSSE,
    run_stdio: RunStdIO,
    shim_factory: ShimFactory,
) -> None:
    """Execute the CLI behaviour shared by legacy and modular entry points."""
    if args.debug:
        logger.setLevel(logging.DEBUG)

    ghidra_url = os.getenv(
        "GHIDRA_SERVER_URL", args.ghidra_server or default_ghidra_server
    )
    set_ghidra_url(ghidra_url)
    logger.info("[Bridge] Connecting to Ghidra server at %s", ghidra_url)

    if args.transport == "sse":
        thread = threading.Thread(
            target=start_sse, args=(args.mcp_host, args.mcp_port), daemon=True
        )
        thread.start()

        upstream_base = f"http://{args.mcp_host}:{args.mcp_port}"
        app = shim_factory(upstream_base)
        logger.info(
            "[Shim] OpenWebUI endpoint on http://%s:%s/openapi.json",
            args.shim_host,
            args.shim_port,
        )
        uvicorn.run(app, host=args.shim_host, port=int(args.shim_port))
    else:
        logger.info("[MCP] Running in stdio mode (no SSE).")
        run_stdio()


__all__ = ["build_parser", "run"]
