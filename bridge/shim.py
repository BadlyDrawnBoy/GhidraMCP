"""Legacy Starlette shim used by OpenWebUI deployments."""

from __future__ import annotations

import httpx
from typing import Sequence

from starlette.applications import Starlette
from starlette.responses import JSONResponse, StreamingResponse, PlainTextResponse
from starlette.routing import Route
from starlette.requests import Request


def build_openwebui_shim(
    upstream_base: str, *, extra_routes: Sequence[Route] | None = None
) -> Starlette:
    """Create a Starlette app exposing the legacy OpenWebUI shim routes."""

    async def openapi_get(request: Request):  # pragma: no cover - thin glue
        return JSONResponse(
            {
                "openapi": "3.1.0",
                "info": {"title": "Ghidra MCP Bridge (stub)", "version": "0.1"},
                "x-openwebui-mcp": {
                    "transport": "sse",
                    "sse_url": "/sse",
                    "messages_url": "/messages",
                },
            }
        )

    async def openapi_post(request: Request):  # pragma: no cover - thin glue
        try:
            body = await request.json()
            req_id = body.get("id", 0)
        except Exception:  # noqa: BLE001 - compatibility shim must be forgiving
            req_id = 0

        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {
                        "experimental": {},
                        "prompts": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                        "tools": {"listChanged": False},
                    },
                    "serverInfo": {"name": "ghidra-mcp", "version": "1.14.1"},
                },
            }
        )

    async def health(request: Request):  # pragma: no cover - thin glue
        return JSONResponse(
            {
                "ok": True,
                "type": "mcp-sse",
                "endpoints": {"sse": "/sse", "messages": "/messages"},
            }
        )

    async def root_post_ok(request: Request):  # pragma: no cover - thin glue
        return JSONResponse({"jsonrpc": "2.0", "id": 0, "result": {"ok": True}})

    async def sse_proxy(request: Request):  # pragma: no cover - passthrough logic
        url = upstream_base + "/sse"
        headers = {"accept": "text/event-stream"}
        params = dict(request.query_params)

        async def event_generator():
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream(
                    "GET", url, params=params, headers=headers
                ) as upstream:
                    async for chunk in upstream.aiter_bytes():
                        yield chunk

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    async def messages_proxy(request: Request):  # pragma: no cover - passthrough
        url = upstream_base + request.url.path
        data = await request.body()
        headers = {
            "content-type": request.headers.get(
                "content-type", "application/json"
            )
        }
        params = dict(request.query_params)

        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
            resp = await client.post(
                url, content=data, headers=headers, params=params
            )
            return PlainTextResponse(
                resp.text,
                status_code=resp.status_code,
                headers={
                    "content-type": resp.headers.get(
                        "content-type", "application/json"
                    )
                },
            )

    routes = [
        Route("/openapi.json", openapi_get, methods=["GET"]),
        Route("/openapi.json", openapi_post, methods=["POST"]),
        Route("/health", health, methods=["GET"]),
        Route("/", root_post_ok, methods=["POST"]),
        Route("/sse", sse_proxy, methods=["GET"]),
        Route("/messages", messages_proxy, methods=["POST"]),
        Route("/messages/", messages_proxy, methods=["POST"]),
    ]
    if extra_routes:
        routes.extend(extra_routes)
    return Starlette(debug=False, routes=routes)


__all__ = ["build_openwebui_shim"]
