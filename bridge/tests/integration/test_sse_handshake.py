"""Integration test ensuring the SSE endpoint produces a handshake event."""
from __future__ import annotations

import anyio
import pytest

from bridge.app import MCP_SERVER, configure


@pytest.fixture
def anyio_backend() -> str:
    """Force the anyio pytest plugin to use the asyncio backend."""

    return "asyncio"


@pytest.mark.anyio
async def test_sse_handshake_emits_endpoint_event() -> None:
    """The SSE endpoint should emit an endpoint event with a session URI."""

    configure()
    app = MCP_SERVER.sse_app()

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/sse",
        "raw_path": b"/sse",
        "root_path": "",
        "query_string": b"",
        "headers": [(b"accept", b"text/event-stream")],
        "client": ("testclient", 12345),
        "server": ("testserver", 80),
    }

    event_received = anyio.Event()
    messages: list[dict[str, object]] = []
    received_request = False

    async def receive() -> dict[str, object]:
        nonlocal received_request
        if not received_request:
            received_request = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await anyio.sleep_forever()

    async def send(message: dict[str, object]) -> None:
        messages.append(message)
        if message["type"] == "http.response.body" and message.get("body"):
            event_received.set()

    cancel_scope = anyio.CancelScope()

    async def run_app() -> None:
        with cancel_scope:
            await app(scope, receive, send)

    async with anyio.create_task_group() as tg:
        tg.start_soon(run_app)
        with anyio.fail_after(2):
            await event_received.wait()
        cancel_scope.cancel()

    status_messages = [m for m in messages if m["type"] == "http.response.start"]
    assert status_messages, "Expected HTTP response start message"
    status = status_messages[0]
    assert status["status"] == 200

    body_chunks = [
        m["body"].decode("utf-8")
        for m in messages
        if m["type"] == "http.response.body" and m.get("body")
    ]
    assert body_chunks, "Expected at least one SSE body chunk"

    payload = "".join(body_chunks)
    lines = [line for line in payload.splitlines() if line]

    event_line = next(line for line in lines if line.startswith("event:"))
    data_line = next(line for line in lines if line.startswith("data:"))

    assert event_line.split(":", 1)[1].strip() == "endpoint"
    session_uri = data_line.split(":", 1)[1].strip()
    assert session_uri.startswith("/messages")
    assert "session_id=" in session_uri
