import asyncio
import logging

import httpx
import pytest
from starlette.applications import Starlette

from bridge.api.routes import make_routes
from bridge.ghidra.client import GhidraClient


class RecordingSemaphore(asyncio.Semaphore):
    """Semaphore that tracks concurrent acquisitions for assertions."""

    def __init__(self) -> None:
        super().__init__(1)
        self.current = 0
        self.max_active = 0
        self.acquired = 0

    async def __aenter__(self) -> "RecordingSemaphore":
        await super().__aenter__()
        self.current += 1
        self.acquired += 1
        self.max_active = max(self.max_active, self.current)
        await asyncio.sleep(0)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self.current -= 1
        await super().__aexit__(exc_type, exc, tb)


async def _exercise_serialization(caplog: pytest.LogCaptureFixture) -> None:
    semaphore = RecordingSemaphore()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, text="ok\n")
        return httpx.Response(404, text="not found\n")

    mock_transport = httpx.MockTransport(handler)

    def factory() -> GhidraClient:
        return GhidraClient("http://ghidra/", transport=mock_transport)

    app = Starlette(routes=make_routes(factory, call_semaphore=semaphore))

    caplog.set_level(logging.INFO)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        responses = await asyncio.gather(
            client.get("/api/health.json"),
            client.get("/api/health.json"),
        )

    assert [response.status_code for response in responses] == [200, 200]
    assert semaphore.acquired >= 2
    assert semaphore.max_active == 1

    ghidra_logs = [record for record in caplog.records if record.message == "ghidra.request"]
    assert len(ghidra_logs) >= 2
    for record in ghidra_logs:
        assert getattr(record, "method", None) == "GET"
        assert getattr(record, "path", None) in {"/", "read_dword"}
        duration = getattr(record, "duration_ms", 0.0)
        assert isinstance(duration, float)
        assert duration >= 0.0


def test_plugin_calls_are_serialized(caplog: pytest.LogCaptureFixture) -> None:
    asyncio.run(_exercise_serialization(caplog))
