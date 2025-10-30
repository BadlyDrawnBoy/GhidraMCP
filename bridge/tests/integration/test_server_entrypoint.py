from typing import Callable

from starlette.applications import Starlette
from starlette.testclient import TestClient


def _resolve() -> Starlette:
    from bridge.app import app as module_app  # noqa: WPS433 (import inside function)

    if isinstance(module_app, Starlette):
        return module_app

    from bridge.app import create_app  # type: ignore  # noqa: WPS433

    factory: Callable[[], Starlette] = create_app  # type: ignore[assignment]
    app = factory()
    assert isinstance(app, Starlette)
    return app


def test_entrypoint_openapi() -> None:
    app = _resolve()
    with TestClient(app) as client:
        response = client.get("/openapi.json")
        assert response.status_code == 200
        assert "openapi" in response.json()
