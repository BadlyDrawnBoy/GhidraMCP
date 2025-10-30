from importlib import import_module
from starlette.applications import Starlette
from starlette.testclient import TestClient

def _resolve():
    m = import_module("bridge.app")
    obj = getattr(m, "app", None)
    if isinstance(obj, Starlette):
        return obj
    f = getattr(m, "create_app", None)
    if callable(f):
        a = f()
        assert isinstance(a, Starlette)
        return a
    raise AssertionError("No app or create_app in bridge.app")

def test_entrypoint_openapi():
    app = _resolve()
    with TestClient(app) as c:
        r = c.get("/openapi.json")
        assert r.status_code == 200
        assert "openapi" in r.json()
