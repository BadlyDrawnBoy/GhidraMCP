from __future__ import annotations

from typing import Iterable

import pytest
from starlette.testclient import TestClient

import bridge.app as bridge_app
from bridge.tests.contract.conftest import StubGhidraClient


@pytest.fixture()
def app_client(monkeypatch: pytest.MonkeyPatch) -> Iterable[TestClient]:
    monkeypatch.setattr(bridge_app, "_client_factory", lambda: StubGhidraClient())
    test_app = bridge_app.create_app()
    with TestClient(test_app) as client:
        yield client


def test_strings_compact_contract(app_client: TestClient) -> None:
    response = app_client.post(
        "/api/strings_compact.json",
        json={"limit": 3, "offset": 0},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["errors"] == []
    data = body["data"]
    assert data["total"] == len(data["items"])
    items = data["items"]
    assert items
    assert [item["addr"] for item in items] == sorted(item["addr"] for item in items)
    assert all(set(item.keys()) == {"s", "addr", "refs"} for item in items)

    repeat = app_client.post(
        "/api/strings_compact.json",
        json={"limit": 3, "offset": 0},
    )
    assert repeat.status_code == 200
    assert repeat.json()["data"] == body["data"]
