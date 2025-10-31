from typing import Iterable, List

import pytest
from starlette.testclient import TestClient

import bridge.app as bridge_app
from bridge.tests.contract.conftest import StubGhidraClient


@pytest.fixture()
def app_client(monkeypatch: pytest.MonkeyPatch) -> Iterable[tuple[TestClient, StubGhidraClient]]:
    stub = StubGhidraClient()
    monkeypatch.setattr(bridge_app, "_client_factory", lambda: stub)
    test_app = bridge_app.create_app()
    with TestClient(test_app) as client:
        yield client, stub


def _seed_strings(stub: StubGhidraClient, count: int = 15) -> None:
    entries: List[dict[str, object]] = []
    for index in range(count):
        entries.append(
            {
                "literal": f"value {index}",
                "address": 0x00200000 + index,
                "refs": index % 7,
            }
        )
    stub._strings = entries


def test_search_strings_success(app_client: tuple[TestClient, StubGhidraClient]) -> None:
    client, stub = app_client
    _seed_strings(stub, 15)

    response = client.post(
        "/api/search_strings.json",
        json={"query": "value", "limit": 5, "offset": 5},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["errors"] == []
    data = body["data"]
    assert data["total_results"] == 15
    assert data["page"] == 2
    assert data["limit"] == 5
    items = data["items"]
    assert len(items) == 5
    expected_addrs = [f"0x{0x00200000 + idx:08x}" for idx in range(5, 10)]
    assert [item["addr"] for item in items] == expected_addrs
    assert [item["s"] for item in items] == [f"value {idx}" for idx in range(5, 10)]


def test_search_strings_limit_exceeded(
    app_client: tuple[TestClient, StubGhidraClient]
) -> None:
    client, stub = app_client
    _seed_strings(stub, 1)

    response = client.post(
        "/api/search_strings.json",
        json={"query": "value", "limit": 300, "offset": 0},
    )
    assert response.status_code == 400
    body = response.json()
    assert body["ok"] is False
    assert body["data"] is None
    errors = body["errors"]
    assert isinstance(errors, list) and errors
    first_error = errors[0]
    assert str(first_error["code"]).endswith("SAFETY_LIMIT")
    assert "limit exceeded" in str(first_error["message"]).lower()
