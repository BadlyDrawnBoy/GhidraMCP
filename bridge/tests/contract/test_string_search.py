from starlette.testclient import TestClient


def test_search_strings_contract(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/search_strings.json",
        json={"query": "o", "limit": 1, "offset": 1},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["errors"] == []

    data = body["data"]
    assert data["query"] == "o"
    assert data["total_results"] == 3
    assert data["page"] == 1
    assert data["limit"] == 1

    items = data["items"]
    assert len(items) == 1
    item = items[0]
    assert item["addr"] == "0x00200010"
    assert item["s"] == "Status: ready for commands"
    assert item["refs"] == 4
