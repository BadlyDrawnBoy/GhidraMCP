"""Contract tests for function search endpoint."""

import pytest
from starlette.testclient import TestClient


def test_search_functions_basic(contract_client: TestClient) -> None:
    """Test that search_functions returns correct structure."""
    response = contract_client.post(
        "/api/search_functions.json",
        json={"query": "func", "limit": 10, "offset": 0},
    )
    
    assert response.status_code == 200
    payload = response.json()
    
    assert payload["ok"] is True
    data = payload["data"]
    
    assert data["query"] == "func"
    assert "total_results" in data
    assert isinstance(data["total_results"], int)
    assert data["page"] == 0
    assert data["limit"] == 10
    assert "items" in data
    assert isinstance(data["items"], list)
    
    # Each item should have name and address
    for item in data["items"]:
        assert "name" in item
        assert "address" in item
        assert item["address"].startswith("0x")


def test_search_functions_pagination(contract_client: TestClient) -> None:
    """Test that offset pagination works correctly."""
    # First page
    response1 = contract_client.post(
        "/api/search_functions.json",
        json={"query": "func", "limit": 5, "offset": 0},
    )
    
    # Second page
    response2 = contract_client.post(
        "/api/search_functions.json",
        json={"query": "func", "limit": 5, "offset": 5},
    )
    
    assert response1.status_code == 200
    assert response2.status_code == 200
    
    data1 = response1.json()["data"]
    data2 = response2.json()["data"]
    
    # Both should have same total_results
    assert data1["total_results"] == data2["total_results"]
    
    # Different pages
    assert data1["page"] == 0
    assert data2["page"] == 1
    
    # Items should be different (if there are enough results)
    if data1["total_results"] > 5:
        items1_addrs = [item["address"] for item in data1["items"]]
        items2_addrs = [item["address"] for item in data2["items"]]
        assert items1_addrs != items2_addrs


def test_search_functions_validates_schema(contract_client: TestClient) -> None:
    """Test that invalid payloads are rejected."""
    # Missing required query field
    response = contract_client.post(
        "/api/search_functions.json",
        json={"limit": 10},
    )
    
    assert response.status_code == 400
    payload = response.json()
    assert payload["ok"] is False
    
    # Invalid limit type
    response = contract_client.post(
        "/api/search_functions.json",
        json={"query": "test", "limit": "invalid"},
    )
    
    assert response.status_code == 400


def test_search_functions_negative_offset(contract_client: TestClient) -> None:
    """Test that negative offset is rejected."""
    response = contract_client.post(
        "/api/search_functions.json",
        json={"query": "test", "limit": 10, "offset": -1},
    )
    
    assert response.status_code == 400
    payload = response.json()
    assert payload["ok"] is False


def test_search_functions_zero_limit(contract_client: TestClient) -> None:
    """Test that zero or negative limit is rejected."""
    response = contract_client.post(
        "/api/search_functions.json",
        json={"query": "test", "limit": 0},
    )
    
    assert response.status_code == 400
    payload = response.json()
    assert payload["ok"] is False
