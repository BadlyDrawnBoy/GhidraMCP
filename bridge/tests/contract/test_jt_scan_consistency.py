from __future__ import annotations

from typing import Dict

import pytest
from starlette.testclient import TestClient

# Ensure the contract fixtures are registered for this module.
from bridge.tests.contract import test_http_contracts as _http_contracts  # noqa: F401


@pytest.mark.parametrize(
    "start,count,expected",
    [
        (0, 4, {"valid": 1, "invalid": 3}),
        (4, 4, {"valid": 3, "invalid": 1}),
        (8, 4, {"valid": 4, "invalid": 0}),
    ],
)
def test_jt_scan_summary_consistency(
    contract_client: TestClient, start: int, count: int, expected: Dict[str, int]
) -> None:
    response = contract_client.post(
        "/api/jt_scan.json",
        json={
            "jt_base": "0x00100000",
            "start": start,
            "count": count,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "arch": "arm",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True

    data = payload["data"]
    summary = data["summary"]
    items = data["items"]

    assert summary["total"] == len(items) == count
    assert summary["valid"] + summary["invalid"] == summary["total"]
    assert summary["valid"] == expected["valid"]
    assert summary["invalid"] == expected["invalid"]
