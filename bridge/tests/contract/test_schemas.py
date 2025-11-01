from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from bridge.api.routes import make_routes
from bridge.tests.golden.test_http_parity import GoldenStubGhidraClient


@dataclass(frozen=True)
class EndpointCase:
    id: str
    path: str
    valid: Dict[str, Any]
    missing: str


_CASES: List[EndpointCase] = [
    EndpointCase(
        id="jt_slot_check",
        path="/api/jt_slot_check.json",
        valid={
            "jt_base": "0x00100000",
            "slot_index": 0,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "arch": "arm",
        },
        missing="jt_base",
    ),
    EndpointCase(
        id="jt_slot_process",
        path="/api/jt_slot_process.json",
        valid={
            "jt_base": "0x00100000",
            "slot_index": 0,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "rename_pattern": "slot_{slot}_{target}",
            "comment": "Processed",
            "dry_run": True,
            "arch": "arm",
        },
        missing="jt_base",
    ),
    EndpointCase(
        id="jt_scan",
        path="/api/jt_scan.json",
        valid={
            "jt_base": "0x00100000",
            "start": 0,
            "count": 1,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "arch": "arm",
        },
        missing="start",
    ),
    EndpointCase(
        id="string_xrefs",
        path="/api/string_xrefs.json",
        valid={
            "string_addr": "0x00200000",
            "limit": 2,
        },
        missing="string_addr",
    ),
    EndpointCase(
        id="search_strings",
        path="/api/search_strings.json",
        valid={
            "query": "value",
            "limit": 5,
            "offset": 0,
        },
        missing="query",
    ),
    EndpointCase(
        id="strings_compact",
        path="/api/strings_compact.json",
        valid={
            "limit": 3,
            "offset": 0,
        },
        missing="limit",
    ),
    EndpointCase(
        id="search_imports",
        path="/api/search_imports.json",
        valid={
            "query": "import",
            "limit": 10,
            "offset": 0,
        },
        missing="query",
    ),
    EndpointCase(
        id="search_functions",
        path="/api/search_functions.json",
        valid={
            "query": "func",
            "limit": 10,
            "offset": 0,
        },
        missing="query",
    ),
    EndpointCase(
        id="mmio_annotate",
        path="/api/mmio_annotate.json",
        valid={
            "function_addr": "0x00007000",
            "dry_run": True,
            "max_samples": 2,
        },
        missing="function_addr",
    ),
]


@pytest.fixture()
def client() -> TestClient:
    def factory() -> GoldenStubGhidraClient:
        return GoldenStubGhidraClient()

    app = Starlette(routes=make_routes(factory, enable_writes=True))
    with TestClient(app) as test_client:
        yield test_client


def _case_ids() -> List[str]:
    return [case.id for case in _CASES]


@pytest.mark.parametrize("case", _CASES, ids=_case_ids())
def test_valid_payload_succeeds(client: TestClient, case: EndpointCase) -> None:
    payload = dict(case.valid)
    response = client.post(case.path, json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert isinstance(body["data"], dict)
    assert body["errors"] == []


@pytest.mark.parametrize("case", _CASES, ids=_case_ids())
def test_missing_required_field_is_rejected(
    client: TestClient, case: EndpointCase
) -> None:
    payload = dict(case.valid)
    payload.pop(case.missing, None)
    response = client.post(case.path, json=payload)
    assert response.status_code == 400
    body = response.json()
    assert body["ok"] is False
    assert body["data"] is None
    errors = body["errors"]
    assert isinstance(errors, list) and errors
    first_error = errors[0]
    assert first_error["code"].endswith("SCHEMA_INVALID")
    assert isinstance(first_error["message"], str) and first_error["message"]


@pytest.mark.parametrize("case", _CASES, ids=_case_ids())
def test_unexpected_field_is_rejected(client: TestClient, case: EndpointCase) -> None:
    payload = dict(case.valid)
    payload["unexpected"] = "value"
    response = client.post(case.path, json=payload)
    assert response.status_code == 400
    body = response.json()
    assert body["ok"] is False
    assert body["data"] is None
    errors = body["errors"]
    assert isinstance(errors, list) and errors
    first_error = errors[0]
    assert first_error["code"].endswith("SCHEMA_INVALID")
    assert "unexpected" in first_error["message"]
