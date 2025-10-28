from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Iterable

import pytest
from starlette.testclient import TestClient

from bridge.shim import build_openwebui_shim


_DATA_DIR = Path(__file__).parent / "data"
_SNAPSHOT_PATH = _DATA_DIR / "legacy_shim_snapshots.json"
_UPDATE_SNAPSHOTS = os.getenv("UPDATE_GOLDEN_SNAPSHOTS", "0").lower() in {
    "1",
    "true",
    "yes",
    "on",
}


class SnapshotStore:
    """Read/write helper for legacy shim golden snapshots."""

    def __init__(self, data: Dict[str, object], update: bool) -> None:
        self._data = data
        self._update = update

    def assert_match(self, key: str, payload: Dict[str, object]) -> None:
        if self._update:
            self._data[key] = payload
            return
        assert key in self._data, f"Missing golden snapshot for {key}"
        assert payload == self._data[key]

    def dump(self) -> None:
        if not self._update:
            return
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        with _SNAPSHOT_PATH.open("w", encoding="utf-8") as handle:
            json.dump(self._data, handle, indent=2, sort_keys=True)
            handle.write("\n")


@pytest.fixture(scope="module")
def snapshot_store() -> Iterable[SnapshotStore]:
    data: Dict[str, object] = {}
    if _SNAPSHOT_PATH.exists():
        with _SNAPSHOT_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    store = SnapshotStore(data, _UPDATE_SNAPSHOTS)
    yield store
    store.dump()


@pytest.fixture()
def legacy_shim_client() -> Iterable[TestClient]:
    app = build_openwebui_shim("http://127.0.0.1:8080")
    with TestClient(app) as client:
        yield client


def test_openapi_get_snapshot(
    legacy_shim_client: TestClient, snapshot_store: SnapshotStore
) -> None:
    response = legacy_shim_client.get("/openapi.json")
    assert response.status_code == 200
    snapshot_store.assert_match("openapi_get", response.json())


def test_openapi_post_snapshot(
    legacy_shim_client: TestClient, snapshot_store: SnapshotStore
) -> None:
    response = legacy_shim_client.post("/openapi.json", json={"id": 123})
    assert response.status_code == 200
    snapshot_store.assert_match("openapi_post", response.json())


def test_health_snapshot(
    legacy_shim_client: TestClient, snapshot_store: SnapshotStore
) -> None:
    response = legacy_shim_client.get("/health")
    assert response.status_code == 200
    snapshot_store.assert_match("health_get", response.json())


def test_root_post_snapshot(
    legacy_shim_client: TestClient, snapshot_store: SnapshotStore
) -> None:
    response = legacy_shim_client.post("/")
    assert response.status_code == 200
    snapshot_store.assert_match("root_post", response.json())
