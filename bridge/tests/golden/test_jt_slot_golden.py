from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Iterable

import pytest

from bridge.features import jt
from bridge.tests.unit.test_jt_feature import StubAdapter, StubClient


_DATA_DIR = Path(__file__).parent / "data"
_SNAPSHOT_PATH = _DATA_DIR / "jt_slot_cases.json"
_UPDATE = os.getenv("UPDATE_GOLDEN_SNAPSHOTS", "0").lower() in {
    "1",
    "true",
    "yes",
    "on",
}


class SnapshotStore:
    def __init__(self, data: Dict[str, object]) -> None:
        self._data = data

    def assert_match(self, key: str, payload: Dict[str, object]) -> None:
        if _UPDATE:
            self._data[key] = payload
            return
        assert key in self._data, f"Missing golden snapshot for {key}"
        assert self._data[key] == payload

    def dump(self) -> None:
        if not _UPDATE:
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
    store = SnapshotStore(data)
    yield store
    store.dump()


def _slot_check(
    *,
    client: StubClient,
    adapter: StubAdapter,
    slot_index: int,
) -> Dict[str, object]:
    return jt.slot_check(
        client,
        jt_base=0x400000,
        slot_index=slot_index,
        code_min=0x400000,
        code_max=0x401000,
        adapter=adapter,
    )


def test_jt_slot_check_cases(snapshot_store: SnapshotStore) -> None:
    snapshot_store.assert_match(
        "instruction_word",
        _slot_check(
            client=StubClient(read_result=0x400200),
            adapter=StubAdapter(sentinel_values={0x400200: True}),
            slot_index=0,
        ),
    )
    snapshot_store.assert_match(
        "out_of_range",
        _slot_check(
            client=StubClient(read_result=0x402000),
            adapter=StubAdapter(),
            slot_index=1,
        ),
    )
    snapshot_store.assert_match(
        "arm_valid",
        _slot_check(
            client=StubClient(read_result=0x400208),
            adapter=StubAdapter(
                mode="ARM",
                target=0x400208,
            ),
            slot_index=2,
        ),
    )
    snapshot_store.assert_match(
        "thumb_valid",
        _slot_check(
            client=StubClient(read_result=0x40020C),
            adapter=StubAdapter(
                mode="Thumb",
                target=0x40020C,
            ),
            slot_index=3,
        ),
    )
