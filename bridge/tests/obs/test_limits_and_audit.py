from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from bridge.features import jt
from bridge.tests.unit.test_jt_feature import StubAdapter, StubClient
from bridge.utils import audit
from bridge.utils.logging import (
    SafetyLimitExceeded,
    enforce_batch_limit,
    increment_counter,
    record_write_attempt,
    request_scope,
)


def test_request_scope_logs_structured_metadata(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("bridge.obs.test")
    with caplog.at_level(logging.DEBUG, logger="bridge.obs.test"):
        with request_scope(
            "obs.test",
            logger=logger,
            extra={"path": "/api/test.json"},
        ) as ctx:
            increment_counter("items", 3)
            enforce_batch_limit(1)
    start = next(record for record in caplog.records if record.message == "request.start")
    finish = next(record for record in caplog.records if record.message == "request.finish")
    timer = next(record for record in caplog.records if record.message == "obs.test.duration")

    assert start.request_id == ctx.request_id
    assert start.request == "obs.test"
    assert finish.request_id == ctx.request_id
    assert finish.counters == {"items": 3, "batch_size": 1}
    assert finish.duration_s >= 0
    assert timer.duration_s >= 0


def test_limits_respect_config_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("bridge.utils.logging.MAX_WRITES_PER_REQUEST", 1)
    monkeypatch.setattr("bridge.utils.logging.MAX_ITEMS_PER_BATCH", 2)

    with request_scope("limits.test"):
        record_write_attempt()
        with pytest.raises(SafetyLimitExceeded):
            record_write_attempt()
        enforce_batch_limit(2)
        with pytest.raises(SafetyLimitExceeded):
            enforce_batch_limit(3)


def test_audit_log_includes_request_metadata(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    previous_path = audit.get_audit_log_path()
    audit.set_audit_log_path(audit_path)
    client = StubClient(
        read_result=0x400200,
        metadata=[
            {"name": "old_name", "comment": "prev"},
            {"name": "new_name", "comment": "updated"},
        ],
    )
    adapter = StubAdapter(mode="ARM", target=0x400200)

    try:
        with request_scope(
            "jt_slot_process",
            extra={"path": "/api/jt_slot_process.json"},
        ) as ctx:
            result = jt.slot_process(
                client,
                jt_base=0x400000,
                slot_index=7,
                code_min=0x400000,
                code_max=0x500000,
                rename_pattern="renamed_{slot}",
                comment="updated",
                adapter=adapter,
                dry_run=False,
                writes_enabled=True,
            )
        assert result["writes"] == {"renamed": True, "comment_set": True}
        assert audit_path.exists()
        lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["request_id"] == ctx.request_id
        assert entry["request"] == "jt_slot_process"
        assert entry["context"] == {"path": "/api/jt_slot_process.json"}
        assert entry["rename"] == {"ok": True, "from": "old_name", "to": "new_name"}
        assert entry["comment"] == {"ok": True, "from": "prev", "to": "updated"}
        assert entry["verify"] == {"name": "new_name", "comment_present": True}
        assert entry["errors"] == []
    finally:
        audit.set_audit_log_path(previous_path)

    assert audit_path.unlink() is None
