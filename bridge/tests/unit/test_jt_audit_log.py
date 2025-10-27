from __future__ import annotations

import json

from bridge.features import jt
from bridge.tests.unit.test_jt_feature import StubAdapter, StubClient
from bridge.utils import audit
from bridge.utils.logging import request_scope


def test_slot_process_records_audit_entry(tmp_path) -> None:
    audit_file = tmp_path / "audit.log"
    previous_path = audit.get_audit_log_path()
    audit.set_audit_log_path(audit_file)
    try:
        client = StubClient(
            read_result=0x400200,
            metadata=[
                {"name": "orig_5", "comment": "old"},
                {"name": "new_5", "comment": "note"},
            ],
        )
        adapter = StubAdapter(mode="ARM", target=0x400200)

        with request_scope("jt_slot_process", extra={"jt_base": "0x00400000"}):
            result = jt.slot_process(
                client,
                jt_base=0x400000,
                slot_index=5,
                code_min=0x400000,
                code_max=0x500000,
                rename_pattern="new_{slot}",
                comment="note",
                adapter=adapter,
                dry_run=False,
                writes_enabled=True,
            )

        assert result["writes"] == {"renamed": True, "comment_set": True}
        content = audit_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(content) == 1
        entry = json.loads(content[0])
        assert entry["function"] == "0x00400200"
        assert entry["rename"] == {"ok": True, "from": "orig_5", "to": "new_5"}
        assert entry["comment"] == {"ok": True, "from": "old", "to": "note"}
        assert entry["verify"] == {"name": "new_5", "comment_present": True}
        assert entry["request"] == "jt_slot_process"
        assert entry["slot"] == 5
    finally:
        audit.set_audit_log_path(previous_path)
