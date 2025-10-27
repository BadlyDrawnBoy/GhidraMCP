from __future__ import annotations

from bridge.orchestrator.aggregator import aggregate_transcripts


def test_aggregate_transcripts_success() -> None:
    records = [
        {
            "task": "jt_slot_check",
            "content": "log prefix {\"ok\": true, \"data\": {\"value\": 1}, \"errors\": []} trailing",
        }
    ]

    result = aggregate_transcripts(records)

    assert result["summary"] == {"total": 1, "ok": 1, "failed": 0, "non_json": 0, "invalid_schema": 0}
    assert result["items"][0]["ok"] is True
    assert result["items"][0]["data"]["data"] == {"value": 1}


def test_aggregate_transcripts_handles_missing_json() -> None:
    result = aggregate_transcripts([{"task": "jt_scan", "content": "no json here"}])

    assert result["summary"]["failed"] == 1
    assert result["summary"]["non_json"] == 1
    assert result["items"][0]["error"]["code"] == "NON_JSON"


def test_aggregate_transcripts_handles_invalid_schema() -> None:
    records = [
        {"task": "jt_slot_process", "content": "ignored {\"foo\": 1} text"},
    ]

    result = aggregate_transcripts(records)

    assert result["summary"]["failed"] == 1
    assert result["summary"]["invalid_schema"] == 1
    assert result["items"][0]["error"]["code"] == "INVALID_SCHEMA"


def test_aggregate_transcripts_ignores_chatter_between_tasks() -> None:
    records = [
        {
            "task": "task_1",
            "messages": [
                {
                    "role": "assistant",
                    "content": "Result {\"ok\": true, \"data\": {\"value\": 1}, \"errors\": []}",
                }
            ],
        },
        {
            "task": "task_2",
            "messages": [
                {
                    "role": "assistant",
                    "content": "Earlier chat mentioned {\"ok\": true, \"data\": {\"value\": 1}, \"errors\": []}",
                },
                {
                    "role": "assistant",
                    "content": "Final output {\"ok\": false, \"data\": null, \"errors\": []}",
                },
            ],
        },
    ]

    result = aggregate_transcripts(records)

    assert result["summary"]["ok"] == 2
    assert result["items"][0]["data"]["data"] == {"value": 1}
    assert result["items"][1]["data"]["ok"] is False
