"""Parse-only aggregator that extracts JSON envelopes from transcripts."""
from __future__ import annotations

from json import JSONDecoder, JSONDecodeError
from typing import Dict, Iterable, Mapping, MutableMapping, Optional, Sequence

from bridge.api.validators import validate_payload


_decoder = JSONDecoder()


def _extract_first_object(text: str) -> Optional[Dict[str, object]]:
    """Return the first JSON object embedded in *text* or ``None`` if absent."""

    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            payload, _ = _decoder.raw_decode(text[index:])
        except JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    return None


def _candidate_contents(record: Mapping[str, object]) -> Iterable[str]:
    content = record.get("content")
    if isinstance(content, str) and content:
        yield content
    messages = record.get("messages")
    if isinstance(messages, Sequence):
        for message in reversed(messages):
            if not isinstance(message, Mapping):
                continue
            role = message.get("role")
            if role is not None and str(role).lower() != "assistant":
                continue
            msg_content = message.get("content")
            if isinstance(msg_content, str) and msg_content:
                yield msg_content


def aggregate_transcripts(
    records: Sequence[Mapping[str, object]],
    *,
    schema: str = "envelope.v1.json",
) -> Dict[str, object]:
    """Parse transcript snippets into validated envelopes with summary counts."""

    items: list[MutableMapping[str, object]] = []
    summary: Dict[str, int] = {
        "total": len(records),
        "ok": 0,
        "failed": 0,
        "non_json": 0,
        "invalid_schema": 0,
    }
    for record in records:
        task = str(record.get("task", ""))
        raw_source = next(iter(_candidate_contents(record)), "")
        item: MutableMapping[str, object] = {"task": task, "raw": raw_source}
        payload: Optional[Dict[str, object]] = None
        for snippet in _candidate_contents(record):
            payload = _extract_first_object(snippet)
            if payload is not None:
                item["raw"] = snippet
                break
        if payload is None:
            item["ok"] = False
            item["error"] = {"code": "NON_JSON", "message": "No JSON object found"}
            summary["failed"] += 1
            summary["non_json"] += 1
            items.append(item)
            continue
        valid, errors = validate_payload(schema, payload)
        if not valid:
            item["ok"] = False
            item["error"] = {"code": "INVALID_SCHEMA", "message": "; ".join(errors)}
            summary["failed"] += 1
            summary["invalid_schema"] += 1
            items.append(item)
            continue
        item["ok"] = True
        item["data"] = payload
        summary["ok"] += 1
        items.append(item)
    return {"items": items, "summary": summary, "schema": schema}


__all__ = ["aggregate_transcripts"]
