"""Audit logging helpers for deterministic write operations."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, MutableMapping, Optional, Sequence

from .config import AUDIT_LOG_PATH
from .logging import RequestContext, current_request

logger = logging.getLogger("bridge.audit")

_audit_path: Optional[Path] = AUDIT_LOG_PATH


def set_audit_log_path(path: Path | str | None) -> None:
    """Override the audit log location (mainly for tests)."""

    global _audit_path
    if path is None:
        _audit_path = None
        return
    _audit_path = Path(path).expanduser()


def get_audit_log_path() -> Optional[Path]:
    """Return the currently configured audit log path."""

    return _audit_path


def _request_metadata(context: Optional[RequestContext]) -> MutableMapping[str, Any]:
    metadata: MutableMapping[str, Any] = {}
    if context is None:
        return metadata
    metadata["request_id"] = context.request_id
    metadata["request"] = context.name
    if context.metadata:
        metadata["context"] = dict(context.metadata)
    return metadata


def _write_entry(entry: Mapping[str, Any]) -> None:
    if _audit_path is None:
        logger.debug("Audit log disabled; skipping entry", extra={"event": "audit.skip"})
        return
    try:
        _audit_path.parent.mkdir(parents=True, exist_ok=True)
        with _audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
    except OSError:
        logger.exception("Failed to write audit log entry", extra={"path": str(_audit_path)})


def record_jt_write(
    *,
    slot: int,
    slot_address: str,
    function_address: int,
    rename_from: Optional[str],
    rename_to: Optional[str],
    rename_ok: bool,
    comment_from: Optional[str],
    comment_to: Optional[str],
    comment_ok: bool,
    verify_name: Optional[str],
    verify_comment_present: bool,
    notes: Sequence[str],
    errors: Sequence[str],
) -> None:
    """Persist a structured audit entry for a JT slot write."""

    if not (rename_ok or comment_ok):
        return

    context = current_request()
    payload: MutableMapping[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "category": "jt_slot_process",
        "slot": slot,
        "slot_address": slot_address,
        "function": f"0x{function_address:08x}",
        "rename": {
            "ok": rename_ok,
            "from": rename_from,
            "to": rename_to,
        },
        "comment": {
            "ok": comment_ok,
            "from": comment_from,
            "to": comment_to,
        },
        "verify": {
            "name": verify_name,
            "comment_present": verify_comment_present,
        },
        "notes": list(notes),
        "errors": list(errors),
    }
    payload.update(_request_metadata(context))
    _write_entry(payload)


__all__ = ["get_audit_log_path", "record_jt_write", "set_audit_log_path"]
