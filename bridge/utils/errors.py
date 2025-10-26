"""Error codes and helpers for the bridge server."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional


class ErrorCode(str, Enum):
    """Stable error codes returned from the deterministic endpoints."""

    ARM_INSTRUCTION = "ARM_INSTRUCTION"
    OUT_OF_RANGE = "OUT_OF_RANGE"
    NO_FUNCTION_AT_TARGET = "NO_FUNCTION_AT_TARGET"
    TOOL_BINDING_MISSING = "TOOL_BINDING_MISSING"
    WRITE_DISABLED_DRY_RUN = "WRITE_DISABLED_DRY_RUN"
    WRITE_VERIFY_FAILED = "WRITE_VERIFY_FAILED"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"


@dataclass(slots=True)
class ErrorDetail:
    """Structured error payload for the public envelope."""

    code: ErrorCode | str
    message: str
    details: Optional[Dict[str, Any]] = None

    def to_json(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"code": str(self.code), "message": self.message}
        if self.details is not None:
            payload["details"] = self.details
        return payload


def make_error(code: ErrorCode | str, message: str, *, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Create a JSON-serialisable error dict."""

    return ErrorDetail(code=code, message=message, details=details).to_json()
