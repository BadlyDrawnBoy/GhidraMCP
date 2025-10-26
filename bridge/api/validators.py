"""JSON schema validation helpers for API responses."""
from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any, Dict, List, Tuple

from jsonschema import Draft202012Validator


@lru_cache(maxsize=None)
def _load_schema(name: str) -> Draft202012Validator:
    with resources.files("bridge.api.schemas").joinpath(name).open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    return Draft202012Validator(schema)


def validate_payload(schema_name: str, payload: Dict[str, Any]) -> Tuple[bool, List[str]]:
    validator = _load_schema(schema_name)
    errors: List[str] = []
    for error in validator.iter_errors(payload):
        errors.append(error.message)
    return not errors, errors
