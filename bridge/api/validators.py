"""JSON schema validation helpers for API responses."""
from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any, Dict, List, Tuple

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


@lru_cache(maxsize=None)
def _schema_contents(name: str) -> Dict[str, Any]:
    with resources.files("bridge.api.schemas").joinpath(name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


@lru_cache(maxsize=1)
def _registry() -> Registry:
    registry = Registry()
    package = resources.files("bridge.api.schemas")
    for entry in package.iterdir():
        if entry.name.endswith(".json"):
            contents = _schema_contents(entry.name)
            schema_id = contents.get("$id")
            if schema_id:
                registry = registry.with_resource(schema_id, Resource.from_contents(contents))
    return registry


@lru_cache(maxsize=None)
def _load_schema(name: str) -> Draft202012Validator:
    schema = _schema_contents(name)
    return Draft202012Validator(schema, registry=_registry())


def validate_payload(schema_name: str, payload: Dict[str, Any]) -> Tuple[bool, List[str]]:
    validator = _load_schema(schema_name)
    errors: List[str] = []
    for error in validator.iter_errors(payload):
        errors.append(error.message)
    return not errors, errors
