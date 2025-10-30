"""Shared helpers for tools and HTTP routes."""
from __future__ import annotations

import os
from functools import wraps
from typing import Callable, Dict

from ..adapters import ArchAdapter, load_optional_adapter, optional_adapter_names
from ..adapters.arm_thumb import ARMThumbAdapter
from ..adapters.fallback import FallbackAdapter
from ..ghidra.client import GhidraClient
from ..utils.errors import ErrorCode, make_error


def envelope_ok(data: Dict[str, object]) -> Dict[str, object]:
    return {"ok": True, "data": data, "errors": []}


def envelope_error(code: ErrorCode | str, message: str) -> Dict[str, object]:
    return {"ok": False, "data": None, "errors": [make_error(code, message)]}


def adapter_for_arch(arch: str) -> ArchAdapter:
    normalized = arch.lower()
    if normalized in {"arm", "auto", "thumb"}:
        return ARMThumbAdapter()

    enabled = os.getenv("BRIDGE_OPTIONAL_ADAPTERS", "")
    if enabled:
        requested = {
            item.strip().lower()
            for item in enabled.split(",")
            if item.strip()
        }
        registry = optional_adapter_names()
        if normalized in requested and normalized in registry:
            return load_optional_adapter(normalized)

    return FallbackAdapter()


def with_client(factory: Callable[[], GhidraClient]):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            client = factory()
            try:
                return func(client, *args, **kwargs)
            finally:
                client.close()

        return wrapper

    return decorator
