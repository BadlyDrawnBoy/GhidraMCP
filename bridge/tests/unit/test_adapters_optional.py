"""Tests for optional architecture adapters."""
from __future__ import annotations

import sys

from bridge.adapters import load_optional_adapter, optional_adapter_names
from bridge.adapters.fallback import FallbackAdapter
from bridge.api._shared import adapter_for_arch


def test_optional_registry_lists_x86() -> None:
    names = optional_adapter_names()
    assert "x86" in names
    assert names["x86"].endswith("X86Adapter")


def test_optional_adapter_is_lazy_imported(monkeypatch) -> None:
    monkeypatch.delenv("BRIDGE_OPTIONAL_ADAPTERS", raising=False)
    sys.modules.pop("bridge.adapters.x86", None)
    adapter = load_optional_adapter("x86")
    from bridge.adapters.x86 import X86Adapter  # imported on demand

    assert isinstance(adapter, X86Adapter)
    assert hasattr(adapter, "probe_function")


def test_optional_adapter_not_enabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv("BRIDGE_OPTIONAL_ADAPTERS", raising=False)
    adapter = adapter_for_arch("x86")
    assert isinstance(adapter, FallbackAdapter)


def test_optional_adapter_enabled_via_flag(monkeypatch) -> None:
    monkeypatch.setenv("BRIDGE_OPTIONAL_ADAPTERS", "x86")
    adapter = adapter_for_arch("x86")
    from bridge.adapters.x86 import X86Adapter

    assert isinstance(adapter, X86Adapter)
    assert adapter.in_code_range(0x1000, 0x1000, 0x2000)
