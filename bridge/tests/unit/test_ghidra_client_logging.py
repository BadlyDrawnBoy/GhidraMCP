from __future__ import annotations

import pytest

from bridge.ghidra.client import GhidraClient
from bridge.utils.logging import request_scope


class FakeResponse:
    def __init__(self, text: str, status_code: int = 200) -> None:
        self.text = text
        self.status_code = status_code

    @property
    def is_error(self) -> bool:  # pragma: no cover - property behavior is trivial
        return self.status_code >= 400


class FakeSession:
    def request(self, method: str, url: str, params=None, data=None):  # noqa: ANN001
        path = url.rsplit("/", 1)[-1]
        if path == "read_dword":
            return FakeResponse("00000010\n")
        if path in {"disassemble", "disassemble_function", "disasmByAddr"}:
            return FakeResponse("00001000: MOV R0, R1\n00001004: BX LR\n")
        if path in {"function_by_addr", "get_function_by_address", "functionMeta"}:
            return FakeResponse("name: func\nentry_point: 0x00001000\n")
        if path in {"get_xrefs_to", "xrefs_to"}:
            return FakeResponse("00002000 | call string\n00003000 | BL other\n")
        if path in {"rename_function_by_address", "renameFunctionByAddress"}:
            return FakeResponse("OK\n")
        if path in {"set_decompiler_comment", "setDecompilerComment"}:
            return FakeResponse("OK\n")
        if path in {"set_disassembly_comment", "setDisassemblyComment"}:
            return FakeResponse("OK\n")
        return FakeResponse("ERROR: not found\n", status_code=404)

    def close(self) -> None:  # pragma: no cover - nothing to close
        return None


@pytest.fixture()
def client():
    ghidra = GhidraClient("https://example.invalid/")
    ghidra._session = FakeSession()
    return ghidra


def test_request_counters_are_recorded(client: GhidraClient) -> None:
    with request_scope("ghidra.test", extra={"tool": "test"}) as ctx:
        assert client.read_dword(0x1234) == 0x10
        assert client.disassemble_function(0x1234)
        assert client.get_function_by_address(0x1234)
        assert client.get_xrefs_to(0x5678, limit=2)
        assert client.rename_function(0x1234, "new_name")
        assert client.set_decompiler_comment(0x1234, "hi")
        assert client.set_disassembly_comment(0x1234, "hi")
    assert ctx.counters["ghidra.read"] == 1
    assert ctx.counters["ghidra.disasm"] == 1
    assert ctx.counters["ghidra.verify"] == 1
    assert ctx.counters["ghidra.xrefs"] == 1
    assert ctx.counters["ghidra.rename"] == 1
    assert ctx.counters["ghidra.decompiler_comment"] == 1
    assert ctx.counters["ghidra.disassembly_comment"] == 1
