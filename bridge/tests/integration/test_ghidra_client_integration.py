from __future__ import annotations

import httpx

from bridge.ghidra.client import GhidraClient


def _success_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path.endswith("/read_dword"):
        return httpx.Response(200, text="00001000\n")
    if path.endswith("/function_by_addr"):
        return httpx.Response(200, text="name: target\nentry_point: 0x00001000\n")
    if path.endswith("/disassemble"):
        return httpx.Response(200, text="00001000: PUSH {lr}\n00001004: BX LR\n")
    if path.endswith("/get_xrefs_to"):
        return httpx.Response(200, text="00002000 | BL target\n")
    if path.endswith("/rename_function_by_address"):
        return httpx.Response(200, text="OK\n")
    if path.endswith("/set_decompiler_comment"):
        return httpx.Response(200, text="OK\n")
    if path.endswith("/set_disassembly_comment"):
        return httpx.Response(200, text="OK\n")
    return httpx.Response(404, text="ERROR: not found\n")


def test_ghidra_client_happy_path() -> None:
    client = GhidraClient("http://ghidra/", transport=httpx.MockTransport(_success_handler))

    assert client.read_dword(0x1000) == 0x1000
    meta = client.get_function_by_address(0x1000)
    assert meta and meta["name"] == "target"
    assert client.disassemble_function(0x1000)
    assert client.get_xrefs_to(0x2000) == [
        {"addr": 0x2000, "context": "BL target"}
    ]
    assert client.rename_function(0x1000, "new_name") is True
    assert client.set_decompiler_comment(0x1000, "note") is True
    assert client.set_disassembly_comment(0x1000, "note") is True


def _failure_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path.endswith("/read_dword"):
        return httpx.Response(200, text="n/a\n")
    if path.endswith("/function_by_addr"):
        return httpx.Response(500, text="Internal error\n")
    if path.endswith("/rename_function_by_address") or path.endswith("/renameFunctionByAddress"):
        return httpx.Response(200, text="ERROR: rename failed\n")
    if path.endswith("/set_decompiler_comment") or path.endswith("/setDecompilerComment"):
        return httpx.Response(200, text="ERROR: comment failed\n")
    if path.endswith("/set_disassembly_comment") or path.endswith("/setDisassemblyComment"):
        return httpx.Response(200, text="ERROR: disasm failed\n")
    return httpx.Response(404, text="ERROR: not found\n")


def test_ghidra_client_handles_failures() -> None:
    client = GhidraClient("http://ghidra/", transport=httpx.MockTransport(_failure_handler))

    assert client.read_dword(0x1000) is None
    assert client.get_function_by_address(0x1000) is None
    assert client.rename_function(0x1000, "new") is False
    assert client.set_decompiler_comment(0x1000, "note") is False
    assert client.set_disassembly_comment(0x1000, "note") is False


def test_ghidra_client_timeouts_are_reported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    client = GhidraClient("http://ghidra/", transport=httpx.MockTransport(handler), timeout=0.01)

    assert client.read_dword(0x1000) is None
    assert client.rename_function(0x1000, "name") is False
