import httpx

from bridge.ghidra.client import GhidraClient
from bridge.ghidra.whitelist import WhitelistEntry


def _build_transport(on_request):
    def handler(request: httpx.Request) -> httpx.Response:
        return on_request(request)

    return httpx.MockTransport(handler)


def test_alias_resolution_uses_whitelist_key():
    requested_paths = []

    def handle(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        return httpx.Response(200, text="line1\nline2")

    whitelist = {
        "GET": (
            WhitelistEntry("GET", "DISASSEMBLE", ("disassemble", "disasmByAddr")),
        )
    }
    client = GhidraClient(
        "https://example.test/api",
        whitelist=whitelist,
        transport=_build_transport(handle),
    )

    lines = client.disassemble_function(0x401000)

    assert lines == ["line1", "line2"]
    # Ensure the resolver hit an allowed alias and the whitelist permitted it via the key
    assert requested_paths == ["/api/disassemble"]


def test_requests_for_unknown_alias_are_blocked():
    def handle(_request: httpx.Request) -> httpx.Response:  # pragma: no cover - should not be called
        raise AssertionError("Transport should not be invoked for blocked aliases")

    whitelist = {
        "GET": (
            WhitelistEntry("GET", "DISASSEMBLE", ("disassemble",)),
        )
    }
    client = GhidraClient(
        "https://example.test/api",
        whitelist=whitelist,
        transport=_build_transport(handle),
    )

    result = client._request_lines("GET", "disasmByAddr", key="DISASSEMBLE")

    assert result == ["ERROR: endpoint GET disasmByAddr not allowed"]


def test_post_alias_resolver_falls_back_to_camel_case():
    requested_paths = []

    def handle(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        if request.url.path.endswith("rename_function_by_address"):
            return httpx.Response(404, text="Not Found")
        return httpx.Response(200, text="")

    whitelist = {
        "POST": (
            WhitelistEntry(
                "POST",
                "RENAME_FUNCTION",
                ("rename_function_by_address", "renameFunctionByAddress"),
            ),
        )
    }

    client = GhidraClient(
        "https://example.test/api",
        whitelist=whitelist,
        transport=_build_transport(handle),
    )

    assert client.rename_function(0x401000, "new_name") is True
    assert requested_paths == [
        "/api/rename_function_by_address",
        "/api/renameFunctionByAddress",
    ]


def test_default_whitelist_blocks_forbidden_get_calls():
    def handle(_request: httpx.Request) -> httpx.Response:  # pragma: no cover - blocked
        raise AssertionError("Forbidden GET endpoint should never reach transport")

    client = GhidraClient(
        "https://example.test/api",
        transport=_build_transport(handle),
    )

    for path in ("read_bytes", "read_cstring", "list_functions", "search_bytes"):
        result = client._request_lines("GET", path)
        assert result == [f"ERROR: endpoint GET {path} not allowed"]


def test_confirm_true_payload_is_rejected():
    def handle(_request: httpx.Request) -> httpx.Response:  # pragma: no cover - blocked
        raise AssertionError("Requests with confirm=true should be rejected before transport")

    client = GhidraClient(
        "https://example.test/api",
        transport=_build_transport(handle),
    )

    result = client._request_lines(
        "POST",
        "rename_function_by_address",
        key="RENAME_FUNCTION",
        data={
            "function_address": "0x00401000",
            "new_name": "foo",
            "confirm": True,
        },
    )

    assert result == ["ERROR: endpoint POST rename_function_by_address not allowed"]


def test_get_alias_resolution_is_cached():
    requested_paths = []

    def handle(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        if request.url.path.endswith("disassemble"):
            return httpx.Response(404, text="Not Found")
        return httpx.Response(200, text="line1\n")

    client = GhidraClient(
        "https://example.test/api",
        transport=_build_transport(handle),
    )

    assert client.disassemble_function(0x401000) == ["line1"]
    assert client.disassemble_function(0x401000) == ["line1"]
    assert requested_paths == [
        "/api/disassemble",
        "/api/disassemble_function",
        "/api/disassemble_function",
    ]


def test_post_alias_resolution_is_cached():
    requested_paths = []

    def handle(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        if request.url.path.endswith("rename_function_by_address"):
            return httpx.Response(404, text="Not Found")
        return httpx.Response(200, text="")

    client = GhidraClient(
        "https://example.test/api",
        transport=_build_transport(handle),
    )

    assert client.rename_function(0x401000, "new_name") is True
    assert client.rename_function(0x401000, "other_name") is True
    assert requested_paths == [
        "/api/rename_function_by_address",
        "/api/renameFunctionByAddress",
        "/api/renameFunctionByAddress",
    ]
