from bridge.features.strings import xrefs_compact


class DummyClient:
    def __init__(self, xrefs, disassembly_map):
        self._xrefs = xrefs
        self._disassembly_map = disassembly_map
        self.disasm_calls = []
        self.last_limit = None

    def get_xrefs_to(self, address, *, limit=50):
        self.last_limit = limit
        return list(self._xrefs)

    def disassemble_function(self, address):
        self.disasm_calls.append(address)
        return list(self._disassembly_map.get(address, []))


def test_xrefs_compact_enriches_context_and_hint():
    client = DummyClient(
        xrefs=[{"addr": 0x401000, "context": "From 0x401000 [DATA]"}],
        disassembly_map={
            0x401000: [
                "00401000: MOV R0, #0x00001000",
                "00401004: BL printf",
            ]
        },
    )

    payload = xrefs_compact(client, string_addr=0x1000, limit=5)

    assert payload["string"] == "0x00001000"
    assert payload["count"] == 1
    assert payload["callers"][0]["context"] == (
        "00401000: MOV R0, #0x00001000 | 00401004: BL printf"
    )
    assert payload["callers"][0]["arg_index"] == 0
    assert payload["callers"][0]["hint"].lower() == "printf"


def test_xrefs_compact_respects_limit_and_trims():
    xrefs = [
        {"addr": 0x500000, "context": "  First hit   "},
        {"addr": 0x500010, "context": "Second hit"},
        {"addr": 0x500020, "context": "Third hit"},
    ]
    disassembly_map = {
        0x500000: [
            "00500000: ADRP X0, 0x00002000",
            "00500004: BL puts",
        ],
        0x500010: [
            "00500010: MOV R1, #0x00002000",
            "00500014: BL log_message",
        ],
        0x500020: [
            "00500020: MOV R2, #0x00002000",
            "00500024: BL something",
        ],
    }
    client = DummyClient(xrefs, disassembly_map)

    payload = xrefs_compact(client, string_addr=0x2000, limit=2)

    assert payload["count"] == len(xrefs)
    assert len(payload["callers"]) == 2
    # Ensure limit was forwarded and only first two addresses were processed
    assert client.last_limit == 2
    assert client.disasm_calls == [0x500000, 0x500010]
    contexts = [caller["context"] for caller in payload["callers"]]
    assert contexts[0] == "00500000: ADRP X0, 0x00002000 | 00500004: BL puts"
    # Check normalization removed double spaces from fallback
    assert contexts[0].startswith("00500000")


def test_xrefs_compact_falls_back_to_original_context_when_disassembly_missing():
    client = DummyClient(
        xrefs=[{"addr": 0x600000, "context": "  Raw context snippet  "}],
        disassembly_map={0x600000: []},
    )

    payload = xrefs_compact(client, string_addr=0x3000, limit=3)

    assert payload["callers"][0]["context"] == "Raw context snippet"
    assert "arg_index" not in payload["callers"][0]
    assert "hint" not in payload["callers"][0]
