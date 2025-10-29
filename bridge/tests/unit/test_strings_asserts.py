from bridge.features.strings import xrefs_compact


class RecordingClient:
    def __init__(self, xrefs, disassembly_map):
        self._xrefs = list(xrefs)
        self._disassembly_map = dict(disassembly_map)
        self.last_limit = None
        self.disasm_calls = []

    def get_xrefs_to(self, address, *, limit=50):
        self.last_limit = limit
        return list(self._xrefs)

    def disassemble_function(self, address):
        self.disasm_calls.append(address)
        return list(self._disassembly_map.get(address, []))


def test_xrefs_compact_records_limit_and_disassembly_calls():
    xrefs = [
        {"addr": 0x401000, "context": "call site"},
        {"addr": 0x401010, "context": "another"},
    ]
    disassembly_map = {
        0x401000: [
            "00401000: MOV R0, #0x00001000",
            "00401004: BL puts",
        ],
        0x401010: [
            "00401010: MOV R1, #0x00001000",
            "00401014: BL printf",
        ],
    }
    client = RecordingClient(xrefs, disassembly_map)

    payload = xrefs_compact(client, string_addr=0x1000)

    assert payload["count"] == len(xrefs)
    assert client.last_limit == 50
    assert client.disasm_calls == [0x401000, 0x401010]


def test_xrefs_compact_limits_processed_callers():
    xrefs = [
        {"addr": 0x500000, "context": "first"},
        {"addr": 0x500010, "context": "second"},
        {"addr": 0x500020, "context": "third"},
    ]
    disassembly_map = {
        0x500000: ["00500000: MOV R0, #0x0", "00500004: BL puts"],
        0x500010: ["00500010: MOV R1, #0x0", "00500014: BL puts"],
        0x500020: ["00500020: MOV R2, #0x0", "00500024: BL puts"],
    }
    client = RecordingClient(xrefs, disassembly_map)

    payload = xrefs_compact(client, string_addr=0x2000, limit=2)

    assert payload["count"] == len(xrefs)
    assert len(payload["callers"]) == 2
    assert client.last_limit == 2
    assert client.disasm_calls == [0x500000, 0x500010]
