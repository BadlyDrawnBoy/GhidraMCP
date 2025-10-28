from bridge.features import mmio


class DummyClient:
    def __init__(self, disassembly):
        self._disassembly = list(disassembly)
        self.requested = []

    def disassemble_function(self, address):
        self.requested.append(address)
        return list(self._disassembly)

    def set_disassembly_comment(self, address, comment):
        raise AssertionError("comments should not be attempted in heuristics tests")


def test_skips_register_indirect_loads_and_stores():
    disassembly = [
        "00450000: LDR R0, [R1]",
        "00450004: STR R0, [R2]",
        "00450008: LDR R2, [R3, R4]",
        "0045000C: STR R5, [R6, R7]",
        "00450010: LDR R1, [R2, #0x10]",
    ]
    client = DummyClient(disassembly)

    payload = mmio.annotate(client, function_addr=0x450000)

    assert payload["reads"] == 1
    assert payload["writes"] == 0
    assert [sample["addr"] for sample in payload["samples"]] == ["0x00450010"]
    assert client.requested == [0x450000]


def test_literal_pool_loads_are_counted():
    disassembly = [
        "00460000: LDR R0, =0x60000000",
        "00460004: STR R0, [R1, #0x20]",
    ]
    client = DummyClient(disassembly)

    payload = mmio.annotate(client, function_addr=0x460000)

    samples = {sample["addr"]: sample for sample in payload["samples"]}
    assert payload["reads"] == 1
    assert payload["writes"] == 1
    assert samples["0x00460000"]["target"] == "0x60000000"
    assert samples["0x00460004"]["target"] == "0x00000020"
    assert client.requested == [0x460000]
