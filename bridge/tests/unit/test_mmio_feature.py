import pytest

from bridge.features import mmio


class DummyClient:
    def __init__(self, disassembly, *, comment_success=True):
        self._disassembly = list(disassembly)
        self.comment_success = comment_success
        self.requested = []
        self.comments = []

    def disassemble_function(self, address):
        self.requested.append(address)
        return list(self._disassembly)

    def set_disassembly_comment(self, address, comment):
        self.comments.append((address, comment))
        return self.comment_success


def test_mmio_annotate_collects_counts_and_samples():
    disassembly = [
        "00400000: LDR R0, [R1, #0x4000]",
        "00400004: STR R0, [R1, #0x5000]",
        "00400008: ORR R0, R0, #0x1",
        "0040000C: AND R0, R0, #0xfffffffe",
        "00400010: EOR R0, R0, #0x1",
        "00400014: NOP",
    ]
    client = DummyClient(disassembly)

    payload = mmio.annotate(client, function_addr=0x400000)

    assert payload["function"] == "0x00400000"
    assert payload["reads"] == 1
    assert payload["writes"] == 1
    assert payload["bitwise_or"] == 1
    assert payload["bitwise_and"] == 1
    assert payload["toggles"] == 1
    assert payload["annotated"] == 0
    assert [sample["op"] for sample in payload["samples"]] == [
        "READ",
        "WRITE",
        "OR",
        "AND",
        "TOGGLE",
    ]
    assert client.requested == [0x400000]


@pytest.mark.parametrize("success", [True, False])
def test_mmio_annotate_sets_comments_when_writes_enabled(success):
    disassembly = [
        "00410000: LDR R1, [R2, #0x4100]",
        "00410004: STR R1, [R2, #0x4100]",
        "00410008: ORR R1, R1, #0x2",
    ]
    client = DummyClient(disassembly, comment_success=success)

    payload = mmio.annotate(
        client,
        function_addr=0x410000,
        dry_run=False,
        writes_enabled=True,
        max_samples=2,
    )

    assert payload["annotated"] == (2 if success else 0)
    assert len(client.comments) == 2
    assert client.comments[0][0] == 0x00410000
    assert "MMIO" in client.comments[0][1]
