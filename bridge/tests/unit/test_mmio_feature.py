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


def test_mmio_annotate_skips_block_transfer_instructions():
    disassembly = [
        "00420000: LDM R0!, {R1, R2, R3}",
        "00420004: STM R3!, {R4, R5}",
        "00420008: LDR R0, [R1, #0x4200]",
    ]
    client = DummyClient(disassembly)

    payload = mmio.annotate(client, function_addr=0x420000)

    assert payload["reads"] == 1
    assert payload["writes"] == 0
    assert [sample["addr"] for sample in payload["samples"]] == ["0x00420008"]


def test_mmio_annotate_ignores_byte_and_halfword_variants():
    disassembly = [
        "00425000: LDRB R0, [R1, #0x1]",
        "00425004: STRH R0, [R1, #0x2]",
        "00425008: LDRNE R0, [R1, #0x4]",
        "0042500C: STRCS R0, [R1, #0x8]",
    ]
    client = DummyClient(disassembly)

    payload = mmio.annotate(client, function_addr=0x425000)

    assert payload["reads"] == 1
    assert payload["writes"] == 1
    assert [sample["addr"] for sample in payload["samples"]] == [
        "0x00425008",
        "0x0042500c",
    ]


def test_mmio_annotate_extracts_literal_and_offset_targets():
    disassembly = [
        "00430000: LDR R0, =0x50000000",
        "00430004: STR R0, [R1, #0x100]",
        "00430008: LDR R2, [R3, R4]",
        "0043000C: ORR R2, R2, #0x8",
    ]
    client = DummyClient(disassembly)

    payload = mmio.annotate(client, function_addr=0x430000)

    samples = {sample["addr"]: sample for sample in payload["samples"]}
    assert samples["0x00430000"]["target"] == "0x50000000"
    assert samples["0x00430004"]["target"] == "0x00000100"
    assert "0x00430008" not in samples
    assert samples["0x0043000c"]["target"] == "0x00000008"
