import pytest

from bridge.features import jt, mmio
from bridge.utils.errors import ErrorCode


class DummyAdapter:
    def in_code_range(self, ptr: int, code_min: int, code_max: int) -> bool:
        return code_min <= ptr <= code_max

    def is_instruction_sentinel(self, raw: int) -> bool:
        return False

    def probe_function(self, ptr: int):
        return "thumb", ptr


class DummyJTClient:
    def __init__(self, target=0x401000):
        self._target = target
        self.read_addrs = []
        self.rename_calls = 0
        self.comment_calls = 0
        self.meta_calls = 0
        self._meta = {
            target: {
                "name": "func_401000",
                "comment": "",
            }
        }

    def read_dword(self, addr):
        self.read_addrs.append(addr)
        return self._target

    def get_function_by_address(self, addr):
        self.meta_calls += 1
        return self._meta.get(addr)

    def rename_function(self, addr, new_name):
        self.rename_calls += 1
        return True

    def set_decompiler_comment(self, addr, comment):
        self.comment_calls += 1
        return True


@pytest.mark.parametrize("dry_run", [True, False])
def test_jt_slot_process_gates_writes_when_disabled(dry_run):
    client = DummyJTClient()
    adapter = DummyAdapter()

    payload = jt.slot_process(
        client,
        jt_base=0x400000,
        slot_index=1,
        code_min=0x400000,
        code_max=0x500000,
        rename_pattern="slot_{slot}",
        comment="annotate",
        adapter=adapter,
        dry_run=dry_run,
        writes_enabled=False,
    )

    assert client.read_addrs == [0x400004]

    if dry_run:
        assert payload["errors"] == []
        assert payload["verify"]["name"] == "func_401000"
        assert client.rename_calls == 0
        assert client.comment_calls == 0
        assert client.meta_calls == 1
    else:
        assert payload["errors"] == [ErrorCode.WRITE_DISABLED_DRY_RUN.value]
        assert payload["writes"] == {"renamed": False, "comment_set": False}
        assert client.rename_calls == 0
        assert client.comment_calls == 0


def test_mmio_annotate_raises_when_writes_disabled_and_dry_run_false():
    with pytest.raises(mmio.WritesDisabledError):
        mmio.annotate(
            object(),
            function_addr=0x500000,
            dry_run=False,
            writes_enabled=False,
        )


class DummyMMIOClient:
    def __init__(self):
        self.calls = []

    def disassemble_function(self, address):
        self.calls.append(address)
        return ["00500000: NOP"]

    def set_disassembly_comment(self, address, comment):  # pragma: no cover - not used here
        return True


def test_mmio_annotate_allows_dry_run_with_writes_disabled():
    client = DummyMMIOClient()

    payload = mmio.annotate(
        client,
        function_addr=0x500000,
        dry_run=True,
        writes_enabled=False,
    )

    assert payload["function"] == "0x00500000"
    assert payload["annotated"] == 0
    assert payload["samples"] == []
    assert client.calls == [0x500000]
