import pytest

from bridge.features import jt, mmio
from bridge.utils.errors import ErrorCode


class DummyAdapter:
    def in_code_range(self, ptr: int, code_min: int, code_max: int) -> bool:
        return code_min <= ptr < code_max

    def is_instruction_sentinel(self, raw: int) -> bool:
        return False

    def probe_function(self, client, ptr: int, code_min: int, code_max: int):
        # Simuliere validen Thumb-Treffer
        return "Thumb", ptr


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


def _has_note(payload: dict, phrase: str) -> bool:
    notes = payload.get("notes", [])
    return any(phrase in note for note in notes)


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

    # hat ein Wort gelesen
    assert client.read_addrs == [0x400004]

    if dry_run:
        assert payload["errors"] == []
        assert payload["verify"]["name"] == "func_401000"
        assert _has_note(payload, "dry-run")
        assert client.rename_calls == 0
        assert client.comment_calls == 0
        assert client.meta_calls == 1
    else:
        assert payload["errors"] == [ErrorCode.WRITE_DISABLED_DRY_RUN.value]
        assert payload["writes"] == {"renamed": False, "comment_set": False}
        assert _has_note(payload, "writes disabled")
        assert client.rename_calls == 0
        assert client.comment_calls == 0


class DummyMMIOClient:
    def __init__(self):
        self.calls = []

    def disassemble_function(self, address):
        self.calls.append(address)
        return ["00500000: NOP"]

    def set_disassembly_comment(self, address, comment):
        return True


def test_mmio_annotate_returns_note_when_writes_disabled_and_dry_run_false():
    payload = mmio.annotate(
        DummyMMIOClient(),
        function_addr=0x500000,
        dry_run=False,
        writes_enabled=False,
    )

    assert payload["annotated"] == 0
    assert payload["notes"]
    assert any("writes disabled" in note for note in payload["notes"])


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
    assert any("dry-run" in note for note in payload["notes"])
