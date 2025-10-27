from bridge.adapters.arm_thumb import ARMThumbAdapter


class StubClient:
    def __init__(self, mapping=None):
        self.mapping = mapping or {}

    def disassemble_function(self, address):
        return self.mapping.get(address, {}).get("disasm", [])

    def get_function_by_address(self, address):
        meta = self.mapping.get(address, {}).get("meta")
        return dict(meta) if meta else None


def test_in_code_range():
    adapter = ARMThumbAdapter()
    assert adapter.in_code_range(0x1000, 0x1000, 0x2000)
    assert not adapter.in_code_range(0x2000, 0x1000, 0x2000)
    assert not adapter.in_code_range(0x0FFF, 0x1000, 0x2000)


def test_probe_function_arm_and_thumb():
    adapter = ARMThumbAdapter()
    client = StubClient(
        {
            0x2000: {
                "disasm": ["00200000: PUSH {r4, lr}"],
                "meta": {"entry_point": 0x2000},
            }
        }
    )
    mode, target = adapter.probe_function(client, 0x2000)
    assert mode == "ARM"
    assert target == 0x2000

    mode, target = adapter.probe_function(client, 0x2001)
    assert mode == "Thumb"
    assert target == 0x2000


def test_probe_function_requires_disasm_and_metadata():
    adapter = ARMThumbAdapter()
    client = StubClient(
        {
            0x3000: {
                "disasm": [],
                "meta": {"entry_point": 0x3000},
            },
            0x3004: {
                "disasm": ["00300400: PUSH {r4, lr}"],
                "meta": None,
            },
        }
    )

    mode, target = adapter.probe_function(client, 0x3000)
    assert mode is None
    assert target is None

    mode, target = adapter.probe_function(client, 0x3005)
    assert mode is None
    assert target is None


def test_instruction_sentinel():
    adapter = ARMThumbAdapter()
    assert adapter.is_instruction_sentinel(0xE12FFF1C)
    assert not adapter.is_instruction_sentinel(0x12345678)
