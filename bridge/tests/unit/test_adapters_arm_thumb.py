from bridge.adapters.arm_thumb import ARMThumbAdapter


def test_in_code_range():
    adapter = ARMThumbAdapter()
    assert adapter.in_code_range(0x1000, 0x1000, 0x2000)
    assert not adapter.in_code_range(0x0FFF, 0x1000, 0x2000)


def test_probe_function_arm_and_thumb():
    adapter = ARMThumbAdapter()
    mode, target = adapter.probe_function(0x2000)
    assert mode == "ARM"
    assert target == 0x2000

    mode, target = adapter.probe_function(0x2001)
    assert mode == "Thumb"
    assert target == 0x2000


def test_instruction_sentinel():
    adapter = ARMThumbAdapter()
    assert adapter.is_instruction_sentinel(0xE12FFF1C)
    assert not adapter.is_instruction_sentinel(0x12345678)
