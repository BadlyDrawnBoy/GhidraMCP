import json

from bridge.features.strings import strings_compact_view


def test_strings_compact_view_truncates_and_orders() -> None:
    raw_entries = [
        {
            "literal": "Beta entry",
            "address": 0x00200020,
            "refs": 7,
        },
        {
            "literal": "Alpha entry with newline\n" + "A" * 200,
            "address": "0x00200000",
            "refs": 5,
        },
        {
            "string": "Gamma entry",
            "addr": 0x00200010,
            "refs": [1, 2, 3],
        },
    ]

    payload = strings_compact_view(raw_entries)

    assert payload["total"] == len(payload["items"])
    addresses = [item["addr"] for item in payload["items"]]
    assert addresses == sorted(addresses)

    truncated_literal = payload["items"][0]["s"]
    assert len(truncated_literal) <= 120
    assert truncated_literal.endswith("…")

    for item in payload["items"]:
        assert set(item.keys()) == {"s", "addr", "refs"}
    refs_by_addr = {item["addr"]: item["refs"] for item in payload["items"]}
    assert refs_by_addr["0x00200010"] == 3

    response = {"ok": True, "data": payload, "errors": []}
    assert len(json.dumps(response)) <= 8192
