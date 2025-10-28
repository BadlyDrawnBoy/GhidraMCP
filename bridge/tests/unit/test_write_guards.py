import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from bridge.api import routes
from bridge.api.routes import make_routes
from bridge.features import jt, mmio


class RecordingJTClient:
    def __init__(self, target: int = 0x00402000) -> None:
        self._target = target
        self.read_calls: list[int] = []
        self.rename_calls: list[tuple[int, str]] = []
        self.comment_calls: list[tuple[int, str]] = []
        self.meta_calls: list[int] = []
        self._functions: dict[int, dict[str, str]] = {
            target: {"name": "orig_target", "comment": "old"}
        }

    def read_dword(self, address: int) -> int:
        self.read_calls.append(address)
        return self._target

    def get_function_by_address(self, address: int) -> dict[str, str] | None:
        self.meta_calls.append(address)
        meta = self._functions.get(address)
        return dict(meta) if meta is not None else None

    def rename_function(self, address: int, new_name: str) -> bool:
        self.rename_calls.append((address, new_name))
        if address not in self._functions:
            return False
        self._functions[address]["name"] = new_name
        return True

    def set_decompiler_comment(self, address: int, comment: str) -> bool:
        self.comment_calls.append((address, comment))
        if address not in self._functions:
            return False
        self._functions[address]["comment"] = comment
        return True

    def close(self) -> None:  # pragma: no cover - required by interface
        return None


class RecordingJTFactory:
    def __init__(self, target: int = 0x00402000) -> None:
        self._target = target
        self._clients: list[RecordingJTClient] = []

    def __call__(self) -> RecordingJTClient:
        client = RecordingJTClient(target=self._target)
        self._clients.append(client)
        return client

    @property
    def last(self) -> RecordingJTClient:
        assert self._clients, "factory did not produce a client"
        return self._clients[-1]


class StaticAdapter:
    def __init__(self, mode: str = "ARM") -> None:
        self._mode = mode

    def in_code_range(self, ptr: int, code_min: int, code_max: int) -> bool:
        return code_min <= ptr < code_max

    def is_instruction_sentinel(self, raw: int) -> bool:
        return False

    def probe_function(self, _client, ptr: int, _code_min: int, _code_max: int):
        return self._mode, ptr


class RecordingMMIOClient:
    def __init__(self) -> None:
        self.comments: list[tuple[int, str]] = []
        self.calls: list[int] = []
        self._disassembly = [
            "00450000: LDR R0, [R1, #0x0]",
            "00450004: STR R0, [R1, #0x4]",
            "00450008: ORR R0, R0, #0x1",
        ]

    def disassemble_function(self, address: int) -> list[str]:
        self.calls.append(address)
        return list(self._disassembly)

    def set_disassembly_comment(self, address: int, comment: str) -> bool:
        self.comments.append((address, comment))
        return True

    def close(self) -> None:  # pragma: no cover - required by interface
        return None


class RecordingMMIOFactory:
    def __init__(self) -> None:
        self._clients: list[RecordingMMIOClient] = []

    def __call__(self) -> RecordingMMIOClient:
        client = RecordingMMIOClient()
        self._clients.append(client)
        return client

    @property
    def last(self) -> RecordingMMIOClient:
        assert self._clients, "factory did not produce a client"
        return self._clients[-1]


@pytest.fixture()
def _patch_adapter(monkeypatch) -> None:
    adapter = StaticAdapter()
    monkeypatch.setattr(routes, "adapter_for_arch", lambda _arch: adapter)


def _post(client: TestClient, path: str, payload: dict[str, object]) -> dict[str, object]:
    response = client.post(path, json=payload)
    assert response.status_code == 200
    return response.json()


def test_jt_slot_process_dry_run_returns_note(_patch_adapter, monkeypatch) -> None:
    attempts: list[None] = []
    monkeypatch.setattr(jt, "record_write_attempt", lambda: attempts.append(None))
    factory = RecordingJTFactory()
    app = Starlette(routes=make_routes(factory, enable_writes=True))
    with TestClient(app) as http:
        body = _post(
            http,
            "/api/jt_slot_process.json",
            {
                "jt_base": "0x00400000",
                "slot_index": 0,
                "code_min": "0x00400000",
                "code_max": "0x00410000",
                "rename_pattern": "slot_{slot}",
                "comment": "note",
                "dry_run": True,
                "arch": "arm",
            },
        )
    data = body["data"]
    client = factory.last

    assert body["ok"] is True
    assert any("dry-run" in note for note in data["notes"])
    assert client.rename_calls == []
    assert client.comment_calls == []
    assert attempts == []


def test_jt_slot_process_writes_disabled_reports_note(
    _patch_adapter, monkeypatch
) -> None:
    attempts: list[None] = []
    monkeypatch.setattr(jt, "record_write_attempt", lambda: attempts.append(None))
    factory = RecordingJTFactory()
    app = Starlette(routes=make_routes(factory, enable_writes=False))
    with TestClient(app) as http:
        body = _post(
            http,
            "/api/jt_slot_process.json",
            {
                "jt_base": "0x00400000",
                "slot_index": 0,
                "code_min": "0x00400000",
                "code_max": "0x00410000",
                "rename_pattern": "slot_{slot}",
                "comment": "note",
                "dry_run": False,
                "arch": "arm",
            },
        )
    data = body["data"]
    client = factory.last

    assert body["ok"] is True
    assert data["errors"] == ["WRITE_DISABLED_DRY_RUN"]
    assert any("writes disabled" in note for note in data["notes"])
    assert client.rename_calls == []
    assert client.comment_calls == []
    assert attempts == []


def test_jt_slot_process_writes_enabled_records_audit(_patch_adapter, monkeypatch) -> None:
    factory = RecordingJTFactory()
    calls: list[dict[str, object]] = []
    attempts: list[None] = []
    monkeypatch.setattr(jt, "record_jt_write", lambda **kwargs: calls.append(kwargs))
    monkeypatch.setattr(jt, "record_write_attempt", lambda: attempts.append(None))

    app = Starlette(routes=make_routes(factory, enable_writes=True))
    with TestClient(app) as http:
        body = _post(
            http,
            "/api/jt_slot_process.json",
            {
                "jt_base": "0x00400000",
                "slot_index": 1,
                "code_min": "0x00400000",
                "code_max": "0x00410000",
                "rename_pattern": "slot_{slot}",
                "comment": "note",
                "dry_run": False,
                "arch": "arm",
            },
        )
    data = body["data"]
    client = factory.last

    assert body["ok"] is True
    assert data["notes"] == []
    assert data["writes"] == {"renamed": True, "comment_set": True}
    assert client.rename_calls
    assert client.comment_calls
    assert len(calls) == 1
    assert calls[0]["slot"] == 1
    assert attempts == [None, None]


def test_mmio_dry_run_reports_note(monkeypatch) -> None:
    attempts: list[None] = []
    monkeypatch.setattr(mmio, "record_write_attempt", lambda amount=1: attempts.append(None))
    factory = RecordingMMIOFactory()
    app = Starlette(routes=make_routes(factory, enable_writes=True))
    with TestClient(app) as http:
        body = _post(
            http,
            "/api/mmio_annotate.json",
            {"function_addr": "0x00450000", "dry_run": True, "max_samples": 2},
        )
    data = body["data"]
    client = factory.last

    assert any("dry-run" in note for note in data["notes"])
    assert client.comments == []
    assert attempts == []


def test_mmio_writes_disabled_reports_note(monkeypatch) -> None:
    attempts: list[None] = []
    monkeypatch.setattr(mmio, "record_write_attempt", lambda amount=1: attempts.append(None))
    factory = RecordingMMIOFactory()
    app = Starlette(routes=make_routes(factory, enable_writes=False))
    with TestClient(app) as http:
        body = _post(
            http,
            "/api/mmio_annotate.json",
            {"function_addr": "0x00450000", "dry_run": False, "max_samples": 2},
        )
    data = body["data"]
    client = factory.last

    assert any("writes disabled" in note for note in data["notes"])
    assert data["annotated"] == 0
    assert client.comments == []
    assert attempts == []


def test_mmio_writes_enabled_records_comments(monkeypatch) -> None:
    factory = RecordingMMIOFactory()
    recorded: list[int] = []
    monkeypatch.setattr(mmio, "record_write_attempt", lambda amount=1: recorded.append(amount))

    app = Starlette(routes=make_routes(factory, enable_writes=True))
    with TestClient(app) as http:
        body = _post(
            http,
            "/api/mmio_annotate.json",
            {"function_addr": "0x00450000", "dry_run": False, "max_samples": 2},
        )
    data = body["data"]
    client = factory.last

    assert data["annotated"] == 2
    assert data["notes"] == []
    assert client.comments
    assert recorded == [1, 1]
