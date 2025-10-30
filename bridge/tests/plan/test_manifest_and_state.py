import json, time, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PLAN = ROOT / ".plan"

def test_manifest_utf8_arrow_and_no_mojibake():
    s = (PLAN / "tasks.manifest.json").read_text(encoding="utf-8")
    assert "â†’" not in s
    assert "READ→VERIFY" in s

def test_state_contains_all_todo_ids():
    todo = (PLAN / "TODO.md").read_text(encoding="utf-8")
    ids_todo = set()
    for line in todo.splitlines():
        m = re.match(r"^###\s+\d+\)\s+[⬜✅⛔]\s+([A-Z0-9\-]+)\s+\(ID:\s*\1\)", line)
        if m:
            ids_todo.add(m.group(1))
    state = json.loads((PLAN / "state.json").read_text(encoding="utf-8"))
    assert ids_todo <= set(state["tasks"].keys())

def test_agent_metadata_files_exist_and_valid():
    pr = PLAN / "pr.json"
    lock = ROOT / ".ci" / "AGENT_LOCK"
    assert pr.exists(), "Missing .plan/pr.json"
    assert lock.exists(), "Missing .ci/AGENT_LOCK"
    prj = json.loads(pr.read_text(encoding="utf-8"))
    assert "last_report" in prj and "last_task" in prj
    lj = json.loads(lock.read_text(encoding="utf-8"))
    assert "branch" in lj and "expires_at" in lj
    assert float(lj["expires_at"]) > time.time()
