# bridge/tests/plan/test_plan_check.py
import subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PLAN = ROOT / ".plan"

def test_plan_check_exits_zero():
    script = ROOT / "bin" / "plan_check.py"
    p = subprocess.run([sys.executable, str(script)], cwd=str(ROOT), capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr

def test_no_mojibake_and_arrow_present():
    todo = (PLAN / "TODO.md").read_text(encoding="utf-8")
    man  = (PLAN / "tasks.manifest.json").read_text(encoding="utf-8")
    blob = todo + "\n" + man
    assert "â†’" not in blob
    assert "READ→VERIFY" in man
