#!/usr/bin/env python3
import re, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
todo_p = ROOT/".plan"/"TODO.md"
man_p  = ROOT/".plan"/"tasks.manifest.json"
st_p   = ROOT/".plan"/"state.json"

def die(msg): print(f"PLAN CHECK ✖ {msg}", file=sys.stderr); sys.exit(1)
def ok(msg):  print(f"PLAN CHECK ✓ {msg}")

# --- read files
try:
    todo = todo_p.read_text(encoding="utf-8")
    man  = json.loads(man_p.read_text(encoding="utf-8"))
    st   = json.loads(st_p.read_text(encoding="utf-8"))
except Exception as e:
    die(f"failed to read plan files: {e}")

# --- UTF-8 sanity (simple mojibake marker)
if "â†’" in todo or "â†’" in man_p.read_text(encoding="utf-8", errors="ignore"):
    die("UTF-8 mojibake detected (e.g., 'â†’'). Fix arrows like 'READ→VERIFY'.")

# --- IDs from TODO headings like: '### 7) ✅ SCHEMA-STRICT — ... (ID: SCHEMA-STRICT)'
todo_items = []
pat = re.compile(r"^###\s*\d+\)\s*([✅⬜⛔])\s.*?\(ID:\s*([A-Z0-9\-]+)\)", re.M)
for m in pat.finditer(todo):
    status_emoji, tid = m.group(1), m.group(2)
    todo_items.append((tid, status_emoji))
todo_ids = {tid for tid,_ in todo_items}
if not todo_ids:
    die("no tasks parsed from TODO.md headings (check format '### n) ✅ NAME (ID: XXX)')")

man_ids = {e["id"] for e in man.get("sequence", [])}
state_ids = set(st.get("tasks", {}).keys())

# --- ID set checks
missing_in_state  = todo_ids - state_ids
missing_in_man    = todo_ids - man_ids
extra_in_state    = state_ids - todo_ids  # tolerated, but warn

if missing_in_state:
    die(f"IDs in TODO missing in state.json: {sorted(missing_in_state)}")
if missing_in_man:
    die(f"IDs in TODO missing in tasks.manifest.json: {sorted(missing_in_man)}")

if extra_in_state:
    ok(f"note: extra IDs in state.json (not in TODO): {sorted(extra_in_state)}")

# --- status mapping
map_ = {"✅": "done", "⬜": ("todo","in-progress"), "⛔": "blocked"}
problems = []
for tid, emoji in todo_items:
    s = st["tasks"].get(tid, {})
    want = map_[emoji]
    got  = s.get("status")
    if isinstance(want, tuple):
        if got not in want:
            problems.append(f"{tid}: TODO={emoji} expects {want}, state.json has '{got}'")
    else:
        if got != want:
            problems.append(f"{tid}: TODO={emoji} expects '{want}', state.json has '{got}'")
        if emoji == "✅" and not s.get("commit"):
            problems.append(f"{tid}: marked ✅ but state.json.commit is missing")
if problems:
    die("status/commit mismatch:\n  - " + "\n  - ".join(problems))

ok("IDs aligned across TODO/manifest/state")
ok("Statuses & commits consistent")
sys.exit(0)
