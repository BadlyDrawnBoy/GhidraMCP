#!/usr/bin/env bash
set -euo pipefail
mf=".plan/tasks.manifest.json"
tmp="$mf.tmp"

add() {
  local id="$1" title="$2" after_csv="$3"
  # baue after-Array aus CSV
  local after="["; IFS=, read -r -a arr <<< "$after_csv"; for i in "${arr[@]}"; do
    [ -n "$i" ] && after="$after\"$i\","
  done; after="${after%,}]"
  # jq: wenn id noch nicht vorhanden → anhängen
  jq --arg id "$id" --arg title "$title" --argjson after "$after" '
    if any(.sequence[]; .id==$id) then .
    else .sequence += [ { "id": $id, "title": $title, "after": $after } ]
    end
  ' "$mf" > "$tmp" && mv "$tmp" "$mf"
}

add WRITE-GUARDS          "Write guards on endpoints"        "SCHEMA-STRICT"
add SSE-HANDSHAKE         "SSE handshake test"                "API-MOUNT"
add JT-SCAN-CONSISTENCY   "JT summary invariants"             "JT-SCAN"
add STRINGS-ASSERTS       "Strings feature asserts"           "CLIENT-UNIFY"
add SNAPSHOT-SAFEGUARD    "Non-golden safeguards"             "SCHEMA-STRICT"
add PLAN-CHECK            "Plan consistency script + CI"      "SCHEMA-STRICT"

jq . "$mf" >/dev/null   # JSON quick-validate
echo "Updated: $mf"
