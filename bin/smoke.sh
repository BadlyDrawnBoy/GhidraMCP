#!/usr/bin/env bash
set -euo pipefail
base="${BASE_URL:-http://127.0.0.1:8081}"
echo "Smoke @ $base"

echo "- GET /openapi.json ..."
curl -fsS "$base/openapi.json" | jq -re '.openapi' >/dev/null

echo "- GET /api/health.json (optional)…"
if curl -fsS "$base/api/health.json" | jq -e '.ok == true' >/dev/null 2>&1; then
  echo "health ok"
else
  echo "health endpoint not found or not ok (ignored)"
fi

echo "SMOKE OK"
