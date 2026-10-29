#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8000}"

echo "[1/5] Seeding demo data"
curl -sS -X POST "$BASE_URL/v1/demo/seed" | jq

echo "[2/5] Fetching endpoints"
ENDPOINTS_JSON="$(curl -sS "$BASE_URL/v1/endpoints")"
echo "$ENDPOINTS_JSON" | jq

TARGET_ID="$(echo "$ENDPOINTS_JSON" | jq '[.[] | select((.risk_score // 0) >= 85)] | sort_by(.risk_score) | reverse | .[0].id')"
if [[ "$TARGET_ID" == "null" || -z "$TARGET_ID" ]]; then
  echo "No high-risk endpoint found."
  exit 1
fi

echo "[3/5] Requesting quarantine for endpoint $TARGET_ID"
ACTION_JSON="$(curl -sS -X POST "$BASE_URL/v1/remediation/actions" \
  -H 'Content-Type: application/json' \
  -d "{\"endpoint_id\":$TARGET_ID,\"action_type\":\"quarantine\",\"reason\":\"demo containment\",\"requested_by\":\"demo-analyst\"}")"

echo "$ACTION_JSON" | jq
ACTION_ID="$(echo "$ACTION_JSON" | jq '.id')"

echo "[4/5] Approving and executing action $ACTION_ID"
curl -sS -X POST "$BASE_URL/v1/remediation/actions/$ACTION_ID/approve" \
  -H 'Content-Type: application/json' \
  -d '{"approved_by":"demo-manager"}' | jq

curl -sS -X POST "$BASE_URL/v1/remediation/actions/$ACTION_ID/execute" \
  -H 'Content-Type: application/json' \
  -d '{"executed_by":"demo-automation"}' | jq

echo "[5/5] Executive report after remediation"
curl -sS -X POST "$BASE_URL/v1/reports/executive" \
  -H 'Content-Type: application/json' \
  -d '{"generated_by":"demo-ciso"}' | jq

echo "Demo flow complete."
