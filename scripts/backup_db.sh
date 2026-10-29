#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-./data/backups}"
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%d_%H%M%S)"

if [[ -n "${SENTINEL_DATABASE_URL:-}" && "${SENTINEL_DATABASE_URL}" == postgresql* ]]; then
  echo "Using pg_dump for PostgreSQL backup"
  pg_dump "$SENTINEL_DATABASE_URL" > "$OUT_DIR/api_sentinel_${TS}.sql"
  echo "Backup created: $OUT_DIR/api_sentinel_${TS}.sql"
  exit 0
fi

DB_PATH="${2:-./api_sentinel.db}"
cp "$DB_PATH" "$OUT_DIR/api_sentinel_${TS}.db"
echo "Backup created: $OUT_DIR/api_sentinel_${TS}.db"
