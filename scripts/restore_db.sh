#!/usr/bin/env bash
set -euo pipefail

BACKUP_FILE="${1:-}"
if [[ -z "$BACKUP_FILE" ]]; then
  echo "Usage: $0 <backup-file>"
  exit 1
fi

if [[ -n "${SENTINEL_DATABASE_URL:-}" && "${SENTINEL_DATABASE_URL}" == postgresql* ]]; then
  echo "Restoring PostgreSQL backup"
  psql "$SENTINEL_DATABASE_URL" < "$BACKUP_FILE"
  echo "Restore complete"
  exit 0
fi

TARGET_DB="${2:-./api_sentinel.db}"
cp "$BACKUP_FILE" "$TARGET_DB"
echo "Restore complete: $TARGET_DB"
