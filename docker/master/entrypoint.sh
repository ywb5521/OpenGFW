#!/usr/bin/env bash
set -euo pipefail

DATABASE_URL="${OPENGFW_DATABASE_URL:-${DATABASE_URL:-}}"
LISTEN_ADDR="${OPENGFW_MASTER_LISTEN:-:9527}"
PROJECT_ROOT="${OPENGFW_PROJECT_ROOT:-/opt/opengfw}"
EVENT_RETENTION="${OPENGFW_EVENT_RETENTION:-}"
METRIC_RETENTION="${OPENGFW_METRIC_RETENTION:-}"
RETENTION_INTERVAL="${OPENGFW_RETENTION_INTERVAL:-}"

if [[ -z "$DATABASE_URL" ]]; then
  echo "OPENGFW_DATABASE_URL is required" >&2
  exit 1
fi

ARGS=(
  -listen "$LISTEN_ADDR"
  -database-url "$DATABASE_URL"
  -project-root "$PROJECT_ROOT"
)

if [[ -n "$EVENT_RETENTION" ]]; then
  ARGS+=(-event-retention "$EVENT_RETENTION")
fi
if [[ -n "$METRIC_RETENTION" ]]; then
  ARGS+=(-metric-retention "$METRIC_RETENTION")
fi
if [[ -n "$RETENTION_INTERVAL" ]]; then
  ARGS+=(-retention-interval "$RETENTION_INTERVAL")
fi

exec /usr/local/bin/opengfw-master "${ARGS[@]}" "$@"
