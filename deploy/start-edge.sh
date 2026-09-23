#!/usr/bin/env bash
# Start Fastdog Edge persistently for LAN dogfood (no sudo required).
# Prefer systemd unit in deploy/fastdog-edge.service when sudo/linger is available.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p data logs
chmod 700 data 2>/dev/null || true
if ss -ltn 2>/dev/null | grep -q ':8787 '; then
  echo "edge already listening on :8787"
  curl -sS http://127.0.0.1:8787/health || true
  exit 0
fi
# shellcheck disable=SC1091
[ -f .env ] && set -a && . ./.env && set +a
nohup /usr/bin/node src/edge/server.js >> logs/edge.log 2>&1 &
echo $! > logs/edge.pid
sleep 1
curl -sS http://127.0.0.1:8787/health
echo
echo "started pid=$(cat logs/edge.pid) log=$ROOT/logs/edge.log"