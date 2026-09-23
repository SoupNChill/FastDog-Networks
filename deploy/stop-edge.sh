#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [ -f .env ]; then
  # shellcheck disable=SC1091
  set -a; . ./.env; set +a
fi
port="${EDGE_PORT:-8787}"
PIDFILE="$ROOT/logs/edge.pid"
is_edge_pid() { ps -p "$1" -o args= 2>/dev/null | grep -q '[n]ode src/edge/server.js'; }
listener_pid() {
  ss -H -ltnp "sport = :$port" 2>/dev/null | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n 1
}
stop_pid() {
  local pid="$1"
  kill -TERM "$pid"
  for _ in {1..30}; do
    if ! kill -0 "$pid" 2>/dev/null; then break; fi
    sleep 1
  done
  if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid"; fi
  echo "stopped edge pid=$pid"
}
pid=""
if [ -f "$PIDFILE" ]; then
  candidate="$(cat "$PIDFILE")"
  if [[ "$candidate" =~ ^[0-9]+$ ]] && kill -0 "$candidate" 2>/dev/null && is_edge_pid "$candidate"; then
    pid="$candidate"
  else
    echo "removed stale pidfile"
  fi
  rm -f "$PIDFILE"
fi
if [ -z "$pid" ]; then
  candidate="$(listener_pid)"
  if [ -n "$candidate" ] && is_edge_pid "$candidate" && ! systemctl is-active --quiet fastdog-edge 2>/dev/null; then
    pid="$candidate"
  fi
fi
if [ -n "$pid" ]; then stop_pid "$pid"; else echo "no script-managed edge process found"; fi
if ss -H -ltn "sport = :$port" 2>/dev/null | grep -q .; then
  echo ":$port is still held; inspect the listener before restarting" >&2
  exit 1
fi
