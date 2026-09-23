#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [ "${1:-}" = restart ]; then
  "$ROOT/deploy/stop-edge.sh"
elif [ "$#" -ne 0 ]; then
  echo "usage: $0 [restart]" >&2
  exit 2
fi
umask 077
mkdir -p data logs
chmod 700 data
if [ -f .env ]; then
  chmod 600 .env
  # shellcheck disable=SC1091
  set -a; . ./.env; set +a
fi
port="${EDGE_PORT:-8787}"
pidfile="$ROOT/logs/edge.pid"
port_up() { ss -H -ltn "sport = :$port" 2>/dev/null | grep -q .; }
is_edge_pid() { ps -p "$1" -o args= 2>/dev/null | grep -q '[n]ode src/edge/server.js'; }
if [ -f "$pidfile" ]; then
  pid="$(cat "$pidfile")"
  if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null && is_edge_pid "$pid"; then
    if port_up; then
      echo "edge already running pid=$pid on :$port"
      exit 0
    fi
    echo "pidfile process $pid is alive but :$port is down; inspect before starting another edge" >&2
    exit 1
  fi
  rm -f "$pidfile"
fi
if port_up; then
  echo ":$port is already in use; refusing to start a second edge" >&2
  exit 1
fi
nohup /usr/bin/node src/edge/server.js >> "$ROOT/logs/edge.log" 2>&1 < /dev/null &
pid=$!
echo "$pid" > "$pidfile"
disown "$pid" 2>/dev/null || true
for _ in {1..30}; do
  if ! kill -0 "$pid" 2>/dev/null; then
    rm -f "$pidfile"
    echo "edge exited during startup; see logs/edge.log" >&2
    exit 1
  fi
  if curl -fsS "http://127.0.0.1:$port/health" > /dev/null 2>&1; then
    echo "started edge pid=$pid port=$port log=$ROOT/logs/edge.log"
    exit 0
  fi
  sleep 1
done
echo "edge did not become healthy; see logs/edge.log" >&2
exit 1
