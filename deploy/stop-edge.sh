#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PIDFILE="$ROOT/logs/edge.pid"
if [ -f "$PIDFILE" ]; then
  pid=$(cat "$PIDFILE")
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    echo "stopped edge pid=$pid"
  else
    echo "stale pidfile $pid"
  fi
  rm -f "$PIDFILE"
else
  pkill -f 'node src/edge/server.js' 2>/dev/null && echo "stopped via pkill" || echo "edge not running"
fi