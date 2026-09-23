#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
"$ROOT/deploy/stop-edge.sh"
"$ROOT/deploy/start-edge.sh"
