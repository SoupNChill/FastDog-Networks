#!/usr/bin/env bash
# Read-only mail DNS check. Usage: check-mail-dns.sh <domain> [server ...] [--selector x] [--expect include:x ...]
set -u -o pipefail
exec node "$(dirname "$0")/mail-dns-check.js" "$@"
