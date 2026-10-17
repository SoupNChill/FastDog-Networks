#!/usr/bin/env bash
# update-disposable.sh — Manually refresh portal/src/data/disposable-domains.txt from a reviewed upstream copy.
# Usage: portal/bin/update-disposable.sh <path/to/disposable_email_blocklist.conf>
# The script never touches the network. Download the upstream file yourself from
# github.com/disposable-email-domains/disposable-email-domains (CC0 1.0), review it, then pass its path here.
# The result keeps this repository's header, lowercases, drops invalid lines, sorts and de-duplicates.
# Review `git diff --stat` before committing; the portal reads the file at startup only.

set -euo pipefail

if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
  echo "Usage: $0 <path/to/disposable_email_blocklist.conf>" >&2
  exit 1
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$SCRIPT_DIR/../src/data/disposable-domains.txt"
TMP="$(mktemp "$TARGET.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

grep '^#' "$TARGET" > "$TMP"
tr 'A-Z' 'a-z' < "$1" | sed 's/[[:space:]]//g' | grep -E '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$' | LC_ALL=C sort -u >> "$TMP"
count="$(grep -vc '^#' "$TMP" || true)"
if [ "$count" -lt 100 ]; then
  echo "Refusing to write: only $count domains parsed" >&2
  exit 1
fi
chmod 0644 "$TMP"
mv "$TMP" "$TARGET"
trap - EXIT
echo "disposable-domains.txt: $count domains"
