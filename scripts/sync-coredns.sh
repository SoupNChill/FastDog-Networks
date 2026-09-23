#!/usr/bin/env bash
# sync-coredns.sh — Export control-plane zones to CoreDNS and reload
# Usage: ./scripts/sync-coredns.sh [zone...]
#        ./scripts/sync-coredns.sh              # exports all zones
#        ./scripts/sync-coredns.sh fastdognetworks.com

set -euo pipefail

COREDNS_ZONES_DIR="${COREDNS_ZONES_DIR:-/etc/coredns/zones}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

log() { echo "[sync-coredns] $*"; }
err() { echo "[sync-coredns] ERROR: $*" >&2; }

# Ensure we're in the repo root for npm commands
cd "$REPO_ROOT"

# Get zones to export
if [[ $# -gt 0 ]]; then
    ZONES=("$@")
else
    # List all zones from the zones/ directory
    ZONES=()
    for f in zones/*.json; do
        [[ -f "$f" ]] || continue
        zone="$(basename "$f" .json)"
        ZONES+=("$zone")
    done
fi

if [[ ${#ZONES[@]} -eq 0 ]]; then
    err "No zones found to export"
    exit 1
fi

# Ensure target directory exists
if [[ ! -d "$COREDNS_ZONES_DIR" ]]; then
    log "Creating $COREDNS_ZONES_DIR"
    mkdir -p "$COREDNS_ZONES_DIR"
fi

EXPORTED=0
FAILED=0

for zone in "${ZONES[@]}"; do
    zone_file="$COREDNS_ZONES_DIR/${zone}.zone"
    log "Exporting $zone -> $zone_file"
    
    if output=$(node src/dns/export-cli.js "$zone" 2>&1); then
        echo "$output" > "$zone_file"
        ((EXPORTED++)) || true
    else
        err "Failed to export $zone: $output"
        ((FAILED++)) || true
    fi
done

log "Exported $EXPORTED zone(s), $FAILED failed"

# Reload CoreDNS if running
if pgrep -x coredns >/dev/null 2>&1; then
    log "Sending SIGUSR1 to CoreDNS for zone reload"
    pkill -USR1 -x coredns || true
elif systemctl is-active --quiet fastdog-coredns 2>/dev/null; then
    log "Reloading fastdog-coredns service"
    systemctl reload fastdog-coredns || true
else
    log "CoreDNS not running — skipping reload"
fi

[[ $FAILED -eq 0 ]] || exit 1
