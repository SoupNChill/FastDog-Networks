#!/usr/bin/env bash
# sync-coredns.sh — Export control-plane zones to CoreDNS, validate, reload, optional PoP sync
# Usage: ./scripts/sync-coredns.sh [zone...]
# Env: COREDNS_ZONES_DIR, COREDNS_SYNC_DRY_RUN, COREDNS_SYNC_ENABLED, COREDNS_POP_TARGETS, COREDNS_SSH_*

set -euo pipefail

COREDNS_ZONES_DIR="${COREDNS_ZONES_DIR:-/etc/coredns/zones}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

log() { echo "[sync-coredns] $*"; }
err() { echo "[sync-coredns] ERROR: $*" >&2; }

cd "$REPO_ROOT"

if [[ $# -gt 0 ]]; then
    ZONES=("$@")
else
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

DRY=0
case "${COREDNS_SYNC_DRY_RUN:-}" in
  1|true|TRUE|yes|YES|on|ON) DRY=1 ;;
esac

if [[ $DRY -eq 0 && ! -d "$COREDNS_ZONES_DIR" ]]; then
    log "Creating $COREDNS_ZONES_DIR"
    mkdir -p "$COREDNS_ZONES_DIR"
fi

EXPORTED=0
FAILED=0

for zone in "${ZONES[@]}"; do
    zone_file="$COREDNS_ZONES_DIR/${zone}.zone"
    log "Exporting $zone"

    if ! output=$(node src/dns/export-cli.js "$zone" 2>&1); then
        err "Failed to export $zone: $output"
        ((FAILED++)) || true
        continue
    fi

    # Validate via Node helper (SOA/NS/ns1+ns2)
    if ! node --input-type=module -e "
      import { validateZone } from './src/dns/validate-zone.js';
      import { readZone } from './src/dns/store.js';
      const zone = process.argv[1];
      const data = readZone(zone);
      const text = process.argv[2];
      const a = validateZone(data, { zone });
      const b = validateZone(text, { zone });
      if (!a.ok || !b.ok) {
        console.error([...(a.errors||[]), ...(b.errors||[])].join(','));
        process.exit(1);
      }
    " "$zone" "$output"; then
        err "Validation failed for $zone"
        ((FAILED++)) || true
        continue
    fi

    if [[ $DRY -eq 1 ]]; then
        log "DRY-RUN: validated $zone (skip write/reload)"
        ((EXPORTED++)) || true
        continue
    fi

    log "Writing $zone_file"
    echo "$output" > "$zone_file"
    ((EXPORTED++)) || true

    # Prefer full Node sync path when enabled (handles PoPs + audit)
    if [[ "${COREDNS_SYNC_ENABLED:-}" =~ ^(1|true|TRUE|yes|YES|on|ON)$ ]]; then
        node --input-type=module -e "
          import { syncZone } from './src/dns/sync-coredns.js';
          const r = syncZone(process.argv[1], { action: 'sync-cli' });
          console.log(JSON.stringify(r));
          if (!r.ok && !r.skipped) process.exit(2);
        " "$zone" || { err "Node sync reported failure for $zone"; ((FAILED++)) || true; }
    fi
done

log "Exported $EXPORTED zone(s), $FAILED failed"

if [[ $DRY -eq 1 ]]; then
    log "DRY-RUN complete — no CoreDNS reload"
    [[ $FAILED -eq 0 ]] || exit 1
    exit 0
fi

# Reload CoreDNS if running (local)
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