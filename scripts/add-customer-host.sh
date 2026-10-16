#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
usage() { echo 'Usage: add-customer-host.sh [--dry-run] <hostname>' >&2; exit 1; }
dry_run=false
if [[ ${1:-} == --dry-run ]]; then dry_run=true; shift; fi
[[ $# == 1 ]] || usage
host=${1,,}
label='[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
[[ ${#host} -le 253 && $host =~ ^($label\.)+[a-z]{2,63}$ ]] || { echo 'Invalid hostname.' >&2; exit 1; }
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# Reuse the canonical guardrails, including their subdomains, without duplicating names.
node --input-type=module - "$repo" "$host" <<'JS'
import { pathToFileURL } from 'node:url';
const { ENFORCE_DENYLIST } = await import(pathToFileURL(`${process.argv[2]}/verdict/src/config/hosts.js`));
const host = process.argv[3];
if (host.split('.')[0] === 'lease' || ENFORCE_DENYLIST.some(name => host === name || host.endsWith(`.${name}`))) {
  console.error('Refusing a protected hostname.');
  process.exit(1);
}
JS
caddyfile=${CADDYFILE:-/etc/caddy/Caddyfile}
# BIN is a directory containing caddy and systemctl; only override it for fixtures.
caddy=${BIN:+$BIN/}caddy
systemctl=${BIN:+$BIN/}systemctl
[[ -f $caddyfile && ! -L $caddyfile ]] || { echo 'Caddyfile must be a regular, non-symlink file.' >&2; exit 1; }
if ! $dry_run; then
  [[ $EUID == 0 ]] || { echo 'Run as root on the edge.' >&2; exit 1; }
  # Lock the file itself so a dry run creates no files.
  exec 9<"$caddyfile"
  flock -x 9
fi
# Conservative token match also catches URL-style site addresses and fdlog imports.
escaped=${host//./\\.}
if grep -Eiq "(^|[^a-z0-9_.-])${escaped}([^a-z0-9_.-]|$)" "$caddyfile"; then
  echo 'Hostname already present in Caddyfile.' >&2
  exit 1
fi
block=$(cat <<BLOCK
$host {
    import fdlog $host
    reverse_proxy 127.0.0.1:8787
}
BLOCK
)
if $dry_run; then printf '%s\n' "$block"; exit 0; fi
backup="${caddyfile}.bak-addhost-${host}-$(date -u +%Y%m%dT%H%M%S%N)"
cp -p -- "$caddyfile" "$backup"
printf 'Rollback: cp -p -- %q %q && %q validate --config %q --adapter caddyfile && %q reload caddy\n' "$backup" "$caddyfile" "$caddy" "$caddyfile" "$systemctl"
created_log=false
logfile=
restore() {
  cp -p -- "$backup" "$caddyfile"
  if $created_log; then rm -f -- "$logfile"; fi
}
trap 'restore' ERR
trap 'restore; exit 1' HUP INT TERM
printf '\n%s\n' "$block" >> "$caddyfile"
# Precreate the site log as the caddy user so a root validate cannot leave a root-owned
# 0600 log that breaks the reload. Root never chowns or chmods a caddy-writable path.
# CADDY_LOG_DIR is honoured only for non-root fixture runs.
if (( EUID == 0 )); then logdir=/var/log/caddy; as_log=(runuser -u caddy --); else logdir=${CADDY_LOG_DIR:-/var/log/caddy}; as_log=(); fi
logfile="$logdir/$host.log"
if [[ ! -d $logdir || -L $logdir ]]; then
  echo 'Log directory must be a real directory.' >&2
  false
fi
if [[ -e $logfile || -L $logfile ]]; then
  if [[ ! -f $logfile || -L $logfile || -s $logfile ]]; then
    echo 'Existing log file must be an empty regular file; rotate it first.' >&2
    false
  fi
else
  "${as_log[@]}" sh -c 'umask 037; set -C; : > "$1"' sh "$logfile"
  created_log=true
fi
"${as_log[@]}" chmod 640 -- "$logfile"
"$caddy" validate --config "$caddyfile" --adapter caddyfile
"$systemctl" reload caddy
trap - ERR HUP INT TERM
printf 'Added %s. Backup: %s\n' "$host" "$backup"
