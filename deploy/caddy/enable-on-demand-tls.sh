#!/usr/bin/env bash
# Enable (or roll back) Caddy on-demand TLS. Existing site blocks are never edited: the global
# block is prepended (or merged into an existing one) and the catch-all site is appended.
set -euo pipefail
export LC_ALL=C
usage() {
  echo 'Usage: enable-on-demand-tls.sh [--dry-run] [Caddyfile]' >&2
  echo '       enable-on-demand-tls.sh --rollback <backup> [Caddyfile]' >&2
  exit 1
}
dry_run=false
rollback=
while [[ $# -gt 0 ]]; do
  case $1 in
    --dry-run) dry_run=true; shift ;;
    --rollback) [[ $# -ge 2 ]] || usage; rollback=$2; shift 2 ;;
    -*) usage ;;
    *) break ;;
  esac
done
[[ $# -le 1 ]] || usage
[[ -z $rollback ]] || ! $dry_run || usage
caddyfile=${1:-/etc/caddy/Caddyfile}
# BIN is a directory containing caddy and systemctl; only override it for fixtures.
caddy=${BIN:+$BIN/}caddy
systemctl=${BIN:+$BIN/}systemctl
# INTERNAL_PORT is the edge internal listener (see TLS ask docs); UPSTREAM_PORT is the edge proxy port.
ask_port=${INTERNAL_PORT:-8789}
upstream_port=${UPSTREAM_PORT:-8787}
[[ $ask_port =~ ^[0-9]{1,5}$ && $upstream_port =~ ^[0-9]{1,5}$ ]] || { echo 'Ports must be numeric.' >&2; exit 1; }
[[ -f $caddyfile && ! -L $caddyfile ]] || { echo 'Caddyfile must be a regular, non-symlink file.' >&2; exit 1; }

# Validate as the caddy user when root so validate never leaves root-owned log files behind.
if (( EUID == 0 )); then as_caddy=(runuser -u caddy --); else as_caddy=(); fi
validate() { "${as_caddy[@]}" "$caddy" validate --adapter caddyfile --config "$1"; }

if ! $dry_run; then
  [[ $EUID == 0 ]] || { echo 'Run as root on the edge.' >&2; exit 1; }
  # Lock a sidecar file: the Caddyfile inode is replaced by every install.
  exec 9>"${caddyfile}.lock"
  flock -x 9
fi

stamp=$(date -u +%Y%m%dT%H%M%S%N)
work=
candidate=
cleanup() {
  [[ -z $work ]] || rm -rf -- "$work"
  [[ -z $candidate ]] || rm -f -- "$candidate"
}
trap cleanup EXIT

# Install a file over the Caddyfile atomically (same directory rename), keeping mode and owner.
install_over() {
  local tmp="${caddyfile}.tmp-ondemand-$stamp"
  cp -p -- "$1" "$tmp"
  mv -f -- "$tmp" "$caddyfile"
}
# Reinstall a known-good file, validate it, reload; fall back to a restart. Returns 0 only when
# Caddy is active, 1 when the file could not be restored but Caddy is running, 3 when Caddy is down.
restore_file() {
  local restored=false
  if install_over "$1" && validate "$caddyfile"; then
    restored=true
    reload_and_check && return 0
    echo 'Reload failed after restoring the Caddyfile; restarting caddy.' >&2
    "$systemctl" restart caddy || true
    "$systemctl" is-active --quiet caddy && return 0
  else
    echo 'Could not install and validate the restored Caddyfile.' >&2
  fi
  if "$systemctl" is-active --quiet caddy; then
    $restored || echo 'Caddy is still running with its previously loaded configuration; fix the Caddyfile by hand.' >&2
    return 1
  fi
  echo "CADDY IS DOWN: restoring $1 did not bring caddy back. Fix the Caddyfile and run: systemctl restart caddy" >&2
  return 3
}
reload_and_check() {
  # Explicit chain: errexit is suspended when callers test this function in an if.
  "$systemctl" reload caddy && "$systemctl" is-active --quiet caddy
}

if [[ -n $rollback ]]; then
  [[ -f $rollback && ! -L $rollback ]] || { echo 'Backup must be a regular, non-symlink file.' >&2; exit 1; }
  safety="${caddyfile}.bak-ondemand-prerollback-$stamp"
  cp -p -- "$caddyfile" "$safety"
  candidate="${caddyfile}.candidate-ondemand-$stamp"
  cp -p -- "$rollback" "$candidate"
  validate "$candidate"
  install_over "$candidate"
  if ! reload_and_check; then
    echo "Reload failed after rollback; restoring pre-rollback file $safety." >&2
    code=0
    restore_file "$safety" || code=$?
    [[ $code != 0 ]] || echo "Restored $safety." >&2
    exit $(( code == 0 ? 1 : code ))
  fi
  printf 'Rolled back from %s. Pre-rollback copy: %s\n' "$rollback" "$safety"
  exit 0
fi

# (a) Refuse when on-demand TLS or a catch-all site already exists.
if grep -Eq '(^|[^a-z0-9_])on_demand_tls([^a-z0-9_]|$)' "$caddyfile"; then
  echo 'Caddyfile already has an on_demand_tls block.' >&2
  exit 1
fi
if grep -Eq '^[[:space:]]*https://[[:space:]]*(\{|,|$)' "$caddyfile"; then
  echo 'Caddyfile already has a catch-all https:// site.' >&2
  exit 1
fi

if ! grep -Eq '^[[:space:]]*\(fdctl\)' "$caddyfile"; then
  echo 'Caddyfile has no (fdctl) snippet definition; the catch-all site imports it.' >&2
  exit 1
fi

global_block=$(cat <<BLOCK
{
    on_demand_tls {
        ask http://127.0.0.1:${ask_port}/tls/ask
    }
}
BLOCK
)
site_block=$(cat <<BLOCK
https:// {
    tls {
        on_demand
    }
    import fdctl
    reverse_proxy 127.0.0.1:${upstream_port}
}
BLOCK
)

# A global block is a first significant line of "{". Anything else starting with "{" cannot be merged safely.
first=$(grep -Evm1 '^[[:space:]]*(#.*)?$' "$caddyfile" || true)
trimmed=${first//[[:space:]]/}
if [[ $trimmed == '{' ]]; then
  has_global=true
elif [[ $trimmed == \{* ]]; then
  echo 'Cannot merge into this global block; put "{" alone on its line.' >&2
  exit 1
else
  has_global=false
fi

work=$(mktemp -d)
build="$work/Caddyfile.candidate"
if $has_global; then
  # Insert the ask configuration right after the opening brace of the existing global block.
  ASK=$(printf '    on_demand_tls {\n        ask http://127.0.0.1:%s/tls/ask\n    }' "$ask_port") awk '
    !done && $0 !~ /^[[:space:]]*(#.*)?$/ { print; print ENVIRON["ASK"]; done = 1; next }
    { print }' "$caddyfile" > "$build"
else
  printf '%s\n\n' "$global_block" > "$build"
  cat -- "$caddyfile" >> "$build"
fi
[[ -z $(tail -c1 "$build") ]] || printf '\n' >> "$build"
printf '\n%s\n' "$site_block" >> "$build"

if $dry_run; then
  diff -u -- "$caddyfile" "$build" || true
  exit 0
fi

# (b) Timestamped backup next to the Caddyfile.
backup="${caddyfile}.bak-ondemand-$stamp"
cp -p -- "$caddyfile" "$backup"
printf 'Rollback: %q --rollback %q %q\n' "$0" "$backup" "$caddyfile"

# (d) Validate the candidate, kept beside the Caddyfile so the final install is a same-directory rename.
candidate="${caddyfile}.candidate-ondemand-$stamp"
cp -p -- "$caddyfile" "$candidate"
cat -- "$build" > "$candidate"
validate "$candidate"

# (e)-(f) Install, reload, verify; restore the backup if anything fails from here on.
installed=false
restore() {
  trap - ERR HUP INT TERM
  local code=0
  if $installed; then
    restore_file "$backup" || code=$?
    [[ $code != 0 ]] || echo "Restored $backup." >&2
  fi
  return $code
}
trap 'code=0; restore || code=$?; exit $(( code == 0 ? 1 : code ))' HUP INT TERM
if ! { install_over "$candidate" && installed=true && reload_and_check; }; then
  installed=true # A partial install is restored too; the backup is a complete copy.
  code=0
  restore || code=$?
  exit $(( code == 0 ? 1 : code ))
fi
trap - HUP INT TERM
printf 'Enabled on-demand TLS. Backup: %s\n' "$backup"
