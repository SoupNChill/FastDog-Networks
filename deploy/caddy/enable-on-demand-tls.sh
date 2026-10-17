#!/usr/bin/env bash
# Enable (or roll back) Caddy on-demand TLS. Existing site blocks are never edited: the global
# block is prepended (or merged into an existing one) and the catch-all site is appended.
set -euo pipefail
export LC_ALL=C
umask 077
usage() {
  echo 'Usage: enable-on-demand-tls.sh [--dry-run] [--probe-host HOST] [Caddyfile]' >&2
  echo '       enable-on-demand-tls.sh --check-only [Caddyfile]' >&2
  echo '       enable-on-demand-tls.sh --rollback <backup> [--force] [Caddyfile]' >&2
  exit 1
}
dry_run=false
check_only=false
rollback=
force=false
probe_host=
while [[ $# -gt 0 ]]; do
  case $1 in
    --dry-run) dry_run=true; shift ;;
    --check-only) check_only=true; shift ;;
    --rollback) [[ $# -ge 2 ]] || usage; rollback=$2; shift 2 ;;
    --probe-host) [[ $# -ge 2 ]] || usage; probe_host=$2; shift 2 ;;
    --force) force=true; shift ;;
    -*) usage ;;
    *) break ;;
  esac
done
[[ $# -le 1 ]] || usage
[[ -z $rollback ]] || ! $dry_run || usage
! $check_only || [[ -z $rollback && -z $probe_host && $dry_run == false && $force == false ]] || usage
[[ -n $rollback ]] || ! $force || usage
[[ -z $probe_host || $probe_host =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || usage
caddyfile=${1:-/etc/caddy/Caddyfile}
# BIN is a directory containing caddy, curl and systemctl; only override it for fixtures.
caddy=${BIN:+$BIN/}caddy
systemctl=${BIN:+$BIN/}systemctl
curl=${BIN:+$BIN/}curl
# INTERNAL_PORT is the edge internal listener (see TLS ask docs); UPSTREAM_PORT is the edge proxy port.
ask_port=${INTERNAL_PORT:-8789}
upstream_port=${UPSTREAM_PORT:-8787}
[[ $ask_port =~ ^[0-9]{1,5}$ && $upstream_port =~ ^[0-9]{1,5}$ ]] || { echo 'Ports must be numeric.' >&2; exit 1; }
[[ -f $caddyfile && ! -L $caddyfile ]] || { echo 'Caddyfile must be a regular, non-symlink file.' >&2; exit 1; }

# Validate as the caddy user when root so validate never leaves root-owned log files behind.
if (( EUID == 0 )); then as_caddy=(runuser -u caddy --); else as_caddy=(); fi
validate() { "${as_caddy[@]}" "$caddy" validate --adapter caddyfile --config "$1"; }

if ! $dry_run && ! $check_only; then
  [[ $EUID == 0 ]] || { echo 'Run as root on the edge.' >&2; exit 1; }
  # Lock a sidecar file: the Caddyfile inode is replaced by every install.
  exec 9>"${caddyfile}.lock"
  flock -x 9
fi

stamp=$(date -u +%Y%m%dT%H%M%S%N)
work=
candidate=
tmp=
cleanup() {
  [[ -z $tmp ]] || rm -f -- "$tmp"
  [[ -z $work ]] || rm -rf -- "$work"
  [[ -z $candidate ]] || rm -f -- "$candidate"
}
trap cleanup EXIT

# Install a file over the Caddyfile atomically (same directory rename), keeping mode and owner.
install_over() {
  tmp="${caddyfile}.tmp-ondemand-$stamp"
  # Explicit chain: errexit is suspended when callers test this function in an if.
  cp -p -- "$1" "$tmp" && mv -f -- "$tmp" "$caddyfile" || return 1
  tmp=
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
# The edge internal listener must answer after a reload; the ask route depends on it.
ask_healthy() {
  local try status
  [[ -n $probe_host ]] || echo "Warning: a 4xx probe cannot confirm the ask route is enabled; use --probe-host with an approved static host." >&2
  for try in 1 2 3; do
    if status=$("$curl" --noproxy '*' -sS --max-time 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${ask_port}/tls/ask?domain=${probe_host:-probe.invalid}" 2>/dev/null) && [[ ( -n $probe_host && $status == 200 ) || ( -z $probe_host && $status =~ ^4[0-9][0-9]$ ) ]]; then return 0; fi
    (( try == 3 )) || sleep "${HEALTH_DELAY:-1}"
  done
  echo "Ask endpoint http://127.0.0.1:${ask_port}/tls/ask is not healthy (expected 200 with --probe-host, otherwise a 4xx denial)." >&2
  return 1
}

# Inspect adapted routes: a matcher in a named site does not protect the catch-all.
catch_all_protected() {
  local adapted="$work/adapted.json"
  # The adapted JSON stays in the root-owned work directory; never write through a pre-existing file.
  rm -f -- "$adapted"
  ( set -o noclobber; "$caddy" adapt --adapter caddyfile --config "${1:-$caddyfile}" > "$adapted" ) || return 1
  node --input-type=module - "$adapted" <<'JS'
import fs from 'node:fs';
const config = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
// Host-less routes in request order. Only parents with no matcher at all are descended into:
// children of a route with any matcher (method, remote_ip, header, path...) are conditional.
function flatten(routes) {
  const out = [];
  for (const route of routes ?? []) {
    if (route.match?.some(match => match.host)) continue;
    out.push(route);
    if (route.match?.length) continue;
    for (const handler of route.handle ?? []) if (handler.handler === 'subroute') out.push(...flatten(handler.routes));
  }
  return out;
}
const refusal = handler => ['static_response', 'error'].includes(handler?.handler) && /^4[0-9]{2}$/.test(String(handler.status_code));
// Any reverse_proxy inside the route, whatever its upstream form.
const hasProxy = route => (route.handle ?? []).some(handler => handler.handler === 'reverse_proxy' ||
  (handler.handler === 'subroute' && (handler.routes ?? []).some(hasProxy)));
const pathOnly = match => Object.keys(match).every(key => key === 'path');
const controlMatch = match => Object.keys(match).every(key => key === 'path' || key === 'not') &&
  (match.not === undefined || (Array.isArray(match.not) && match.not.every(pathOnly)));
const control = route => route.match?.length > 0 && route.match.every(controlMatch) &&
  route.match.some(match => match.path?.includes('/_fastdog/*')) && !hasProxy(route) &&
  route.handle?.some(handler => refusal(handler) || (handler.handler === 'subroute' && (() => {
    const end = (handler.routes ?? []).findIndex(inner => !inner.match?.length);
    return end >= 0 && refusal(handler.routes[end].handle?.at(-1));
  })()));
const mismatch = route => route.match?.some(match =>
  match.not?.some(negated => negated.host?.length === 1 && negated.host[0] === '{http.request.tls.server_name}')) &&
  route.handle?.some(handler => handler.handler === 'static_response' && String(handler.status_code) === '421');
const servers = Object.values(config.apps?.http?.servers ?? {});
process.exit(servers.some(server => {
  if (!server.listen?.some(address => address.endsWith(':443'))) return false;
  const routes = flatten(server.routes);
  // The first flattened route that itself proxies is the ordering boundary; without one, fail closed.
  // Routes with a matcher are not descended into, so a proxy nested inside one counts as its own.
  const first = routes.findIndex(route => route.match?.length ? hasProxy(route) :
    (route.handle ?? []).some(handler => handler.handler === 'reverse_proxy'));
  if (first < 0) return false;
  const before = routes.slice(0, first);
  return before.some(control) && before.some(mismatch);
}) ? 0 : 1);
JS
}

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

if [[ -n $rollback ]]; then
  [[ -f $rollback && ! -L $rollback ]] || { echo 'Backup must be a regular, non-symlink file.' >&2; exit 1; }
  # Refuse to discard edits made since enabling (for example hosts added with add-customer-host.sh).
  enabled="${rollback/.bak-ondemand-/.enabled-ondemand-}"
  if ! $force; then
    if [[ $enabled == "$rollback" || ! -f $enabled ]]; then
      echo 'No record of the post-enable Caddyfile for this backup; use --force to roll back anyway.' >&2
      exit 1
    fi
    if ! cmp -s -- "$enabled" "$caddyfile"; then
      echo 'The Caddyfile has changed since on-demand TLS was enabled; rolling back would discard those changes.' >&2
      echo "Review: diff -u $(printf '%q %q' "$enabled" "$caddyfile")" >&2
      echo 'Re-run with --force to roll back anyway.' >&2
      exit 1
    fi
  fi
  safety="${caddyfile}.bak-ondemand-prerollback-$stamp"
  cp -p -- "$caddyfile" "$safety"
  candidate="${caddyfile}.candidate-ondemand-$stamp"
  cp -p -- "$rollback" "$candidate"
  validate "$candidate"
  backup=$safety
  trap 'code=0; restore || code=$?; exit $(( code == 0 ? 1 : code ))' HUP INT TERM
  installed=true
  if ! { install_over "$candidate" && reload_and_check; }; then
    echo "Reload failed after rollback; restoring pre-rollback file $safety." >&2
    code=0
    restore_file "$safety" || code=$?
    [[ $code != 0 ]] || echo "Restored $safety." >&2
    exit $(( code == 0 ? 1 : code ))
  fi
  trap - HUP INT TERM
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
    @sni_mismatch not host {http.request.tls.server_name}
    respond @sni_mismatch 421
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
# Only this subdirectory is ever handed to caddy; the work directory itself stays root-owned.
mkdir -- "$work/cand"
chmod 711 -- "$work"
build="$work/cand/Caddyfile.candidate"
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

if $check_only; then
  # Root validates as caddy, so only the candidate subdirectory and file belong to caddy.
  if (( EUID == 0 )); then chown caddy -- "$work/cand" "$build" || exit 1; fi
  if validate "$build" >/dev/null && catch_all_protected "$build"; then
    echo 'CHECK OK'
    exit 0
  fi
  echo 'CHECK FAILED: candidate did not validate or lacks the catch-all protections.' >&2
  exit 1
fi
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
catch_all_protected "$candidate" || { echo "Candidate catch-all protection check failed; refusing install." >&2; exit 1; }

# (e)-(f) Install, reload, verify; restore the backup if anything fails from here on.
trap 'code=0; restore || code=$?; exit $(( code == 0 ? 1 : code ))' HUP INT TERM
installed=true
if ! { install_over "$candidate" && reload_and_check && ask_healthy && catch_all_protected; }; then
  installed=true # A partial install is restored too; the backup is a complete copy.
  code=0
  restore || code=$?
  exit $(( code == 0 ? 1 : code ))
fi
trap - HUP INT TERM
# Record the installed file so a later rollback can tell whether the Caddyfile changed since.
cp -p -- "$caddyfile" "${backup/.bak-ondemand-/.enabled-ondemand-}"
printf 'Enabled on-demand TLS. Backup: %s\n' "$backup"
