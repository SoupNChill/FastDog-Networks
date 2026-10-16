#!/usr/bin/env bash
# Linux installer. Keep the portal copy byte-identical.
set +x
set -eu
export LC_ALL=C
umask 077
fail() { printf '%s\n' "$1" >&2; exit 1; }
usage() {
  printf '%s\n' 'Usage: FASTDOG_AGENT_TOKEN=TOKEN bash agent.sh --edge URL --hostname HOST [--origin URL] [--name NAME]' \
    'Remove: bash agent.sh --uninstall [--name NAME]' \
    'The edge URL must start with https:// or wss://. The default name is default.'
}
image=ghcr.io/soupnchill/fastdog-agent:0.1.2@sha256:6dcc855e5dcc5c058326d961133186b30cfa158a0173facd50d5e4e00cefd726
token=${FASTDOG_AGENT_TOKEN:-}
unset FASTDOG_AGENT_TOKEN
edge='' hostname='' origin='http://127.0.0.1:8080' name='default' uninstall=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --uninstall) uninstall=1; shift ;;
    --token|--token=*) fail 'The --token option is no longer supported. Pass the token in FASTDOG_AGENT_TOKEN instead.' ;;
    --edge|--hostname|--origin|--name)
      [ "$#" -ge 2 ] && [ -n "$2" ] || fail 'An option is missing its value. Run with --help.'
      case "$1" in
        --edge) edge=$2 ;; --hostname) hostname=$2 ;;
        --origin) origin=$2 ;; --name) name=$2 ;;
      esac
      shift 2 ;;
    *) fail 'Unknown option. Run with --help.' ;;
  esac
done
case "$name" in ''|*[!a-z0-9-]*) fail 'Use only lowercase letters, numbers and hyphens for the name.' ;; esac
[ "${#name}" -le 63 ] || fail 'Use a name of 63 characters or fewer.'
if [ "$uninstall" -eq 0 ]; then
  [ -n "$token" ] || fail 'Provide the connection token in FASTDOG_AGENT_TOKEN.'
  case "$token" in *[![:graph:]]*) fail 'The token must not contain spaces or control characters.' ;; esac
  # Accept an edge authority only; optional standard tunnel path is also supported.
  edge=${edge%/}
  edge=${edge%/_fastdog/tunnel}
  case "$edge" in https://*) authority=${edge#https://} ;; wss://*) authority=${edge#wss://} ;;
    *) fail 'The edge URL must start with https:// or wss://.' ;; esac
  host_pattern='([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?'
  [[ "$authority" =~ ^${host_pattern}(:[0-9]{1,5})?$ ]] || fail 'Provide an edge URL with a hostname and optional port, without a query or password.'
  if [[ "$authority" == *:* ]]; then
    port=${authority##*:}
    (( 10#$port >= 1 && 10#$port <= 65535 )) || fail 'The edge port must be between 1 and 65535.'
  fi
  [[ "$hostname" =~ ^${host_pattern}$ ]] && [ "${#hostname}" -le 253 ] || fail 'Provide the verified hostname with --hostname.'
  [[ "$hostname" == *.* ]] || fail 'Use the full verified hostname, such as app.example.test.'
  IFS='.' read -r -a labels <<< "$hostname"
  for label in "${labels[@]}"; do
    [ "${#label}" -le 63 ] || fail 'Each hostname label must be 63 characters or fewer.'
  done
  [[ "$origin" =~ ^https?://${host_pattern}(:[0-9]{1,5})?(/[^[:space:]\#\?]*)?$ ]] || fail 'The origin must be an http:// or https:// URL without a password or query.'
  origin_authority=${origin#*://}
  origin_authority=${origin_authority%%/*}
  if [[ "$origin_authority" == *:* ]]; then
    port=${origin_authority##*:}
    (( 10#$port >= 1 && 10#$port <= 65535 )) || fail 'The origin port must be between 1 and 65535.'
  fi
  case "$image" in *DIGEST_PLACEHOLDER*) fail 'The agent image is not ready. Ask the operator to set the published image digest.' ;; esac
fi
[ "$(id -u)" -eq 0 ] || fail 'Run this installer as root using sudo bash.'
[ "$(uname -s)" = Linux ] || fail 'This installer requires Linux.'
command -v docker >/dev/null 2>&1 || fail 'Install Docker, then run this installer again.'
command -v systemctl >/dev/null 2>&1 || fail 'This installer requires systemd.'
systemctl show-environment >/dev/null 2>&1 || fail 'Start systemd before running this installer.'
config_dir=/etc/fastdog-agent
unit_dir=/etc/systemd/system
unit="fastdog-agent-$name.service"
env_file="$config_dir/$name.env"
unit_file="$unit_dir/$unit"
if [ "$uninstall" -eq 1 ]; then
  systemctl disable --now "$unit" >/dev/null 2>&1 || fail 'Could not stop the service. Check its status before removing files.'
  rm -f -- "$unit_file" "$env_file"
  systemctl daemon-reload
  printf 'Removed %s and its saved token.\n' "$unit"
  exit 0
fi
[ ! -e "$env_file" ] && [ ! -L "$env_file" ] && [ ! -e "$unit_file" ] && [ ! -L "$unit_file" ] || fail 'This name is already installed. Choose another name or uninstall it first.'
docker pull "$image" >/dev/null 2>&1 || fail 'Could not download the agent image. Check Docker and your connection.'
[ ! -L "$config_dir" ] || fail 'The configuration directory must not be a symbolic link.'
install -d -m 700 -o root -g root "$config_dir"
# Noclobber also prevents following a file created between the checks and write.
(set -C; printf '%s\n' "AGENT_TOKEN=$token" "AGENT_NAME=$name" "AGENT_HOSTNAME=$hostname" \
  "AGENT_LOCAL_UPSTREAM=$origin" "EDGE_HTTP_URL=https://$authority" \
  "EDGE_WS_URL=wss://$authority/_fastdog/tunnel" > "$env_file")
chmod 600 "$env_file"
chown root:root "$env_file"
docker_path=$(command -v docker)
[[ "$docker_path" =~ ^/[a-zA-Z0-9_./-]+$ ]] || fail 'Docker must be installed at a standard absolute path.'
(set -C; cat > "$unit_file" <<UNIT
[Unit]
Description=Hostname connection agent ($name)
Wants=network-online.target
After=network-online.target docker.service
Requires=docker.service

[Service]
ExecStart=$docker_path run --rm --name fastdog-agent-$name --env-file $env_file --network host $image
ExecStop=$docker_path stop fastdog-agent-$name
Restart=always
RestartSec=5
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
UNIT
)
chmod 644 "$unit_file"
systemctl daemon-reload
systemctl enable --now "$unit"
printf 'Agent installed. Check status: sudo systemctl status %s\n' "$unit"
printf 'To remove it, run this installer again with: --uninstall --name %s\n' "$name"
