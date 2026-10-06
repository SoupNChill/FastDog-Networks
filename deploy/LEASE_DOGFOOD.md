# Summit Lease public dogfood on FastDog zone

Secondary hostname `lease.fastdognetworks.com` on the FastDog zone while `trysummitlease.com` remains on Cloudflare DNS + cloudflared.

**Do not** change `zones/trysummitlease.com.json`, stop cloudflared, or flip Summit NS.

## Prerequisites

- PR merged with:
  - `zones/fastdognetworks.com.json`: A record `lease` → `157.230.57.32` TTL 300, SOA serial `2026100601`
  - `config/routes.yaml`: `lease.fastdognetworks.com` in `tunnel_hosts`
- Pete approval for publish

## Deploy steps (go-gated)

### 1. Sync zone to ns1 + ns2 CoreDNS

```sh
# On edge-fastdog (157.230.57.32)
cd ~/projects/fastdog-edge
git pull origin master
./scripts/sync-coredns.sh fastdognetworks.com

# Verify
dig @157.230.57.32 lease.fastdognetworks.com A +short
# Expected: 157.230.57.32

dig @2.29.58.90 lease.fastdognetworks.com A +short
# Expected: 157.230.57.32
```

### 2. Add Caddy hostname block

Edit `/etc/caddy/Caddyfile` on edge-fastdog and add (same pattern as whoami/edge — plain reverse proxy, no /www rewrite):

```caddyfile
lease.fastdognetworks.com {
    reverse_proxy 127.0.0.1:8787
}
```

### 3. Reload Caddy for LE cert

```sh
sudo systemctl reload caddy
# Caddy auto-provisions Let's Encrypt cert on first request

# Verify cert
curl -sS -o /dev/null -w '%{http_code}\n' https://lease.fastdognetworks.com/health
```

### 4. Retarget prod1 agent

Edit `/home/barbra/fastdog-agent/.env` on prod1:

```sh
AGENT_TOKEN=<existing token — do not change>
AGENT_NAME=prod1-summitlease-lease
AGENT_HOSTNAME=lease.fastdognetworks.com
EDGE_HTTP_URL=https://edge.fastdognetworks.com
EDGE_WS_URL=wss://edge.fastdognetworks.com/_fastdog/tunnel
AGENT_LOCAL_UPSTREAM=http://app:3450
```

The agent must dial the public PoP over WSS because LAN server3:8787 is down.

Recreate the agent container only (never touch `/opt/summitlease` or cloudflared):

```sh
cd /home/barbra/fastdog-agent
docker compose up -d --force-recreate
docker compose logs -f --tail=20
```

### 5. Verify

```sh
curl -sS https://lease.fastdognetworks.com/api/health
# Expected: {"status":"ok"}

# Confirm trysummitlease.com still works via CF
curl -sS https://trysummitlease.com/api/health
# Expected: {"status":"ok"}
```

## Rollback

1. Remove Caddy block for `lease.fastdognetworks.com` and reload:
   ```sh
   sudo systemctl reload caddy
   ```

2. Remove A record from `zones/fastdognetworks.com.json` and sync:
   ```sh
   ./scripts/sync-coredns.sh fastdognetworks.com
   ```

3. Revert prod1 agent `.env` to LAN config if needed (optional — agent will fail gracefully if hostname is gone)

**Leave cloudflared alone** — trysummitlease.com path is unaffected.

## Related docs

- [PARALLEL_DOGFOOD.md](PARALLEL_DOGFOOD.md) — original LAN dogfood topology
- [AUTH_DNS.md](AUTH_DNS.md) — CoreDNS zone management
- [prod1-fastdog-agent/](prod1-fastdog-agent/) — agent template
