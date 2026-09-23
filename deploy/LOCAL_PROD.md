# Deploy Fastdog Edge to local prod (LAN)

Use your on-network machine (today: **server3** `192.168.200.42`). Do **not** open port **8787** to the public internet. Do **not** break Summit Lease / Cloudflare on prod1 — build in parallel only.

## Prerequisites

- Ubuntu with Node 18+
- SSH from Mamasota: `ssh -i ... mranderson@192.168.200.42`
- Same LAN as prod1 (`192.168.200.7`) when you are ready to dogfood Summit Lease
- No prod1 SSH yet from Mamasota (server3 key → Permission denied) — edge can still run with mock upstream

## Steps (server3)

1. Tree is already at `~/projects/fastdog-edge` (local git). If copying elsewhere:

```sh
rsync -a --exclude node_modules --exclude data --exclude .env --exclude '*.log' \
  mranderson@server3:~/projects/fastdog-edge/ ~/projects/fastdog-edge/
```

2. On the host:

```sh
cd ~/projects/fastdog-edge
npm ci
cp .env.example .env   # edit AGENT_TOKEN, DEFAULT_UPSTREAM, routes as needed
mkdir -p data
chmod 700 data
npm test
```

3. Run edge (foreground) and smoke:

```sh
npm start
curl -sS http://127.0.0.1:8787/health
curl -sS http://127.0.0.1:8787/_fastdog/dns/zones
```

4. Optional mock origin:

```sh
node scripts/mock-upstream.js
curl -sS -H 'Host: demo.fastdog.local' http://127.0.0.1:8787/
```

5. systemd (optional — units shipped **disabled** / not installed unless you choose):

```sh
# Review User=, paths, and LAN firewall first
sudo cp deploy/fastdog-edge.service /etc/systemd/system/
sudo systemctl daemon-reload
# Do not enable until LAN-only is verified:
# sudo systemctl enable --now fastdog-edge
curl -sS http://127.0.0.1:8787/health
```

6. When **prod1 SSH** exists:

- Find Summit Lease Docker HTTP port (behind Caddy).
- Point `config/routes.yaml` at `http://192.168.200.7:PORT` **or** run `agent/` on prod1 outbound to `ws://192.168.200.42:8787/_fastdog/tunnel`.
- Test with Host header / LAN hosts file only — leave Cloudflare public DNS alone.

## Parallel Summit Lease agent (prod1)

See [PARALLEL_DOGFOOD.md](./PARALLEL_DOGFOOD.md).

Summary: separate compose at `/home/barbra/fastdog-agent` on external network
`summitlease-prod_default`, upstream `http://app:3450`, edge `192.168.200.42:8787`.
Host header: `summitlease.fastdog.lan`. Never touch summitlease-prod compose/cloudflared.

Edge without sudo (survives logout):

```sh
./deploy/start-edge.sh
./deploy/stop-edge.sh
./deploy/restart-edge.sh   # or ./deploy/start-edge.sh restart
```

The scripts use `nohup`, `disown`, and `logs/edge.pid`; output appends to `logs/edge.log`. For logrotate, use `copytruncate` so the running process keeps writing to the active log. A user systemd service will not survive logout while `Linger=no`. If Pete wants boot persistence, review the unit and LAN firewall, then run these optional sudo commands on server3:

```sh
sudo cp deploy/fastdog-edge.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fastdog-edge
sudo systemctl status fastdog-edge
```

Stop the script-managed edge before enabling systemd to avoid a port conflict.

## Rotate the shared agent token

Generate a new token with `openssl rand -hex 32`. Put the same value in server3 `~/projects/fastdog-edge/.env` and prod1 `/home/barbra/fastdog-agent/.env` as `AGENT_TOKEN=...`; run `chmod 600` on both files. Restart edge with `./deploy/restart-edge.sh` (or `sudo systemctl restart fastdog-edge` if using the system unit), then restart the prod1 agent with `docker compose up -d --force-recreate`. Never commit either `.env` or print the production token. The `fastdog-local-dev-token` example is for local development only.

The agent re-registers for a fresh ID after a WebSocket drop and retries registration with exponential backoff and full jitter when edge is unavailable. It survives a brief edge restart.

LAN metrics are available without auth at `http://192.168.200.42:8787/_fastdog/metrics`. JSON fields include `requestsProxied`, `requestsStatic`, `requestsTunnel`, `registerCount`, `tunnelConnected`, `agentsConnected`, `agentsRegistered`, and `uptimeSeconds`.

## Do not

- Publish `:8787` on a WAN interface, cloud security group, or home-router port forward
- Change Cloudflare tunnel or DNS for `trysummitlease.com`
- Commit `.env` or shared `AGENT_TOKEN` used beyond single-host LAN
- Spend on new VPS / domains / Stripe for this phase

## Smoke checklist

```sh
curl -sS http://127.0.0.1:8787/health
curl -sS http://192.168.200.42:8787/_fastdog/metrics
curl -sS -H 'Host: summitlease.fastdog.lan' http://192.168.200.42:8787/api/health
curl -sS http://127.0.0.1:8787/_fastdog/routes
curl -sS http://127.0.0.1:8787/_fastdog/dns/zones/trysummitlease.com
curl -sS http://127.0.0.1:8787/_fastdog/dns/zones/trysummitlease.com/export.bind | head
npm test
```
