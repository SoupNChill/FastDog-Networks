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

## Do not

- Publish `:8787` on a WAN interface, cloud security group, or home-router port forward
- Change Cloudflare tunnel or DNS for `trysummitlease.com`
- Commit `.env` or shared `AGENT_TOKEN` used beyond single-host LAN
- Spend on new VPS / domains / Stripe for this phase

## Smoke checklist

```sh
curl -sS http://127.0.0.1:8787/health
curl -sS http://127.0.0.1:8787/_fastdog/routes
curl -sS http://127.0.0.1:8787/_fastdog/dns/zones/trysummitlease.com
curl -sS http://127.0.0.1:8787/_fastdog/dns/zones/trysummitlease.com/export.bind | head
npm test
```
