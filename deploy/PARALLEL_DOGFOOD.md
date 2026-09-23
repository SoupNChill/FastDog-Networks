# Parallel Summit Lease dogfood (beside Cloudflare)

LAN-only path. **Do not** edit `/opt/summitlease/docker-compose.yml`, stop cloudflared, change CF DNS, or expose :8787 to WAN.

## Topology

- **Edge** on server3 `192.168.200.42:8787` (this repo)
- **Agent** on prod1 as separate compose project `/home/barbra/fastdog-agent`
  - joins external network `summitlease-prod_default`
  - upstream `http://app:3450` (docker DNS alias for summitlease-prod-app-1)
  - outbound WS to `ws://192.168.200.42:8787/_fastdog/tunnel`
- Public path `https://trysummitlease.com` via existing cloudflared stays authoritative

## Hostname for LAN Host-header tests

`summitlease.fastdog.lan` (also registered for `trysummitlease.com` Host header on LAN only — does not change public DNS)

## Edge (server3)

```sh
cd ~/projects/fastdog-edge
npm test
bash deploy/start-edge.sh
curl -sS http://127.0.0.1:8787/health
# from Mamasota:
curl -sS http://192.168.200.42:8787/health
```

Stop: `./deploy/stop-edge.sh`. Restart: `./deploy/restart-edge.sh` (or `./deploy/start-edge.sh restart`). The no-sudo scripts use `nohup`, `disown`, `logs/edge.pid`, and append to `logs/edge.log`; use logrotate `copytruncate`. They survive logout. With `Linger=no`, a user systemd service does not persist after logout.

Optional boot persistence via the system unit (Pete, after reviewing the LAN firewall and stopping script-managed edge):

```sh
sudo cp deploy/fastdog-edge.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fastdog-edge
sudo systemctl status fastdog-edge
# later: sudo systemctl restart fastdog-edge
```

## Agent (prod1)

```sh
# on prod1
cd /home/barbra/fastdog-agent
cp .env.example .env  # replace the local-dev placeholder with the shared token
chmod 600 .env
docker compose up -d
docker compose ps
docker compose logs -f --tail=50
# network join proof:
docker inspect fastdog-agent-fastdog-agent-1 --format '{{json .NetworkSettings.Networks}}'
```

Compose uses `external: true` network `summitlease-prod_default`. Never `docker compose` against summitlease-prod for this.
The agent re-registers for a new ID after WebSocket loss. Exponential backoff with full jitter retries both registration and connection, allowing a brief edge restart.

## Token rotation

Run `openssl rand -hex 32` to generate a new token. Set `AGENT_TOKEN` to that value in server3 `~/projects/fastdog-edge/.env` and prod1 `/home/barbra/fastdog-agent/.env`; run `chmod 600` on both files. Restart the edge with `./deploy/restart-edge.sh` (or `sudo systemctl restart fastdog-edge` for the system unit), then on prod1 run `docker compose up -d --force-recreate`. Never commit either `.env` or print the production token. The example token is for local development only.

## LAN metrics

```sh
curl -sS http://192.168.200.42:8787/_fastdog/metrics
```

The unauthenticated LAN JSON includes `requestsProxied`, `requestsStatic`, `requestsTunnel`, `registerCount`, `tunnelConnected`, `agentsConnected`, `agentsRegistered`, and `uptimeSeconds`.

## Prove tunnel

```sh
curl -sS -H 'Host: summitlease.fastdog.lan' http://192.168.200.42:8787/api/health
# expect Summit Lease {"status":"ok"} (or equivalent) via agent, not edge /health
```

## Spot-check Cloudflare (after, read-only)

```sh
curl -sS -o /dev/null -w '%{http_code}\n' https://trysummitlease.com/
# on prod1: docker ps | grep summitlease  # both app + cloudflared still Up
```

## Env notes

- Compose reads `AGENT_TOKEN` from its local `.env`. Never commit `.env` or Cloudflare `TUNNEL_TOKEN`.
