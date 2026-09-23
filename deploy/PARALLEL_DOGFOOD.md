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

Stop: `bash deploy/stop-edge.sh`

Optional systemd: `deploy/fastdog-edge.service` (needs sudo; not installed by default; Linger currently off for user units).

## Agent (prod1)

```sh
# on prod1
cd /home/barbra/fastdog-agent
docker compose up -d
docker compose ps
docker compose logs -f --tail=50
# network join proof:
docker inspect fastdog-agent-fastdog-agent-1 --format '{{json .NetworkSettings.Networks}}'
```

Compose uses `external: true` network `summitlease-prod_default`. Never `docker compose` against summitlease-prod for this.

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

- `AGENT_TOKEN` in `.env` is local-dev only; rotate before any shared/non-LAN use. Never commit `.env` or Cloudflare `TUNNEL_TOKEN`.