# Fastdog Edge

**Fastdog Networks** Phase 1 foundation: authoritative-DNS *control plane* stub, outbound tunnel agent stub, and a thin reverse-proxy edge.

Umbrella brand: **Fastdog**. Separate service from [Verdict](../verdict) (future hook only — not integrated this pass).

Dogfood target: **Summit Lease** (`trysummitlease.com`) on LAN `prod1` (192.168.200.7), **in parallel** with the existing Cloudflare tunnel. Do not cut over or touch CF / prod1 from this repo yet.

## Architecture (Phase 1)

```
                    LAN only (do not expose WAN)
  ┌─────────────┐     HTTP :8787      ┌──────────────────┐
  │ Browser /   │ ──────────────────► │ fastdog-edge     │
  │ curl on LAN │                     │  - host router   │
  └─────────────┘                     │  - /health       │
                                      │  - /_fastdog/*   │
                                      │  - DNS CRUD API  │
                                      │  - WS tunnel hub │
                                      └────────┬─────────┘
                         static upstream       │ WS tunnel (agent outbound)
                    (config/routes.yaml)       │
                         │                     ▼
                         │              ┌──────────────┐
                         │              │ agent/       │
                         ▼              │ (on origin)  │
                  ┌─────────────┐       └──────┬───────┘
                  │ mock :9999  │              │ HTTP
                  │ or prod1    │◄─────────────┘
                  └─────────────┘
```

- **Edge** (`src/edge/server.js`): Express + raw HTTP proxy + WebSocket tunnel hub. Bind defaults to `0.0.0.0:8787` (fine on LAN; **document: do-not-expose**).
- **Agent** (`agent/index.js`): Registers with edge, opens outbound WS, forwards HTTP-over-JSON frames to a local upstream. Minimal v0 (single request/response); TODOs for multiplex / reconnect / binary.
- **DNS stub** (`src/dns/`): File-backed zones under `zones/*.json` (ships `trysummitlease.com` sample). CRUD under `/_fastdog/dns/*` + BIND export for a future CoreDNS/PowerDNS sidecar (not started here).

## Quick start (server3)

```sh
cd ~/projects/fastdog-edge
cp .env.example .env   # optional
npm install
npm test
npm start              # edge on :8787
```

Health:

```sh
curl -sS http://127.0.0.1:8787/health
```

Mock origin + proxy smoke (optional second terminal):

```sh
node scripts/mock-upstream.js          # :9999
curl -sS -H 'Host: demo.fastdog.local' http://127.0.0.1:8787/
```

Tunnel agent smoke:

```sh
# terminal A: edge already running
# terminal B: mock upstream
node scripts/mock-upstream.js
# terminal C:
AGENT_HOSTNAME=via-tunnel.local npm run agent
# then:
curl -sS -H 'Host: via-tunnel.local' http://127.0.0.1:8787/
```

DNS:

```sh
curl -sS http://127.0.0.1:8787/_fastdog/dns/zones
curl -sS http://127.0.0.1:8787/_fastdog/dns/zones/trysummitlease.com
curl -sS http://127.0.0.1:8787/_fastdog/dns/zones/trysummitlease.com/export.bind
npm run export-zones -- trysummitlease.com
```

## Ports

| Service        | Default | Bind        | Notes                          |
|----------------|---------|-------------|--------------------------------|
| Edge HTTP + WS | 8787    | 0.0.0.0     | LAN only — do not port-forward |
| Mock upstream  | 9999    | 127.0.0.1   | Dev helper                     |
| Verdict (peer) | 8080    | (existing)  | Untouched                      |

## Dogfood beside Cloudflare

1. Keep **cloudflared / CF DNS** as the public path for `trysummitlease.com`.
2. Run Fastdog Edge only on **server3** (or later a LAN host) with routes pointed at prod1's Docker HTTP port once known.
3. Test with `Host:` headers or LAN `/etc/hosts` → `192.168.200.42` — never change public DNS until Phase 1 is proven.
4. Agent on prod1 (later) can replace the need for inbound ports: outbound WS to edge, same idea as cloudflared.

### Wiring to prod1 (blocked until SSH)

- **Blocker:** Mamasota cannot SSH to prod1 (`192.168.200.7`) with the server3 key (Permission denied). Do not invent credentials.
- Once SSH exists: discover Summit Lease container publish port (Docker behind Caddy HTTPS redirect), set in `config/routes.yaml`:

```yaml
routes:
  trysummitlease.com: http://192.168.200.7:PORT
  www.trysummitlease.com: http://192.168.200.7:PORT
```

- Or run `agent/` on prod1 with `AGENT_LOCAL_UPSTREAM=http://127.0.0.1:PORT` and `AGENT_HOSTNAME=trysummitlease.com`, `EDGE_HTTP_URL=http://192.168.200.42:8787`.

See [deploy/LOCAL_PROD.md](deploy/LOCAL_PROD.md).

## systemd

Unit examples live under `deploy/`. **Not installed/enabled** by default. Review LAN-only posture before:

```sh
# only after explicit decision — do not enable casually
sudo cp deploy/fastdog-edge.service /etc/systemd/system/
# sudo systemctl enable --now fastdog-edge   # intentionally not run in Phase 1 scaffold
```

## Future: Verdict hook

Verdict already runs on server3 (`~/projects/verdict`, `:8080`). Later, edge can call Verdict `/v1/decide` as a middleware on selected routes (challenge/block). **Not wired this pass.**

## Non-goals (this pass)

- No public internet exposure
- No Cloudflare or prod1 changes
- No new VPS / domain / Stripe spend
- No full authoritative DNS daemon (export only)
- No Verdict integration

## License

Private — Fastdog Networks / Pete Spelic.
