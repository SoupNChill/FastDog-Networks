# Stranger onboarding (Track A1)

This is a thin LAN control path. The edge API uses the shared `AGENT_TOKEN` for onboarding requests. Keep the control port on a trusted LAN; issued agent credentials are returned once and stored as hashes in `DATA_DIR/agent-credentials.json`.

Zone creation requires an invite code by default (`INVITE_REQUIRED=true`). Generate one with `npm run onboard -- generate-invite`, then pass `--invite <code>` to `create-zone` or `invite_code` in the API body. See [Invite codes](INVITES.md) for API routes, redemption, and how to disable the gate.

1. Set `AGENT_TOKEN`, `EDGE_PUBLIC_IP`, `ZONES_DIR`, and `DATA_DIR` in the edge environment. Set `NS1_HOST`, `NS2_HOST`, `NS1_IP`, and `NS2_IP` if they differ from the live defaults in `.env.example`.
2. Create a zone: `npm run onboard -- create-zone example.com --edge-ip 157.230.57.32 --invite <code>`. Omit `--edge-ip` to leave the apex A absent. An existing zone returns an error; `--force` replaces it.
3. Review nameserver instructions: `npm run onboard -- ns-instructions example.com`. Verify the SOA and NS on **both** authoritative servers before changing registrar delegation. In-bailiwick nameservers also need registrar child host/glue records.
4. Issue an agent credential: `npm run onboard -- issue-credential --name example-agent --hostname app.example.com`. Save the returned `AGENT_TOKEN` privately. A hostname-bound token registers only that hostname.
5. Map the host: `npm run onboard -- map-host example.com app.example.com --origin-hint http://127.0.0.1:8080`. Set the returned `AGENT_HOSTNAME`, `AGENT_LOCAL_UPSTREAM`, and issued `AGENT_TOKEN` on the agent, along with `EDGE_HTTP_URL` and `EDGE_WS_URL`, then run `npm run agent`. Mapping adds an A record and a tunnel host. For CLI changes, reload a running edge via `POST /_fastdog/routes/reload` or restart it. API map-host reloads automatically.
6. When `COREDNS_SYNC_ENABLED=true` (and PoP SSH configured), create-zone/map-host auto-export, validate, and sync CoreDNS to both PoPs. Otherwise sync is skipped (audited) and you can run `npm run sync-coredns -- example.com` manually. Then check `dig @<NS_IP> app.example.com A +norecurse`. A JSON edit alone does not publish DNS.

The same actions are available under `/_fastdog/onboard`: `POST /zones`, `GET /zones/:zone/ns-instructions`, `POST /credentials`, and `POST /hosts`. Send `x-fastdog-token: <AGENT_TOKEN>` (or `token` in JSON). Registration accepts issued credentials; the WebSocket handshake uses the same token.

Example API request:

```sh
curl -sS -X POST http://127.0.0.1:8787/_fastdog/onboard/zones \
  -H "x-fastdog-token: $AGENT_TOKEN" -H 'content-type: application/json' \
  -d '{"zone":"example.com","edge_ip":"157.230.57.32","invite_code":"fd-<code>"}'
```

This path does not change registrar settings. Zone deploy to CoreDNS is automatic only when auto-sync is enabled and configured; otherwise run `sync-coredns` manually. Public use requires the existing authoritative DNS and edge ingress to be ready for the new domain.

## Public NS status (read before pointing a stranger)

- Fastdog's own domain `fastdognetworks.com` still uses Cloudflare registrar NS (`duke` / `melany`) until the post-Sat Porkbun/NS cut (see `deploy/NS_CUT.md` and dry-run `deploy/PORKBUN_TRANSFER.md`). Do not unlock, transfer, or flip NS in this track.
- Customer domains keep their own registrar. Once `ns1.fastdognetworks.com` / `ns2.fastdognetworks.com` glue is public and CoreDNS serves their zone on both PoPs, strangers set custom NS to those two names and verify with `dig`.
- Until that glue/public NS is live, LAN dogfood still works: create zone → issue credential → map host → run agent → `curl -H Host:... http://192.168.200.42:8787/`.

## LAN try (server3)

```sh
cd ~/projects/fastdog-edge
cp -n .env.example .env
npm test
npm start   # terminal A: edge :8787

# terminal B
npm run onboard -- generate-invite --note demo
npm run onboard -- create-zone demo-customer.test --edge-ip 157.230.57.32 --invite fd-<code>
npm run onboard -- ns-instructions demo-customer.test
npm run onboard -- issue-credential --name demo --hostname app.demo-customer.test
# save issued AGENT_TOKEN from JSON
npm run onboard -- map-host demo-customer.test app.demo-customer.test --origin-hint http://127.0.0.1:9999
curl -sS -X POST -H "x-fastdog-token: $AGENT_TOKEN" http://127.0.0.1:8787/_fastdog/routes/reload

# terminal C: mock origin + agent
node scripts/mock-upstream.js
AGENT_TOKEN=<issued> AGENT_HOSTNAME=app.demo-customer.test AGENT_LOCAL_UPSTREAM=http://127.0.0.1:9999 npm run agent

curl -sS -H 'Host: app.demo-customer.test' http://127.0.0.1:8787/
```

## Auto sync-coredns (validation + audit)

After `create-zone` and `map-host` (CLI and `/_fastdog/onboard` API), the control plane exports the zone, validates it, and optionally syncs CoreDNS.

**Safe defaults:** `COREDNS_SYNC_ENABLED=false`. Sync is skipped, an audit line is written, and onboarding still succeeds. Apex A remains **opt-in** (`--edge-ip` / `edge_ip` only).

### Enable (operator / Pete + bots only)

Shared `AGENT_TOKEN` is Phase 1 **operator admin** for onboarding API calls. Do **not** put that token in customer docs or UI. Customer tunnel credentials stay per-zone via `issue-credential`.

```sh
# .env on the control-plane host
COREDNS_SYNC_ENABLED=true
COREDNS_POP_TARGETS=ns1=157.230.57.32,ns2=2.29.58.90
COREDNS_SSH_USER=root
COREDNS_SSH_KEY=/path/to/operator-pop-key
COREDNS_ZONES_DIR=/etc/coredns/zones
```

Manual sync (existing script, now validates before reload):

```sh
npm run sync-coredns -- example.com
# or all zones:
npm run sync-coredns
```

### Dry-run on LAN (no PoP SSH)

```sh
COREDNS_SYNC_ENABLED=true COREDNS_SYNC_DRY_RUN=true   COREDNS_POP_TARGETS=ns1=157.230.57.32,ns2=2.29.58.90   npm run onboard -- create-zone dry-run.example --invite fd-<code>
```

Dry-run validates SOA/NS (`ns1`/`ns2.fastdognetworks.com`), appends audit, and skips local write + remote SSH.

### Validation

Before reload/sync: zone must be non-empty, include SOA + NS, and NS must include `NS1_HOST` / `NS2_HOST` (defaults `ns1.fastdognetworks.com` / `ns2.fastdognetworks.com`).

### Audit log

Structured JSONL at `DATA_DIR/audit/coredns-sync.jsonl` (or `COREDNS_AUDIT_LOG`): `ts`, `zone`, `action`, `pops`, `success`, `error`, `dry_run`.

### Failure behavior

Remote sync failure does **not** roll back zone/host map. The onboard result includes `coredns_sync` with `ok: false` and `error`. CLI prints a clear stderr warning; set `COREDNS_SYNC_STRICT=true` to make the CLI exit non-zero on sync failure. Edge keeps serving; fix PoP SSH/keys and re-run `npm run sync-coredns -- <zone>`.
