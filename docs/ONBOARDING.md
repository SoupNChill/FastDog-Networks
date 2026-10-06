# Stranger onboarding

This is a LAN-only control path. The edge API uses the shared `AGENT_TOKEN` for onboarding requests. Keep the control port on a trusted LAN; issued agent credentials are returned once and stored as hashes in `DATA_DIR/agent-credentials.json`.

## Quick start: Hostname attach (CNAME) — Recommended

**This is the default first-seat onboarding path.** Customer keeps their registrar DNS (including Cloudflare Free). They CNAME their hostname to FastDog's edge. No NS change needed.

```sh
# 1. Attach hostname (returns CNAME instructions)
npm run onboard -- attach-host app.customer.com

# 2. Customer adds CNAME at their registrar:
#    app.customer.com.  300  IN  CNAME  attach.fastdognetworks.com.

# 3. Verify DNS and activate (issues credential, returns Caddy block)
npm run onboard -- verify-host app.customer.com

# 4. Save the issued AGENT_TOKEN (shown once)

# 5. Run agent
AGENT_TOKEN='<issued-token>' \
AGENT_HOSTNAME=app.customer.com \
AGENT_LOCAL_UPSTREAM=http://127.0.0.1:8080 \
npm run agent

# 6. Operator: Add Caddy block and reload (see verify-host output)

# 7. Test: https://app.customer.com works
```

For detailed instructions, see [Hostname attach design](HOSTNAME_ATTACH.md) and [deploy runbook](../deploy/HOSTNAME_ATTACH.md).

### Operator UI

The operator dashboard (`http://127.0.0.1:8788/`) has "Quick attach" as the default first action:
1. Enter hostname → Click Attach
2. Customer adds CNAME
3. Click Verify → Shows credential + Caddy block
4. Add Caddy block, reload Caddy

---

## Advanced: NS cut (authoritative zone)

**For customers who need full zone control.** This path makes FastDog authoritative for the domain. **Registrar NS remains on HOLD throughout this flow.** Use hostname attach above for most customers.

Zone creation requires an invite code by default (`INVITE_REQUIRED=true`). Generate one with `npm run onboard -- generate-invite`, then pass `--invite <code>` to `create-zone` or `invite_code` in the API body. Missing, invalid, expired, or exhausted invites fail zone creation; an existing zone returns `zone_exists`. Resolve the error before continuing. See [Invite codes](INVITES.md) for API routes and redemption.

1. Set `AGENT_TOKEN`, `EDGE_PUBLIC_IP`, `ZONES_DIR`, and `DATA_DIR` in the edge environment. Set `NS1_HOST`, `NS2_HOST`, `NS1_IP`, and `NS2_IP` if they differ from the defaults in `.env.example`. Keep `COREDNS_SYNC_ENABLED=false`.
2. Create a zone: `npm run onboard -- create-zone example.com --edge-ip 157.230.57.32 --invite <code>`. Omit `--edge-ip` to leave the apex A absent. An existing zone returns an error; `--force` replaces it.
3. Preview nameserver data: `npm run onboard -- ns-instructions example.com`. If the zone is already served on the PoPs, verify SOA and NS with the returned `dig @NS1_IP ... +norecurse` and `dig @NS2_IP ... +norecurse` commands. A `zone_not_found` response or failed dig is a stop signal for DNS verification. The local JSON zone alone is not published to CoreDNS. **Do not change registrar delegation.** In-bailiwick glue is future planning only.
4. Issue an agent credential: `npm run onboard -- issue-credential --name example-agent --hostname app.example.com`. Save the returned `AGENT_TOKEN` privately. A hostname-bound token registers only that hostname.
5. Map the host: `npm run onboard -- map-host example.com app.example.com --origin-hint http://127.0.0.1:8080`. Set the returned `AGENT_HOSTNAME`, `AGENT_LOCAL_UPSTREAM`, and issued `AGENT_TOKEN` on the agent, along with `EDGE_HTTP_URL` and `EDGE_WS_URL`, then run `npm run agent`. Mapping adds an A record and a tunnel host. For CLI changes, reload a running edge via `POST /_fastdog/routes/reload` or restart it. API map-host reloads automatically.
6. Test the LAN route directly: `curl -sS -H 'Host: app.example.com' http://127.0.0.1:8787/` on server3, or use its LAN IP from a trusted client. This bypasses public DNS and registrar delegation. With auto sync off, create-zone/map-host only update local JSON; do not treat a successful LAN curl as public DNS readiness.

The same actions are available under `/_fastdog/onboard`: `POST /zones`, `GET /zones/:zone/ns-instructions`, `POST /credentials`, and `POST /hosts`. Send `x-fastdog-token: <AGENT_TOKEN>` (or `token` in JSON). Registration accepts issued credentials; the WebSocket handshake uses the same token.

Example API request:

```sh
curl -sS -X POST http://127.0.0.1:8787/_fastdog/onboard/zones \
  -H "x-fastdog-token: $AGENT_TOKEN" -H 'content-type: application/json' \
  -d '{"zone":"example.com","edge_ip":"157.230.57.32","invite_code":"fd-<code>"}'
```

This path does not change registrar settings. The API's `hold`, `lan_only`, and `next_steps_lan` fields describe the current status. `dig_verify` starts with direct queries to both configured PoP IPs; public `dig` and `+trace` are reference checks and may fail while delegation is on HOLD. The [operator dashboard](operator-ui.md) follows the same flow.

## Public NS status: HOLD

- Fastdog and customer registrar nameservers remain unchanged. The proposed `ns1.fastdognetworks.com` / `ns2.fastdognetworks.com` values are a preview, not an instruction to flip. See `deploy/NS_CUT.md` for the separate future cut checklist.
- LAN dogfood is the primary demo: invite → local zone → optional direct PoP dig verification → issue credential → map host → run agent → `curl -H 'Host: app.demo-customer.test' http://127.0.0.1:8787/`.
- If direct `dig @NS1_IP` or `dig @NS2_IP` fails, report DNS verification as blocked. Continue only with the independent LAN Host-header demo; do not claim the zone is published.

## LAN try (server3)

```sh
cd ~/projects/fastdog-edge
cp -n .env.example .env
npm test
npm start   # terminal A: edge :8787

# terminal B
npm run onboard -- generate-invite --note demo
npm run onboard -- create-zone demo-customer.test --invite '<invite-code>'
npm run onboard -- ns-instructions demo-customer.test
# If already served, run the returned direct dig @NS1_IP and @NS2_IP +norecurse checks.
# A failed dig means DNS verification is blocked; registrar NS stays on HOLD.
npm run onboard -- issue-credential --name demo --hostname app.demo-customer.test
# save issued AGENT_TOKEN privately; it is shown once
npm run onboard -- map-host demo-customer.test app.demo-customer.test --origin-hint http://127.0.0.1:9999
curl -sS -X POST -H "x-fastdog-token: $AGENT_TOKEN" http://127.0.0.1:8787/_fastdog/routes/reload

# terminal C: mock origin + agent
node scripts/mock-upstream.js
AGENT_TOKEN='<issued-token>' AGENT_HOSTNAME=app.demo-customer.test AGENT_LOCAL_UPSTREAM=http://127.0.0.1:9999 npm run agent

curl -sS -H 'Host: app.demo-customer.test' http://127.0.0.1:8787/
```

## CoreDNS sync status (HOLD)

After `create-zone` and `map-host`, the control plane records a skipped sync in its audit log. No PoP changes are part of this LAN flow.

**Required for this track:** `COREDNS_SYNC_ENABLED=false`. Sync is skipped, an audit line is written, and onboarding still succeeds. Apex A remains **opt-in** (`--edge-ip` / `edge_ip` only).

### Audit log

Structured JSONL at `DATA_DIR/audit/coredns-sync.jsonl` (or `COREDNS_AUDIT_LOG`): `ts`, `zone`, `action`, `pops`, `success`, `error`, `dry_run`.

Shared `AGENT_TOKEN` is Phase 1 operator admin for onboarding API calls. Keep it private; customer tunnel credentials are issued separately with `issue-credential`.
