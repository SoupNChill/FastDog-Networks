# Architecture and handover

Repository review: 2026-10-12; initial handover base `5afa603`, updated against current source and operator-supplied deployment facts. This is a source-based handover, not a live audit. Start with the binding [tenant API](TENANT_API.md), then [inventory](INVENTORY.md), [decisions](decisions/README.md) and [deployment runbook](runbooks/deploy.md). Open findings remain in [DAY2_BACKLOG.md](DAY2_BACKLOG.md). No live services, DNS, secrets or environment files were inspected for this handover.

## Components and request paths

```text
Public browser -- HTTPS :443 --> Caddy (TLS, host routing, access policy)
                                  |-- static site/ (marketing, /domains)
                                  |-- portal origin --> 127.0.0.1:8790
                                  |-- domain search --> 127.0.0.1:8791
                                  |-- edge hosts ----> 127.0.0.1:8787
                                  `-- demo auth -----> Verdict :8089

Origin agent -- HTTPS register + outbound WSS --> Caddy --> edge tunnel hub
Browser --> Caddy --> edge Host router --> HTTP frames over existing tunnel
                                                --> agent --> local HTTP origin
                         `--> configured static upstream / default upstream

Browser -- session + Origin + CSRF --> portal (fdportal)
Portal -- separate PORTAL_KEY --> internal edge 127.0.0.1:8789
                                  --> routing DNS + ownership TXT verification
                                  --> tenant claim + scoped credential + host map
Caddy -- direct loopback ask --> :8789 (optional; default off, operational review required)
Operator -- SSH local forwarding --> :8788 -- operator credential --> control APIs
```

The edge (`src/edge/server.js`) is an ESM Node 18/20 application with three listeners: public HTTP/control/WebSocket on loopback `8787`, operator UI on loopback `8788`, and optional tenant API on loopback `8789`. Caddy owns public TLS. Startup requires an explicit non-development operator credential. Static routes take precedence over registered agents; unmatched traffic uses `DEFAULT_UPSTREAM` (default loopback `9999`). Do not assume an unknown Host is rejected: enforce intended Host admission in Caddy. The old README's `0.0.0.0` default is superseded by the implementation.

`agent/` registers a hostname, maintains an outbound WebSocket, retries with jittered exponential backoff and exchanges heartbeat frames. Requests and responses are buffered JSON/base64 HTTP frames; this is not a general streaming or application WebSocket tunnel. No inbound origin port is required. The deployment copy under `deploy/prod1-fastdog-agent/` is a separate template; do not assume it matches the current agent byte-for-byte.

Portal (`portal/server.js`, `portal/src/`, `portal/public/`) is a standalone built-in-only HTTP service. The handover deployment target is user `fdportal`, listener `127.0.0.1:8790`, private state `/var/lib/fastdog-portal`, and its `outbox/`. The operator inventory records unit `fastdog-portal`; the repository does not ship a portal systemd unit template. Code lives at `/opt/fastdog-portal`, with previous code at `/opt/fastdog-portal.old`. Release backups use `/root/backups/<tag>-<timestamp>/code.tgz`; rollback untars code at its recorded extraction root and restarts the unit, preserving compatible runtime state. The portal has its own invite-only login; the Caddy basic-auth gate has been removed (operator-supplied deployment fact). App pages redirect anonymous visitors to `/login`, and business APIs require an active session. Authentication, invites, tenant-scoped hostname management, agent status, domain requests and operator-assigned plans are implemented. Browser credentials are displayed once and are not stored in browser storage.

Domain search (`domain-search/`) is a separate dependency-free Node 20 service on `127.0.0.1:8791`; it alone holds registrar credentials. It supports lookup and pricing, never registration, renewal or transfer. Cache lifetime is three hours; upstream calls are capped at 300 per UTC day. `STATE_DIRECTORY/daily-count.json` persists the budget when configured (the unit uses `StateDirectory=domain-search`); cache/IP limits remain in memory. The README's blanket reset-on-restart statement predates that persistence change. Portal domain requests are an operator queue, not purchases.

Verdict (`verdict/`) is a separate bot decision service, deployed by its edge unit on `127.0.0.1:8089` (standalone default `8080`). Caddy forward-auth is the enforcement integration; it is not edge middleware. Shadow scoring tails access logs and records hypothetical actions without affecting responses. Enforce is restricted operationally to the designated demo host; guardrail hosts must never receive enforcement. See [Verdict runbook](runbooks/verdict.md).

```text
zones/*.json --> validated BIND export --> ns1 on edge: CoreDNS UDP/TCP :53
                                    `--> file copy to ns2: CoreDNS UDP/TCP :53
Recursive resolver --------------------> whichever authoritative NS is delegated

Caddy access logs --> Verdict shadow tail --> shadow.jsonl --> daily summary
Demo request --> Caddy auth --> Verdict --> allow / challenge / block
                    `-- auth error/timeout --> fail-open application handler
```

CoreDNS is authoritative DNS serving `/etc/coredns/zones/*.zone`, separate from edge DNS CRUD. ns1 shares the edge box; ns2 is DNS-only Hetzner. Sync is export/file-copy/reload, not AXFR. Updating JSON alone does not establish that either server loaded it. Historical pre-cut documents disagree about delegation and serials; [DNS runbook](runbooks/dns-changes.md) requires operator verification before changes.

`site/` is static HTML/CSS/JS with bundled fonts and assets, no build step. `/www` is an edge preview mount; public root serving is a Caddy deployment concern. `src/status/` caches health/DNS observations and can send an optional red-transition webhook. Status requests can initiate probes; they are not offline smoke tests. `src/billing/` is a separate Stripe test-only scaffold, not production portal billing.

## Data and source map

| Store or source | Contents and operational constraint |
| --- | --- |
| `config/routes.yaml`, `ROUTES_FILE` | Static upstreams and configured tunnel hosts; reload routes after edits |
| `zones/*.json`, `ZONES_DIR` | DNS control-plane source; preserve SOA/NS/mail/TXT/CAA records |
| `DATA_DIR` (default repo `data/`) | One edge writer; preserve as a coherent snapshot |
| `tenant_hostnames.json` | Pending/active/suspended claims, challenges and ownership; 0600 |
| `agent-credentials.json` | Hashed scoped tokens, ownership/revocation metadata; 0600 |
| `attached_hosts.json`, `tunnel_hosts.json` | Legacy operator attachments and dynamic routing membership |
| `invites.json` | Legacy zone invites; contains raw codes, 0600; distinct from portal invites |
| `billing-sessions.json`, `billing-accounts.json` | Test-mode billing state |
| `status.json`, `audit/coredns-sync.jsonl` | Probe cache and DNS sync audit, not proof of current live state |
| Portal `accounts.json` | Users/password hashes, tenants, invite/link hashes; atomic signup/redemption |
| Portal `sessions.json`, `rate_limits.json` | Session hashes, CSRF and persistent counters |
| Portal `domain_requests.json`, `outbox/` | Request queue and private mail links; outbox contains bearer links |
| Verdict `data/` | `keys.json`, `usage.json`, `hosts.json`, `decisions.jsonl`, `shadow.jsonl`, daily summaries, `asn/asn.bin` |
| Domain-search state directory | `daily-count.json`; retain through upgrades to preserve spend/call cap |

Portal state is 0600 under a 0700 directory. Edge JSON uses atomic file replacement, but the multi-file claim/credential/route transition is not a transactional database. Stop writers before backups or offline edits. Agent connections, edge metrics and several rate-limit windows live in memory and reset on restart. Restarting an edge drops tunnels; agents reconnect.

## Flags and defaults

| Setting | Default and effect |
| --- | --- |
| `INTERNAL_ENABLED` | Off; exactly `1` starts the tenant listener; validates separate `PORTAL_KEY` and loopback bind |
| `TLS_ASK_ENABLED` | Off; exactly `1` enables ask with internal listener; keep off pending operational review; denied asks are metered and the owner index is cached |
| `RECHECK_ENABLED` | Off; exactly `1` schedules active routing checks every six hours with internal listener; keep off pending Day 3 review; bounded inconclusive streaks and outage detection are implemented |
| `INTERNAL_TIMEOUT_CODES` | Off (internal timeouts answer legacy `400 invalid_json`); exactly `1` returns `408 request_timeout` for an incomplete body or `504 gateway_timeout` for a slow handler. Enable together with a portal that maps those codes |
| `CLAIM_CREATE_RATE_LIMIT` | Unset/`0` = off; a positive integer caps claim creates per tenant per minute (`429 rate_limited` with `retry_after`); at most 10000 tenant windows in memory |
| `COREDNS_SYNC_ENABLED` | False; opt-in Node sync after onboarding; **does not disable shell script local writes** |
| `COREDNS_SYNC_DRY_RUN` | False; set true explicitly for validation without zone writes/reloads |
| `COREDNS_SYNC_STRICT` | Off; makes onboarding CLI sync failure affect exit status |
| Portal/search `TRUST_PROXY` | Off; configure header replacement and loopback isolation before enabling |
| `VERDICT_ALLOW_BOOTSTRAP`, `VERDICT_DEMO_FORCE`, `VERDICT_EDGE_GOODBOT_DNS` | Off; production keeps bootstrap/demo forcing off and DNS off the auth hot path |
| Verdict per-host config | `enable=false`, `mode=off`, `fail=open`; shadow does not enforce |
| `INVITE_REQUIRED` | **True**, legacy zone gate; portal is independently invite-only |
| `STATUS_INTERVAL_MS` | **60000**, not off; `0` disables the timer but status requests still probe |
| `STATUS_ALERT_WEBHOOK_URL` | Unset; no alert POST unless configured |
| `EDGE_MAX_BODY_BYTES` | **52428800** (50 MiB) tunneled request-body cap; larger bodies get 413 `payload_too_large` and never reach the agent. Integer 1..73400320 (70 MiB, under the ws 100 MiB frame limit after base64), otherwise startup fails |

Other important settings: `ATTACH_TARGET`, `ALT_ATTACH_TARGET`, `EDGE_PUBLIC_IP`, `RESERVED_SUFFIXES`, `EDGE_BIND/PORT`, `INTERNAL_BIND/PORT`, `OPERATOR_BIND/PORT`, `PORTAL_ORIGIN`, `STATE_DIRECTORY`, `OUTBOX_DIR`, `EDGE_INTERNAL_URL`, `DOMAIN_SEARCH_URL`. See [portal configuration](../portal/README.md) and [internal operations](INTERNAL_API_OPS.md). Do not set an empty reserved list: its treatment is an open finding. Synthetic `example.test` examples below are documentation placeholders; the default reserved suffix policy deliberately rejects `.test` in real tenant onboarding.

## Trust boundaries and known limits

- Public clients reach Caddy, never operator/internal listeners directly. Preserve Caddy's control-route block, allowing agent registration and tunnel only where intended; edge authentication is defence in depth. Do not route portal requests through the public control API.
- Portal derives tenant identity from the session, never request fields. Every edge tenant operation is scoped again. `PORTAL_KEY` must be at least 32 characters and differ from `AGENT_TOKEN`; portal must never receive the operator key.
- Signup is invite-only; verified email gates sensitive operations. Secure/HttpOnly/SameSite cookies, exact Origin and CSRF are required. Caddy must replace forwarded headers; portal accepts only one forwarded IP from a loopback peer.
- Activation requires routing plus a per-claim TXT proof; pending claims grant no credentials. Only one active owner wins. Detach/rotate/suspension revoke old access and close tunnels. Legacy operator attachments are unavailable to tenant claims.
- DNS ownership, active claim, connected agent and working HTTPS are separate checks. There is no certificate-status API. Scheduled re-checks never restore suspended claims; explicit routing and TXT verification issues a fresh token.
- Never record secrets, bodies, cookies or query strings. The current agent still sends its token in the WebSocket query: this is a gap against the contract's no-secret-URLs rule. Query-redacted proxy logs are essential; do not copy agent URLs to tickets.
- Authentication and ownership fail closed. Verdict's fail-open policy applies only to unavailable bot filtering, not authentication, DNS proof or arbitrary origin errors. The free ASN feed is the only planned ASN source; no paid enrichment is authorized.

Older deployment examples omit authentication and TLS validation, describe a LAN bind, or suggest hostname shortcuts. Follow the contract and these runbooks instead. No deployment, registrar change, production write or new spend is authorized by this handover.
