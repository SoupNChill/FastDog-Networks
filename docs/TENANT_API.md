# Tenant API contract (portal <-> edge)

Status: **v1 contract, binding for all lanes** (A edge, B portal, D tests, E agent packaging). Changing it after merge needs a note in the PR and a rebase of every open lane. Part of [SELF_SERVE_PLAN.md](SELF_SERVE_PLAN.md). Nothing here is deployed.

Rules that apply to everything below:
- **Tenant-agnostic.** No code, config, schema, copy or test may name a specific tenant, person, product or customer host. All of it is data. Reserved names come from config, not literals.
- **No dependencies.** Node 18/20 built-ins only (`node:http`, `node:crypto`, `node:fs`, `node:dns/promises`, `node:url`, `node:test`). The edge keeps its existing `express`/`ws` deps; new modules add none.
- **No secrets in logs, URLs or git.** Tokens appear only in the response that creates them.

## 1. Services and trust boundaries

| Service | Listener | Who may call | Credential |
| --- | --- | --- | --- |
| Portal | `127.0.0.1:8790` (`PORTAL_PORT`) behind Caddy on its own hostname | Browsers | Session cookie |
| Edge internal tenant API | `127.0.0.1:8789` (`INTERNAL_PORT`, `INTERNAL_BIND` loopback only; startup fails otherwise) | Portal process only | `x-fastdog-portal-key: <PORTAL_KEY>` |
| Edge public/control API | `127.0.0.1:8787` behind Caddy | Agents, public | `AGENT_TOKEN` for operator routes |
| Operator UI | `127.0.0.1:8788` | Operator via SSH tunnel | `AGENT_TOKEN` |

- `PORTAL_KEY` is a separate random secret (>= 32 chars, checked at startup; the internal listener refuses to start if it is unset, shorter, or equal to `AGENT_TOKEN`). It lives in mode-600 env files for the portal and edge, never in git.
- **The operator `AGENT_TOKEN` is never accepted by the internal API, and `PORTAL_KEY` is never accepted on :8787 or :8788.** The portal never holds `AGENT_TOKEN`.
- Compare keys with `crypto.timingSafeEqual` on equal-length hashes. Missing/wrong key: `401 {"error":"unauthorized"}`, no detail.
- The internal listener is HTTP/1.1 JSON, `content-type: application/json`, bodies <= 16 KB, 5 s request timeout. Unknown routes: `404 {"error":"not_found"}`. Wrong method: `405`.

## 2. Identifiers and normalization

- `tenant_id`: opaque string `t_` + 20 chars `[a-z2-7]`, created by the portal, validated by the edge with `^t_[a-z2-7]{20}$`. The edge never invents or lists tenants; it only stores `tenant_id` on records.
- **Hostname normalization** (single shared function `normalizeHostname()` in `src/onboard/hostname.js`, used by edge, imported or copied verbatim by the portal): trim; strip one trailing dot; lowercase; convert IDN to ASCII with `url.domainToASCII` (punycode `xn--` labels kept); then validate: total length <= 253, each label 1-63 chars `[a-z0-9-]`, no leading/trailing hyphen in a label, at least 2 labels, last label alphabetic 2-63 chars (or `xn--` form), **no `*`, no IP literals, no ports, no paths, no whitespace/control chars**. Case variants therefore map to one host. Anything else: `400 invalid_hostname`.
- **Reserved hostnames** (`400 reserved_hostname`): any name equal to or a subdomain of an entry in `RESERVED_SUFFIXES` (comma-separated env; default = the configured `ATTACH_TARGET` registrable domain and `ALT_ATTACH_TARGET` domain, plus `localhost`, `local`, `lan`, `internal`, `test`, `invalid`, `example`). Also rejected: names that equal the attach target. No literal tenant or customer names appear in the list.
- Suffix names are distinct hosts (`app.example.com`, `myapp.example.com`, `x.app.example.com` never collide).

## 3. Hostname lifecycle

States: `pending` -> `active` <-> `suspended` -> (`detached`: record removed). `pending` expires after 24 h (`expired`, treated as absent, not shown). `suspended` expires 24 h after suspension and is then also treated as absent. Suspension revokes claim credentials; restoration requires explicit routing and TXT verification and issues a new credential. Scheduled routing checks never restore suspended claims.

Rules:
1. A hostname may have **at most one `active` owner**. Any number of tenants may hold a `pending` claim for the same name; pending claims do not block anyone.
2. Activation requires **both** proofs, checked by the edge's resolver at verify time:
   - **Routing proof:** `CNAME` (or chain <= 5) to `ATTACH_TARGET` / `ALT_ATTACH_TARGET`, or an `A` record equal to `EDGE_PUBLIC_IP` (same logic as `checkDnsVerification` today).
   - **Ownership proof:** TXT at `_fastdog-challenge.<hostname>` containing exactly the claim's `txt_value` (`fd-verify=` + 32 hex chars, random per claim).
3. On activation the edge atomically: re-checks no other tenant became active; marks the claim `active`; adds the host to `tunnel_hosts.json`; issues the credential; reloads routes. First tenant to complete this wins; others get `409 hostname_unavailable` when they next verify.
4. `DELETE` removes the claim, the tunnel host mapping and all credentials for that claim, and closes the live tunnel.
5. Legacy operator-attached hosts (records in `attached_hosts.json` without `tenant_id`) are unchanged and cannot be claimed or modified by any tenant (`hostname_unavailable`).

Per-tenant limit: the portal sends `hostname_limit` (integer 1-1000, from the plan) on create. The edge counts the tenant's non-expired `pending` + `suspended` claims plus `active` claims and returns `409 hostname_limit_reached` when full.

## 4. Edge internal endpoints

Base path `/internal/v1`. Every route except `tls/ask` and `health` requires the portal key. `:tid` must match the tenant pattern and **every read or write is scoped to it**: a hostname belonging to another tenant is indistinguishable from a missing one (`404 hostname_not_found`).

### POST `/tenants/:tid/hostnames`
Create or return the caller's pending claim.
Request: `{ "hostname": "App.Example.COM.", "hostname_limit": 3 }`
`201` (new) or `200` (existing pending claim returned unchanged, same challenge):
```json
{
  "hostname": "app.example.com",
  "status": "pending",
  "created_at": "2026-10-10T12:00:00.000Z",
  "expires_at": "2026-10-11T12:00:00.000Z",
  "dns": {
    "cname": { "name": "app.example.com", "type": "CNAME", "value": "attach.example-edge.test", "ttl": 300 },
    "txt":   { "name": "_fastdog-challenge.app.example.com", "type": "TXT", "value": "fd-verify=<32 hex>", "ttl": 300 },
    "apex_note": null
  }
}
```
(`value` for CNAME is the configured `ATTACH_TARGET`.) `apex_note` is a string for 2-label names, else `null`.
Errors: `400 invalid_hostname|reserved_hostname|invalid_limit`, `409 hostname_unavailable|hostname_limit_reached`, `429 rate_limited`.

### GET `/tenants/:tid/hostnames`
`200 { "hostnames": [ <hostname record> ... ] }`, only this tenant's non-expired records, sorted by `created_at`.

### GET `/tenants/:tid/hostnames/:hostname`
`200 <hostname record>`: `{ hostname, status, created_at, expires_at (pending only), verified_at (active only), agent: { connected, last_seen, registered_at } | null }`. Never includes `localUpstream`, token material or the TXT value after activation. `404 hostname_not_found`.

### POST `/tenants/:tid/hostnames/:hostname/verify`
No body. Runs the DNS checks now (rate limited per tenant: 6/min; at most one resolver pass per call).
`200` always when the claim exists:
```json
{
  "hostname": "app.example.com",
  "status": "pending",
  "verified": false,
  "checks": {
    "routing":   { "ok": false, "error": "cname_wrong_target", "found": "other.test", "expected": "attach.example-edge.test" },
    "ownership": { "ok": false, "error": "txt_not_found", "expected_name": "_fastdog-challenge.app.example.com" }
  }
}
```
When both checks pass: `status:"active"`, `verified:true`, `verified_at`, `method`, and a **`credential` object returned exactly once**:
`"credential": { "id": "<uuid>", "token": "<64 hex>", "agent_env": { "AGENT_TOKEN": "<token>", "AGENT_HOSTNAME": "app.example.com", "AGENT_NAME": "<hostname>" } }`.
Re-verifying an active host returns `status:"active"` with **no** credential. Check error codes: routing `no_dns_record|cname_wrong_target|a_wrong_target|dns_proxied|dns_timeout` (`dns_proxied`: the name answers only with Cloudflare proxy addresses, i.e. an orange-cloud record); ownership `txt_not_found|txt_mismatch|dns_timeout`. Other errors: `404 hostname_not_found`, `409 hostname_unavailable` (someone else activated first), `429 rate_limited`.

### POST `/tenants/:tid/hostnames/:hostname/credentials/rotate`
Only for `active` claims. Invalidates the previous credential, closes the live tunnel, returns `200 { "credential": {...same shape...} }`. `409 not_active`. Rate limited 5/day per hostname.

### GET `/tenants/:tid/hostnames/:hostname/agent`
`200 { "connected": true, "last_seen": "<iso>", "registered_at": "<iso>" }` or `{ "connected": false, "last_seen": null, "registered_at": null }`. Active claims only (`409 not_active` otherwise). Also returns `origin_reachable` (`true|false|null`; null when the agent is older than 0.1.2 or has not reported), `origin_checked_at` (`<iso>|null`) and `origin_address` (host:port of the agent's local upstream, or null). Reachability is a boolean from the agent heartbeat; no app content is sent.

### GET `/tenants/:tid/hostnames/:hostname/status`
Active claims of `:tid` only (other tenants: 404; pending: 409). Returns `{ hostname, live, reasons[], checked_at, agent, cert, traffic, verdict }`. `live` = agent connected, origin check not failing (agents that send no origin check report `origin_reachable: null`, treated as unknown, not down), and a valid unexpired certificate. `cert` comes from a loopback TLS handshake to `STATUS_TLS_ADDR` (default `127.0.0.1:443`, must be loopback) with SNI = hostname. `traffic` (24 hourly buckets, `p50_ms`, `errors_5xx`) is read from `FASTDOG_ACCESS_LOG_DIR/<hostname>.log` (default `/var/log/caddy`); `verdict` counts (`would_block`, `would_challenge`, always `shadow: true`) from `VERDICT_SHADOW_FILE`. An unreadable file yields `{ available: false }`, never an error. Probes are cached 30 s per host.

### POST `/tenants/:tid/hostnames/:hostname/test`
"Test it": one `GET /` with `Host: <hostname>` over TLS to `STATUS_TLS_ADDR` (never to an address derived from the hostname, so no SSRF), redirects not followed, body discarded, 4 s timeout. Returns `{ hostname, tested_at, ok, status, ms, error, cert }`. Rate limits: 10/min per tenant and 30/hour per host (429 with `retry_after`).

### DELETE `/tenants/:tid/hostnames/:hostname`
`200 { "hostname": "...", "detached": true }`. Idempotent for the owner after success is `404 hostname_not_found`.

### GET `/tls/ask?domain=<host>` (no key; Caddy `on_demand_tls { ask ... }`)
Loopback only. `200` with empty body iff `<host>` normalizes to an `active` tenant claim (or a legacy active attached host); otherwise `404`. Nothing else is returned, nothing is logged beyond status. Rate limit generous (Caddy calls it before issuing).

### GET `/health`
`200 { "ok": true }`.

## 5. Edge storage

- New file `tenant_hostnames.json` in `DATA_DIR`, mode 0600, written atomically (existing `writeJson` helper). Record: `{ tenant_id, hostname, status, created_at, expires_at, txt_value, verified_at, method, credential_id }`. `txt_value` is stored in the clear (it is public once published in DNS); tokens are stored only as sha256.
- Credentials: existing `agent-credentials.json`; records gain `tenant_id`, `claim_hostname`, `revoked_at`, `last_used_at`. `validCredential(token, hostname)` must also reject revoked credentials.
- A tenant-owned hostname can **no longer be registered with the operator `AGENT_TOKEN`** (`registerAgent` refuses with 401 when the host belongs to a tenant claim). Legacy hosts behave as before.
- Single writer process; file writes are synchronous read-modify-write inside one tick (no awaits between read and write).

## 6. Edge control-plane hardening (lane A, defence in depth)

On :8787 the following require `x-fastdog-token: <AGENT_TOKEN>` (or `token` in the JSON body) and return `401 {"error":"unauthorized"}` otherwise: everything under `/_fastdog/dns`, plus `GET /_fastdog/agents`, `GET /_fastdog/routes`, `GET /_fastdog/metrics` and `POST /_fastdog/routes/reload`. Still unauthenticated by design: `/health`, `/status`, `/status.json`, `POST /_fastdog/agents/register` (its own token check), the WebSocket `/_fastdog/tunnel` (its own token check), `/pricing`. The operator UI and CLI already send the token; any in-repo caller of these routes must be updated in the same PR.

### Agent authentication (0.1.1)

Agent 0.1.1 sends `Authorization: Bearer <token>` on both `POST /_fastdog/agents/register` and the WebSocket upgrade to `/_fastdog/tunnel`. It never sends the credential in a URL or registration body. A present Authorization header takes precedence, even when invalid; an invalid header cannot fall back to another credential. Token comparison remains constant-time, and tenant ownership and revocation checks are unchanged.

For compatibility, registration still accepts the existing JSON `token` and `x-fastdog-token` mechanisms. The tunnel still accepts `x-fastdog-token` and the **deprecated, temporary** `?token=` fallback for 0.1.0 agents. Remove query authentication only after all agents run 0.1.1 or later. Never log Authorization, query strings, or credentials, including on rejected requests. Proxy access logs must continue dropping queries and authentication headers.

## 7. Portal (browser-facing) API summary

All JSON, same-origin, `__Host-fd_session` cookie, `Origin` check and `x-fd-csrf` token on every non-GET. Errors use the same `{ "error": "<code>" }` shape.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/signup` | `{email, password, invite_code}` -> sends verification link; generic response |
| POST | `/api/verify-email` | `{token}` |
| POST | `/api/login` / `/api/logout` | session create/destroy; identical failure for unknown email and wrong password |
| POST | `/api/password-reset` and `/api/password-reset/confirm` | request / complete |
| GET | `/api/me` | `{email, tenant:{id, plan, hostname_limit}, csrf}` |
| GET/POST | `/api/hostnames` | list / add (portal calls edge create with the tenant's `hostname_limit`) |
| POST | `/api/hostnames/:hostname/verify` | proxies to edge verify; returns `credential` once |
| POST | `/api/hostnames/:hostname/rotate` | edge rotate |
| DELETE | `/api/hostnames/:hostname` | edge detach |
| GET | `/api/hostnames/:hostname/agent` | connected indicator |
| GET | `/api/hostnames/:hostname/status` | live status page (allow-listed fields; 60/min per tenant) |
| POST | `/api/hostnames/:hostname/test` | Test it (CSRF; 6/min per tenant) |
| GET/POST/DELETE | `/api/hostnames/:hostname/connect-token` | list / issue (CSRF, verified, active host, 5/hour per tenant) / revoke all 1-hour connect tokens for the AI-assistant prompt |
| GET | `/api/connect/v1/hostname` | Bearer connect token only (cookies ignored): one hostname's connection status |
| POST | `/api/connect/v1/command` | Bearer connect token only: `{origin, platform: linux|docker}` returns the connect command once per token (rotates the credential; own budget of 3/day per hostname plus the shared 5/day rotate limit; a failed rotate does not consume the token, but every attempt that reaches the edge spends budget). Every bearer call re-checks that the hostname is still the tenant's active claim (404 revokes its tokens) and that the issuing user has not reset their password |
| GET | `/api/domains/search?q=` | existing domain-search service (unchanged) |
| GET/POST | `/api/domain-requests` | list / create a request (max 3 open); no registrar write path |
| GET | `/api/plan` | operator-set plan and limits |

The portal derives `tenant_id` from the session only. It never accepts a tenant id or hostname-owner field from the browser. Rate limits (per section 3 of the plan): login 5 fails/15 min/account, 20/IP; signup 3/h/IP; verify 6/min/tenant; rotate 5/day.

### Docker connect command: security notes

- Token handling: the command writes `fastdog-agent-<slug>-<10 hex>.env` (umask 077, only after `docker pull` succeeds) with shell builtins only (`printf`), so no subprocess argv carries the token. An AI assistant must write the command to a 0600 file, run it with `sh <file>`, and delete the file and the exact env file named in the command (never a glob) afterwards (success or failure); it must never print them, run `docker inspect` on the agent container, read `ps` or `/proc/*/cmdline`, or echo the token.
- Residual exposure: Docker stores `--env-file` values in the container config, so the token stays readable by root and anyone in the docker group (`docker inspect`). Docker group access is root-equivalent; use Docker only when the user already has it without sudo, never add users to the group, and otherwise use rootless Docker or the root systemd installer. If the token may have been exposed, rotate it by getting a new command in the portal (the old one stops working).
- Host networking: the container uses `--network host` so the agent reaches origins on the host's `127.0.0.1`. Trade-off: the agent shares the host network namespace and can reach any host-local or LAN service. Mitigations: `--cap-drop ALL --security-opt no-new-privileges`, and origins in link-local 169.254.0.0/16 (cloud metadata) , fe80::/10 or AWS IPv6 metadata fd00:ec2::/32 are rejected (`400 invalid_origin` with a `message`).
- Naming: container and env file use `fastdog-agent-<sanitised host, max 40>-<first 10 hex of sha256(lowercase hostname)>`, so `a-b.example.test` and `a.b-example.test` never collide. Order: `docker pull`, then write the env file, then `docker rm -f`, then `docker run`, so a failed pull keeps the running agent and leaves no token file.

### Scoped API keys (v1)

See `docs/decisions/2026-10-16-scoped-api-keys.md`. Session routes (CSRF, verified email, any paid plan): `GET /api/keys` (list, recent use), `POST /api/keys` `{name?, scopes[], hostnames?[], expires_in_days? (1-90, default 30), password}` returns the `fdak_` secret once, `DELETE /api/keys/:id` revokes. Bearer-only routes (cookies ignored): `POST /api/v1/hostnames` (`hostnames:create`), `GET /api/v1/hostnames/:hostname` (`status:read` or `hostnames:create`), `POST /api/v1/hostnames/:hostname/verify` (`hostnames:create`, never returns a credential), `GET /api/v1/hostnames/:hostname/status` (`status:read`), `POST /api/v1/hostnames/:hostname/connect` (`connect`, active hostnames only, 3/day per hostname on top of the shared 5/day rotate limit). No delete over the API. Errors: `forbidden` 403 (scope or allow-list), `plan_required` 403, `password_required` 403, `invalid_key` 400, `key_limit_reached` 409 (10 live per tenant). Limits: 60/min per key, 300/10 min per IP, 5 creations/hour per tenant. Audit: key id, tenant, scope, route template, method, status (capped per tenant).

## 8. Error codes

`unauthorized` 401 · `not_found` 404 · `hostname_not_found` 404 · `method_not_allowed` 405 · `invalid_hostname` 400 · `reserved_hostname` 400 · `invalid_limit` 400 · `invalid_tenant` 400 · `invalid_json` 400 · `payload_too_large` 413 · `hostname_unavailable` 409 · `hostname_limit_reached` 409 · `not_active` 409 · `rate_limited` 429 (with `retry_after` seconds) · `internal_error` 500 (generic, no detail). Errors never echo secrets or full upstream details.

## 9. Logging (edge and portal)

Log method, route template (not raw path with identifiers), status, duration, and a /24 (IPv4) or /48 (IPv6) truncated client IP at most. Never log query strings, request/response bodies, `Authorization`/cookie/token headers, TXT values, credentials or tenant emails.

**Caddy per-host access logs** (lane A, snippet only, not applied): `deploy/caddy/access-logs.snippet` defines a reusable `(fdlog)` snippet using Caddy's JSON log with a filter that drops the query string, keeps only `request.method`, `request.uri` path, `status`, `duration`, truncated `client_ip` (`ip_mask { ipv4 24; ipv6 48 }`), deletes all request/response headers (`request>headers`, `resp_headers`, `request>tls`) and cookies, rolls at 5 MiB, keeps 5 files (`roll_size`, `roll_keep`, `roll_keep_for`). Intended for `edge.`, `attach.` and every customer host block.

## 10. Test fixtures (shared)

Synthetic tenants only: `t_aaaaaaaaaaaaaaaaaaaa`, `t_bbbbbbbbbbbbbbbbbbbb`, `t_cccccccccccccccccccc`. Hostnames only under `example.com`, `example.test`, `*.invalid` and the configured fake attach target. Awkward set used by every isolation test: 63-char label; 253-char total; `xn--bcher-kva.example.com` and `bücher.example.com` (same host); `App.Example.COM` / `app.example.com.`; `*.example.com`; `a*.example.com`; `app.example.com` vs `myapp.example.com` vs `x.app.example.com`; an IP literal; a reserved-suffix name. Every endpoint is exercised as every other tenant and must behave as `hostname_not_found`.

CI grep check (`test/no-hardcoded-names.test.js`): fails if any file under `portal/`, `src/onboard/`, `src/control/`, `src/edge/`, `test/`, `deploy/caddy/` contains (case-insensitive) a deny-list entry, except files in `test/no-hardcoded-names.allow.json`. The deny-list is a data file (`test/deny-names.json`) and covers the person, product and customer names used so far. The test file itself reads the list and never spells the names.
