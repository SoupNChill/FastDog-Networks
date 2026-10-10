# Self-serve portal

Standalone Node 18/20 service, built from Node built-ins. No install or build step
is needed for this directory. The listener binds only to `127.0.0.1`. Put an HTTPS
reverse proxy on a separate portal origin before using browser sessions.

From the repository root:

```sh
npm run test:portal
node portal/server.js
```

From this directory, `npm test` and `npm start` are equivalent. Tests use a fixed
clock, fake mailer/edge, local servers on port 0 and temporary directories inside
`portal/test`, removed afterward. They make no DNS or external network calls.

## Configuration

The starter reads process environment only; it never opens an environment file.

| Variable | Meaning |
| --- | --- |
| `PORTAL_ORIGIN` | Required exact HTTPS origin, without a trailing slash |
| `STATE_DIRECTORY` | Required private state directory; one running writer |
| `PORTAL_KEY` | Required internal edge key, at least 32 characters |
| `PORTAL_PORT` | Loopback port, default `8790` |
| `EDGE_INTERNAL_URL` | Internal service base URL, default `http://127.0.0.1:8789` |
| `DOMAIN_SEARCH_URL` | Search base URL, default `http://127.0.0.1:8791` |
| `OUTBOX_DIR` | Private outgoing message directory; defaults to state directory `/outbox` |
| `DEFAULT_PLAN` | Default operator-assigned plan text, default `assigned` |
| `DEFAULT_HOSTNAME_LIMIT` | Default integer limit 1–1000, default `3` |
| `TRUST_PROXY` | `1` trusts a single IP in `X-Forwarded-For` from the loopback peer |

When enabling proxy trust, the proxy must replace incoming forwarded headers
with the direct client IP. With trust disabled, all proxied clients share the
loopback IP's limits. The portal never holds the operator credential.

## Factory and browser authentication

`src/app.js` exports `createApp({dataDir, edge, mailer, domainSearch, now, config})`,
returning an unstarted `http.Server`. The edge methods and dependency signatures
match the shared contract. Tests call `.listen(0, '127.0.0.1')`.

`config` accepts `origin` (also `portalOrigin`), `defaultPlan`,
`defaultHostnameLimit`, `outboxDir`, `trustProxy`, `notificationTo` and an optional
`logger`. The factory's synthetic default origin is `https://portal.example.test`;
the production starter requires `PORTAL_ORIGIN` explicitly. Log entries contain
only method, route template, status and duration. There is no request logging by
default in the factory.

Start with `GET /api/me`. Without an authenticated account it returns
`{email:null, tenant:null, email_verified:false, csrf}` and sets an anonymous
session cookie. This bootstrap lets **every** non-GET, including signup and
login, require the exact Origin plus `x-fd-csrf`. Login replaces the anonymous
session; fetch `/api/me` again for the new CSRF token. It returns
`{email, tenant:{id,plan,hostname_limit}, email_verified, csrf}` after login.
Unauthenticated protected routes return `401 {error:"unauthorized"}`.

All state-changing browser calls must send the session cookie, the configured
Origin, and `x-fd-csrf`. The secure cookie deliberately does not work over ordinary
HTTP in a browser. Passwords require 12–1024 characters and must not be on the
short common-password list. Signup replies `{ok:true}` for invalid invitations,
existing accounts, and successful requests. Login uses identical `unauthorized`
errors for unknown accounts and incorrect passwords. Verification is required
before adding hostnames, verifying DNS, rotating credentials or requesting names.

Email messages have `{to,kind,link}`. Verify/reset tokens are 32 random bytes,
one-time, expire in one hour and are stored only as hashes. Links carry tokens
in the fragment. The login page removes the fragment and submits the token in a
JSON body with CSRF protection. File mail contains the actual link so the
operator can deliver it by hand; treat the outbox as private. Password reset
revokes all sessions. Session hashes expire after 14 idle days and at 90 days
absolutely. Account versions also reject sessions left behind by an interrupted
reset operation.

## Invitations and state

Mint an email-bound invitation with the operator CLI. The code goes to stdout
once, and only its hash is stored. Arguments after the email are optional.

```sh
node portal/bin/mint-invite.js user@example.com assigned 3
```

Set `STATE_DIRECTORY` in the operator process environment first. A fourth
argument can specify an ISO expiry; the default is seven days. Run the CLI while
the service is stopped: all state access assumes a single writer process. No
invite listing or minting endpoint is exposed to browsers.

State files use atomic replacement and mode 0600 in a mode-0700 directory:

- `accounts.json`: `users`, `tenants`, `invites`, `links` arrays. Grouping the
  identity data lets signup and invite redemption commit atomically together.
  User fields include `id`, `tenant_id`, `email`, `password_hash`,
  `email_verified_at`, `auth_version`. Tenant fields include `id`, `name`, `plan`,
  `hostname_limit`, `status`. Set `status` to `active` for enabled tenants.
- `sessions.json`: session hashes, user ID, CSRF, account version, creation,
  last-seen and expiry timestamps. Sessions without a user are anonymous.
- `rate_limits.json`: hashed account login counters and per-host daily rotation
  limits. Short IP/search/verification windows use bounded in-memory counters.
- `domain_requests.json`: tenant-scoped records. Create accepts `name` (or
  `domain`) and optional `quoted_price` (or `price_year`), a nonnegative decimal
  USD quote. The server assigns the tenant, ID, timestamp and `requested` status.
  List returns `{requests:[...]}`. `registered`, `rejected`, and `cancelled` are
  terminal states. Three open requests returns `400 {error:"invalid_limit"}`.
- Outbox: one private JSON file per verification/reset message and domain request
  notification. A request notification links to its portal request ID; the
  operator looks up the ID in `domain_requests.json`.

Edit plan/status/request data only with the service stopped. Tenant IDs are never
accepted from request fields. Hostname state and credentials remain authoritative
at the edge; the portal does not cache them. Returned hostname records are
filtered, and credentials appear only in verify/rotate responses. The public
pages never persist credentials in browser storage. Copy the command while it is
visible; after navigating away, use Rotate to issue a replacement.

## Integration boundaries

The edge client calls only `/internal/v1/tenants/:tid/hostnames` routes, with a
five-second total deadline and bounded response size. Upstream errors become
contract codes without upstream details. The search client performs only GET
requests to the existing search API. Its `invalid_domain` maps to
`invalid_hostname`; unknown errors map to `internal_error`.

The portal applies search limits of 10 anonymous or 30 authenticated requests per
IP per ten minutes. The unchanged search service has its own stricter per-IP cap;
without a service-side trusted caller quota, that upstream cap can dominate the
portal's quotas. No registrar write operation exists here.

The origin command reads `credential.agent_env` returned by the API. Its image,
edge WebSocket URL and local upstream placeholders must be replaced with the
operator-provided values. DNS verification and agent connection are displayed
from their respective APIs. The API has no certificate status endpoint; users
open their hostname to check HTTPS and serving rather than seeing an inferred
certificate success.

Static serving is allowlisted to portal pages/JS, `/css/site.css`,
`/css/portal.css`, and the bundled fonts. Paths with traversal, double encoding,
backslashes, absolute URLs or symlink escapes are rejected. No logos, marketing
pages, state files or arbitrary repository files are served. The CSS reuses the
site's theme variables and responsive layout, with 44px controls and no animation.
