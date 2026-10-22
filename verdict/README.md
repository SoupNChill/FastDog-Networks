# Verdict 0.2.2

Threat decision API: `allow`, `challenge`, or `block`. Node 18+.

```sh
npm ci
npm test
npm start
```

Defaults to `127.0.0.1:8080`. Environment variables must be exported (Node does not automatically load `.env`). See [edge deployment](deploy/EDGE.md) for PoP installation artifacts and Caddy configuration. No deployment is performed by these files.

## API

| Route | Authentication / result |
| --- | --- |
| `GET /health`, `/openapi.json` | Public health/schema; health version comes from package.json |
| `GET /metrics` | Bearer-protected JSON; use a read-only key for loopback scraping |
| `POST /v1/keys` | First key: socket loopback OR `VERDICT_ALLOW_BOOTSTRAP=1`; otherwise `403 bootstrap_disabled`. Once any key exists, requires bearer auth (`401` otherwise). Returns plaintext once. |
| `POST /v1/keys/:id/revoke` | Bearer auth; soft revoke, `200 {ok:true}` or `404`. Any active key can manage keys. Revoking all keys does not reopen bootstrap. |
| `POST /v1/decide` | Bearer auth; decision and request ID |
| `GET /v1/usage` | Bearer auth; persistent usage for calling key |
| `GET /v1/edge-auth` | Public local heuristic; allow `200` empty, challenge `401` with `Location` and `X-Verdict-Action`, block `403`. `Accept: application/json` returns decision JSON with the same status. |
| `GET /demo` | Branded phone demo; tap links enabled only with `VERDICT_DEMO_FORCE=1` |
| `GET /challenge` | FastDog PoW page with accessible no-JS form; safe relative `?next=/path` only |
| `GET /challenge/issue` | Single-use PoW challenge JSON; optional signed `hint` |
| `POST /challenge/verify-fallback` | Demo-host-only signed arithmetic form; production requires PoW |
| `POST /challenge/verify` | Verify `{challenge_id, nonce}` (nonce is a decimal string); clearance cookie and `{ok:true,next}` |

Seed on loopback before exposing a reverse proxy. Capture the first key securely as described in EDGE.md; do not print it. On the edge the real key lives in `/etc/fastdog/verdict.env`. Examples below use the literal placeholder `KEY`:

```sh
curl http://127.0.0.1:8080/v1/decide \
  -H 'Authorization: Bearer KEY' -H 'Content-Type: application/json' \
  -d '{"path":"/login","method":"GET","ua":"Mozilla/5.0"}'
curl http://127.0.0.1:8080/v1/usage -H 'Authorization: Bearer KEY'
curl -X POST http://127.0.0.1:8080/v1/keys/KEY_ID/revoke -H 'Authorization: Bearer KEY'
curl http://127.0.0.1:8080/v1/edge-auth \
  -H 'Accept: application/json' -H 'User-Agent: headless' \
  -H 'X-Forwarded-Uri: /login' -H 'X-Forwarded-Method: GET'
```

Decide accepts a structured object or `{ "state": {...} }`. Legacy string state is accepted but carries no local risk signals. `local_heuristic_v3` returns `action`, `confidence`, risk `score`, primary `reason`, fired signal IDs in `reasons`, `engine`, and `request_id`. Risk starts at 0.2; thresholds remain >=0.45 challenge and >=0.75 block (capped at 0.99). Allow confidence is 1 minus risk; challenge/block confidence is risk.

Signals: malicious tools +0.55; headless automation +0.25; sensitive POST/automation actions +0.1; prior score times 0.25; account age under one hour +0.1. Probe paths (`wp-login`, `xmlrpc.php`, `.env`, `.git`, `phpmyadmin`, `pma`, `wp-admin`) add +0.55, including percent-encoded paths. Ordinary browser GETs to `/login` and `/api/health` allow.

Headers are case-insensitive. An explicitly supplied headers object missing Accept-Language adds +0.1; absent header context is unknown. Supply `headers._order`, `headers.header_order`, or top-level `header_order` as a complete array of header names. Duplicate/missing entries add +0.1; reversal of the common relative User-Agent → Accept → Accept-Language order adds +0.1. This is a weak baseline because browsers and proxies differ. Contradictory browser brands or Chromium major versions and mobile client hints each add +0.2; disagreement between `ua` and User-Agent adds +0.1. Unknown client-hint brands are ignored.

In-memory 60-second velocity windows add +0.2 after 30 requests per IP and +0.2 after 300 requests per ASN. ASN velocity only applies when `asn` is supplied in the decide body (numeric or `AS123` form). There is no bundled free local ASN database, no automatic ASN lookup, and no paid feeds. Counters reset on process restart and are not shared between workers. JA3 is accepted context without a scoring rule.

Claimed bots first match published IPv4/IPv6 ranges in memory, allowing with `verified_good_bot` before any DNS or risk signals. Google UAs (case-insensitive word boundaries): Googlebot, Google-Extended, GoogleOther, Storebot-Google, Google-InspectionTool, GoogleProducer; Bing: bingbot. The tiny built-in bootstrap seed covers only `192.178.6.0/24` and `66.249.72.0/24`; install the refresh job for full coverage. `VERDICT_BOT_RANGES_FILE` defaults to `bot-ranges.json` under `VERDICT_DATA_DIR` (default `data`, relative to the process working directory). The version-1 format is `{ version: 1, updated_at: "ISO timestamp", sources: ["source URL"], bots: { google: ["CIDR"], bing: ["CIDR"] } }`. Sorted, merged intervals use binary search, with file metadata checked at most once per second. Missing/invalid files retain the last valid snapshot, or the bootstrap seed before the first successful load; valid empty lists replace the seed.

Outside published ranges, forward-confirmed reverse DNS remains the fallback: `.googlebot.com` or `.search.msn.com`, 200ms deadline, one-hour result cache. Failed verification adds `spoofed_good_bot`; timeout adds `good_bot_dns_timeout`. Edge and shadow default to DNS off (`VERDICT_EDGE_GOODBOT_DNS=0`), so unmatched claims instead receive `good_bot_pending`. `/v1/decide` retains its DNS fallback. Non-bot requests never consult lists or DNS. Shadow scoring returns a row synchronously with DNS off, or a promise when DNS is needed; callers should await it. See [refresh and rescore instructions](deploy/EDGE.md#published-bot-ranges).


Decide is limited per key AND socket IP. Forwarded headers cannot spoof this limiter; behind a local proxy its IP bucket is shared by callers. Invalid bodies return 400; exceeded limits return 429 and `Retry-After`. Hashed keys persist on mutation. Usage updates in memory immediately and persists in batched one-second snapshots; graceful shutdown drains pending usage and decision writes. Abrupt termination can lose recent usage and queued logs. Decisions queue fire-and-forget serialized writes; neither route waits for disk. Log errors are reported to stderr without failing auth. Decisions append only request ID, action, reason, engine, IP, pathname, key ID and timestamp to JSONL. Queries/fragments are removed; never put secrets in path segments. The decision log truncates before an append would exceed 5 MiB or when its oldest entry reaches 7 days. No archives accumulate. Retention runs on writes, so an idle file is cleaned on the next decision; age is recovered from the first record after restart. A record larger than the byte ceiling is skipped. Use a single process per log file.

## Configuration

| Variable | Default |
| --- | --- |
| `PORT`, `VERDICT_BIND` | `8080`, `127.0.0.1` |
| `VERDICT_ALLOW_BOOTSTRAP` | `0`; `1` permits remote first-key bootstrap |
| `VERDICT_KEY_FILE`, `VERDICT_USAGE_FILE` | `data/keys.json`, `data/usage.json` |
| `VERDICT_DECISION_MAX_BYTES`, `VERDICT_DECISION_MAX_AGE_DAYS` | `5242880` (5 MiB), `7`; `0` disables that limit, invalid/negative values fail startup |
| `VERDICT_DECISION_FILE` | `decisions.jsonl` beside usage file (normally `data/decisions.jsonl`) |
| `VERDICT_RATE_LIMIT_WINDOW_MS` | `60000` for both limiters |
| `VERDICT_RATE_LIMIT_MAX`, `VERDICT_IP_RATE_LIMIT_MAX` | `60` per key, `120` per socket IP |
| `VERDICT_CLEARANCE_SECRET` | Unset; challenge routes return 503 without it |
| `VERDICT_CLEARANCE_TTL_SECONDS` | `300` |
| `VERDICT_DEMO_FORCE` | `0`; `1` enables `X-Verdict-Force` and original-URI `?verdict=allow\|challenge\|block` (demo only) |
| `VERDICT_EDGE_GOODBOT_DNS` | `0`; `1` opts edge-auth into DNS verification |
| `TYPESAFE_API_KEY` | Unset; no external calls unless configured |
| `TYPESAFE_BASE_URL` | `https://api.typesafe.ai` |

Edge auth always uses the local heuristic, even if TypeSafe is configured. Decide optionally uses Jev with local fallback; Googlebot/Bingbot claims always use local DNS verification. Jev responses include confidence without a local risk score. Tests mock Jev and need no paid credentials; run them with `TYPESAFE_API_KEY` unset.

## Edge trust and proof-of-work

Caddy supplies `X-Forwarded-Method`, `X-Forwarded-Uri`, `User-Agent` and a sanitized `X-Forwarded-For` (rightmost IP), with `X-Real-IP` as fallback. `X-Original-Method`/`X-Original-Uri` are also accepted. Without original method/URI headers the GET auth request and `/` are used. Edge auth passes all visible headers, including User-Agent, Accept-Language and client hints, into the heuristic. Proxy-observed header order is not assumed to be original browser order. Edge headers are trusted assertions: keep Verdict loopback-only and overwrite client-provided forwarding headers in the proxy.

The self-hosted challenge uses no third-party captcha or external assets. `GET /challenge/issue` returns a random `challenge_id`, `difficulty` and `expires_at` (Unix milliseconds). A same-origin Web Worker finds a decimal nonce such that SHA-256 of `challenge_id + ':' + nonce` has at least `difficulty` leading zero bits. `POST /challenge/verify` checks the proof on the server before granting clearance. Serve on HTTPS. Failure/expiry offers retry and an accessible form; the worker stops when leaving the page.

Edge-auth includes a signed, two-minute score hint in its challenge Location, bound to host, IP, UA and the safe return path. Difficulty is 16 bits below 0.45, 18 at 0.45, 20 at 0.65 and 22 at 0.75 or above (increments are not cumulative). Unsigned score parameters are ignored; direct challenges use 16 bits. Altered, expired or mismatched hints fail closed. A valid clearance bypasses the decision engine; explicit demo force overrides clearance when enabled.

Pending challenges are browser-bound, single-use and expire after two minutes. Verification attempts with a valid challenge identity consume it even if the answer is wrong. Issuance is limited to 30 per IP prefix per two minutes, with a 10,000-entry pending cap and opportunistic expiry cleanup. The HTML form also consumes an issuance slot. Restarting clears pending challenges. Multiple processes/replicas require sticky routing for issue and verification; the in-memory store is not shared. Apply edge request limits as well.

The `fd_verdict_clearance` cookie signs the exact payload `exp.host.ipprefix.uahash` with HMAC-SHA256. Its wire format is `base64url(payload).base64url(hmac)`. Host is the lowercased, trimmed `X-Forwarded-Host` (otherwise Host), including port if present. IPs normalize to IPv4 /24 or IPv6 /64; IPv4-mapped IPv6 uses the IPv4 prefix. UA hash is the first eight hex characters of SHA-256 of the User-Agent. There are no wildcard clearances. All three bindings and expiry must match; old 0.2.0 cookies are invalid. TTL defaults to 300 seconds, with `HttpOnly; Secure; SameSite=Lax; Path=/`. Use a strong random `VERDICT_CLEARANCE_SECRET`, shared by auth and challenge handlers. Keep forwarding headers sanitized, including `X-Forwarded-Host`, and serve the challenge on the protected hostname.

On `verdict-demo.fastdognetworks.com` only, the accessible form posts to `/challenge/verify-fallback` using a signed two-minute arithmetic puzzle, an explicit confirmation checkbox, a hidden honeypot and a minimum two-second completion time. It is single-use and browser-bound, but **weaker than PoW**: automated clients can solve arithmetic without comparable computation. It is an intentional accessibility escape hatch, not equivalent bot protection. On other hosts the form is hidden and its verification endpoint rejects requests; PoW is required. The page ships FastDog logos and local CSS in `public/branding/`; Space Grotesk and Mulish use system fallbacks when fonts are not installed. Demo force must remain off in production.

## Local operations

```sh
node bin/verdict-keys.js create edge-client
node bin/verdict-keys.js list
node bin/verdict-keys.js revoke KEY_ID
```

The CLI uses `VERDICT_KEY_FILE` (default `data/keys.json`, relative to the working directory). Create prints only the plaintext key once to stdout; capture it securely. List prints only ID, name, creation and revocation timestamps, never hashes or plaintext. Run mutations while the server and other key writers are stopped, then restart: the server caches keys in memory. For immediate changes on a running server, use the authenticated key API.

`GET /metrics` returns process-lifetime `requests_total` (all completed HTTP responses), `actions` (completed decisions), and endpoint totals for `/v1/decide` and `/v1/edge-auth`, including errors and rate limits. Each endpoint retains its last 2,048 response latencies in milliseconds, with p50/p99 and cumulative histogram buckets for that recent window. Empty percentiles are null. Metrics reset on restart, contain no key/IP labels, and require a valid bearer key, including read-only panel keys. Keep this route private in the reverse proxy. The scrape itself enters the request total after its response finishes.

Decide retains `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` and the corresponding `X-IP-RateLimit-*` headers; rejected limits also return `Retry-After`. A rejection by the first (IP) limiter does not run the key limiter.

```sh
node scripts/fp-replay.js
PORT=8080 VERDICT_API_KEY=KEY CONCURRENCY=50 node scripts/load-test.js
```

Replay evaluates 536 good and 240 bad request fixtures with mocked reverse/forward DNS and no external or paid calls. It prints allow/challenge/block counts, FP (good → challenge/block), and FN (bad → allow); it fails when FP exceeds 1% or FN exceeds 5%. Fixtures cover browser families on desktop/mobile, language and matching hints, legitimate API clients, verified bots, malicious tools, probes, credential stuffing and spoofed bots. These are synthetic regression results, not production accuracy estimates.

The load script runs for 30 seconds, splits requests between decide and edge-auth, defaults to 50 concurrent requests (configurable 1–200), and prints per-endpoint requests/sec, p50/p99 of the latest 2,048 latencies, transport errors and HTTP status counts. `TARGET` can override the default `http://127.0.0.1:$PORT`; only literal loopback HTTP origins are accepted. Public addresses, all hostnames (including localhost), and redirects are refused. Use a dedicated local server started with `TYPESAFE_API_KEY` unset to prevent spend. Default rate limits will produce 429s; raise both rate-limit maxima on that isolated server when measuring decision throughput. In-flight requests are aborted at the 30-second deadline and included in transport errors and latency samples; rps counts all attempts. The script does not change server configuration.

## 0.2.2 latency and phone demo

Caddy's `dial_timeout 50ms` covers TCP setup only; `response_header_timeout 200ms`
covers waiting for the auth response headers. Dial failures, auth 5xx, and auth
timeouts fail open in the [demo configuration](deploy/EDGE.md). Edge-auth skips DNS
by default. With `VERDICT_EDGE_GOODBOT_DNS=1`, claimed-bot verification has a 200ms
DNS deadline and can exceed the proxy's 200ms response timeout after overhead,
causing fail-open. `/v1/decide` can still verify claimed bots; optional Jev calls
also exceed the local hot-path budget. Leave `TYPESAFE_API_KEY` unset for local-only operation.

On the isolated demo instance enable `VERDICT_DEMO_FORCE=1` and visit
https://verdict-demo.fastdognetworks.com/demo. Its three tap links point to
`/?verdict=allow`, `/?verdict=challenge`, and `/?verdict=block`; for example,
https://verdict-demo.fastdognetworks.com/?verdict=challenge.
The documented proxy exempts `/demo`, `/branding` and `/challenge*` from auth,
then authenticates `/` and serves the demo page on allow. The force header still
works. Forced challenges strip `verdict` from the return URL to avoid a loop.
Keep demo force off on production instances.

```sh
node scripts/bench-hotpath.js
TARGET=http://127.0.0.1:8089 RPS=100 SECONDS=30 PATHS=/v1/edge-auth node scripts/load-step.js
```

The benchmark starts a temporary in-process app with real loopback HTTP and disk
logging, disables paid calls and rate limits, warms up each route, and prints p50/p99
for 1,000 calls per route. It asserts p99 <25ms (goal <15ms on a quiet machine);
noisy CI warns instead. The stepped harness sends at a steady configured rate;
run successive invocations with increasing RPS. It accepts only literal loopback
HTTP origins and the two decision paths, forbids redirects, and needs
`VERDICT_API_KEY` when PATHS includes `/v1/decide`. Disable the server's paid engine
before testing decide. Output includes offered/achieved launch RPS, milliseconds
p50/p99, transport plus HTTP >=400 errors, and status counts. Missed scheduling
slots are skipped, with at most 2,000 in-flight requests and a five-second request
timeout; slow responses drain after the measured launch interval.


## 0.3.1 security boundaries

- API and read-only panel credentials share the SHA-256/timing-safe key store; the panel has no session-cookie authentication. The server defaults to `127.0.0.1`. `/metrics` now requires a bearer key.
- Loopback Caddy is a trusted peer. It must overwrite `X-Forwarded-Host`, `X-Forwarded-For`, `X-Forwarded-Uri` and `X-Forwarded-Method`; strip client `X-Verdict-Demo`/`X-Verdict-Force` on non-demo sites. Direct remote clients cannot select a forwarded tenant or IP. Local processes can impersonate the proxy, so keep the listener private.
- Demo force additionally requires the canonical demo hostname, loopback peer and injected demo marker. Denylisted hosts always receive an allow response from edge auth; explicit off/disabled/shadow configurations never enforce. Unconfigured hosts retain heuristic behavior for existing manually configured integrations.
- Forwarded hostnames use strict ASCII DNS labels, case folding, optional port removal and a single terminal dot. Invalid authorities are rejected. Valid IDNA A-labels represent distinct DNS names; Unicode/percent-encoded authority tricks are rejected.
- Keys and host config files are bounded to 1 MiB, read without following final symlinks, and replaced atomically with mode 0600. Keep their parent directories operator-owned and mode 0700; directory replacement by an attacker with local write access is outside this boundary. Key creation intentionally returns a credential once; do not route that output to logs.
- Proxy/origin-bearing bootstrap requests are rejected unless bootstrap is explicitly opted in. Seed keys locally before publishing; retain the public proxy's key-creation denial.
- JSON requests are capped at 256 KiB, 32 levels and 10,000 traversed values; individual headers at 8 KiB (Node also caps aggregate headers). Rate/velocity/DNS cache state and pending decision-log work are bounded. Under saturated log queues, new decision log records are dropped while metrics continue.
- `scripts/caddy-apply-hosts.js` generates snippets only. `--apply` now fails before writes; automatic shell execution, imports, reloads and live probes have been removed. Review generated snippets and perform validation/reload through your normal operator workflow. Do not directly import the generated output directory into a live config.

### First-party shadow retention

`shadow-tail.js` and `createShadowWriter` retain timestamped `shadow.jsonl` rows for
30 days by default. `VERDICT_SHADOW_MAX_AGE_DAYS` overrides this; `SHADOW_RETENTION_DAYS`
is an alias used when the primary variable is unset. Invalid or empty values use
30 days; values below 7 are clamped to 7 for false-positive watch history.
Expired or malformed/undated rows are removed by atomic 0600 replacement, checked
on startup and at most once per minute while the tailer runs (including idle polls).
`VERDICT_SHADOW_MAX_BYTES` defaults to 10 MiB; 0 disables the size cap. Before an
append exceeds the cap, age trimming runs first, then oldest timestamps are dropped
until the new row fits. The size cap may evict rows younger than seven days when
necessary. A single oversized row is skipped without evicting history.

Daily summary writes prune `shadow-summary-YYYYMMDD.json` using the same retention
setting and the UTC date in each filename. I/O failures warn and remain fail-open;
failed trims can temporarily exceed retention/size limits until storage recovers.
Use one writer process per shadow file; writes within a writer are serialized.
Decision-log retention is unchanged.

Stored rows keep IPv4 as /24 and IPv6 as /48 (live rate-limit/clearance keys stay /64),
and paths never carry a query string (summaries strip it from older rows too).
`shadow-tail.js` persists per-log `{ino, offset, head}` to `shadow-offsets.json` next to the
shadow file (`VERDICT_SHADOW_OFFSETS_FILE` overrides; atomic 0600). A restart resumes;
a log with no saved entry starts at its last complete line; rotation, truncation, or a
changed head fingerprint (same-inode truncate + regrow) restarts at 0, and a rotated log is
drained through its retained descriptor first. Offsets are checkpointed only for rows the
writer acknowledged, every 64 lines, so a crash replays at most that many rows.
Only complete lines are consumed, and NUL bytes (sparse holes left by in-place log
rewrites) are stripped before parsing. `scripts/shadow-cleanup.mjs plan|apply` is a
one-time, tailer-stopped cleanup of query strings and re-scan duplicate blocks;
`scripts/masked-replay.mjs asis` scores already-masked logs as they are.
