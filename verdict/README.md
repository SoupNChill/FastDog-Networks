# Verdict 0.2.1

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
| `GET /metrics` | Public JSON, also accepts bearer headers; intended for loopback scraping |
| `POST /v1/keys` | First key: socket loopback OR `VERDICT_ALLOW_BOOTSTRAP=1`; otherwise `403 bootstrap_disabled`. Once any key exists, requires bearer auth (`401` otherwise). Returns plaintext once. |
| `POST /v1/keys/:id/revoke` | Bearer auth; soft revoke, `200 {ok:true}` or `404`. Any active key can manage keys. Revoking all keys does not reopen bootstrap. |
| `POST /v1/decide` | Bearer auth; decision and request ID |
| `GET /v1/usage` | Bearer auth; persistent usage for calling key |
| `GET /v1/edge-auth` | Public local heuristic; allow `200` empty, challenge `401` with `Location` and `X-Verdict-Action`, block `403`. `Accept: application/json` returns decision JSON with the same status. |
| `GET /challenge` | Demo HTML/JS verification page; safe relative `?next=/path` only |
| `POST /challenge/verify` | Demo clearance cookie and `{ok:true}`; no bearer required |

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

Decide accepts a structured object or `{ "state": {...} }`. Legacy string state is accepted but carries no local risk signals. Only explicit fields influence scoring; arbitrary properties and serialized object keys never do. UA/notes/signals contribute malicious-tool signals; UA/signals contribute automation signals. Sensitive paths add risk only for POST or credential/automation signals. Prior score, account age and a 60-second per-IP velocity counter contribute as specified in `src/engine/heuristic.js`. Header values, ASN and JA3 are accepted structured context but have no scoring rule in v2. GET `/login` with a normal browser allows. Thresholds remain 0.45 challenge and 0.75 block.

Decide is limited per key AND socket IP. Forwarded headers cannot spoof this limiter; behind a local proxy its IP bucket is shared by callers. Invalid bodies return 400; exceeded limits return 429 and `Retry-After`. Usage and hashed keys persist. Decisions append only request ID, action, reason, engine, IP, pathname, key ID and timestamp to JSONL. Queries/fragments are removed; never put secrets in path segments. The decision log truncates before an append would exceed 5 MiB or when its oldest entry reaches 7 days. No archives accumulate. Retention runs on writes, so an idle file is cleaned on the next decision; age is recovered from the first record after restart. A record larger than the byte ceiling is skipped. Use a single process per log file.

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
| `VERDICT_DEMO_FORCE` | `0`; `1` enables `X-Verdict-Force: allow\|challenge\|block` |
| `TYPESAFE_API_KEY` | Unset; no external calls unless configured |
| `TYPESAFE_BASE_URL` | `https://api.typesafe.ai` |

Edge auth always uses the local heuristic, even if TypeSafe is configured. Decide optionally uses Jev with local fallback. Tests mock Jev and need no paid credentials; run them with `TYPESAFE_API_KEY` unset.

## Edge trust and demo clearance

Caddy supplies `X-Forwarded-Method`, `X-Forwarded-Uri`, `User-Agent` and a sanitized `X-Forwarded-For` (first IP), with `X-Real-IP` as fallback. `X-Original-Method`/`X-Original-Uri` are also accepted. Without original method/URI headers the GET auth request and `/` are used. Edge headers are trusted assertions: keep Verdict loopback-only and overwrite client-provided forwarding headers in the proxy.

The `fd_verdict_clearance` cookie is HMAC-SHA256 over `exp.UPPERCASE_IP` (verification also supports signed `exp.*`), bound to the client IP by default, with `HttpOnly; Secure; SameSite=Lax; Path=/`. Serve the challenge on the protected HTTPS hostname; valid clearance permits requests until expiry. The JS check is a demo, not bot-proof verification: any client can POST to obtain clearance. Demo force must stay off outside demonstrations. An invalid or expired cookie falls back to the heuristic.

## Local operations

```sh
node bin/verdict-keys.js create edge-client
node bin/verdict-keys.js list
node bin/verdict-keys.js revoke KEY_ID
```

The CLI uses `VERDICT_KEY_FILE` (default `data/keys.json`, relative to the working directory). Create prints only the plaintext key once to stdout; capture it securely. List prints only ID, name, creation and revocation timestamps, never hashes or plaintext. Run mutations while the server and other key writers are stopped, then restart: the server caches keys in memory. For immediate changes on a running server, use the authenticated key API.

`GET /metrics` returns process-lifetime `requests_total` (all completed HTTP responses), `actions` (completed decisions), and endpoint totals for `/v1/decide` and `/v1/edge-auth`, including errors and rate limits. Each endpoint retains its last 2,048 response latencies in milliseconds, with p50/p99 and cumulative histogram buckets for that recent window. Empty percentiles are null. Metrics reset on restart, contain no key/IP labels, and require no authentication even when a bearer header is supplied. Keep this route private in the reverse proxy. The scrape itself enters the request total after its response finishes.

Decide retains `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` and the corresponding `X-IP-RateLimit-*` headers; rejected limits also return `Retry-After`. A rejection by the first (IP) limiter does not run the key limiter.

```sh
node scripts/fp-replay.js
PORT=8080 VERDICT_API_KEY=KEY CONCURRENCY=50 node scripts/load-test.js
```

Replay evaluates 30 realistic good-request fixtures against the local decision engine, disables paid calls explicitly, prints action counts/allow percentage, and fails below 95% allow. It is a small regression fixture, not a production false-positive estimate.

The load script runs for 30 seconds, splits requests between decide and edge-auth, defaults to 50 concurrent requests (configurable 1–200), and prints per-endpoint requests/sec, p50/p99 of the latest 2,048 latencies, transport errors and HTTP status counts. `TARGET` can override the default `http://127.0.0.1:$PORT`; only literal loopback HTTP origins are accepted. Public addresses, all hostnames (including localhost), and redirects are refused. Use a dedicated local server started with `TYPESAFE_API_KEY` unset to prevent spend. Default rate limits will produce 429s; raise both rate-limit maxima on that isolated server when measuring decision throughput. In-flight requests are aborted at the 30-second deadline and included in transport errors and latency samples; rps counts all attempts. The script does not change server configuration.
