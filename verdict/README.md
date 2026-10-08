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
| `GET /health`, `/openapi.json` | Public health/schema |
| `POST /v1/keys` | First key: socket loopback OR `VERDICT_ALLOW_BOOTSTRAP=1`; otherwise `403 bootstrap_disabled`. Once any key exists, requires bearer auth (`401` otherwise). Returns plaintext once. |
| `POST /v1/keys/:id/revoke` | Bearer auth; soft revoke, `200 {ok:true}` or `404`. Any active key can manage keys. Revoking all keys does not reopen bootstrap. |
| `POST /v1/decide` | Bearer auth; decision and request ID |
| `GET /v1/usage` | Bearer auth; persistent usage for calling key |
| `GET /v1/edge-auth` | Public local heuristic; allow `200` empty, challenge `401` with `Location` and `X-Verdict-Action`, block `403`. `Accept: application/json` returns decision JSON with the same status. |
| `GET /challenge` | FastDog PoW page with accessible no-JS form; safe relative `?next=/path` only |
| `GET /challenge/issue` | Single-use PoW challenge JSON; optional signed `hint` |
| `POST /challenge/verify-fallback` | Signed arithmetic form; weaker accessible fallback |
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

Googlebot/Bingbot claims undergo reverse DNS followed by forward confirmation of the supplied IP using `dns.promises`. Googlebot requires a `.googlebot.com` hostname; Bingbot requires `.search.msn.com`. Confirmed bots allow with `verified_good_bot`. Failed claims add +0.35 (`spoofed_good_bot`); the total DNS deadline is 200ms and timeout adds +0.35 (`good_bot_dns_timeout`), never auto-allowing. Results are cached in memory for one hour, separately by bot and IP. The synchronous scoring helper cannot verify DNS and treats unverified claims as suspicious; API and edge use the async local decision wrapper.


Decide is limited per key AND socket IP. Forwarded headers cannot spoof this limiter; behind a local proxy its IP bucket is shared by callers. Invalid bodies return 400; exceeded limits return 429 and `Retry-After`. Usage and hashed keys persist. Decisions append only request ID, action, reason, engine, IP, pathname, key ID and timestamp to JSONL. Queries/fragments are removed; never put secrets in path segments. Rotate the log operationally.

## Configuration

| Variable | Default |
| --- | --- |
| `PORT`, `VERDICT_BIND` | `8080`, `127.0.0.1` |
| `VERDICT_ALLOW_BOOTSTRAP` | `0`; `1` permits remote first-key bootstrap |
| `VERDICT_KEY_FILE`, `VERDICT_USAGE_FILE` | `data/keys.json`, `data/usage.json` |
| `VERDICT_DECISION_FILE` | `decisions.jsonl` beside usage file (normally `data/decisions.jsonl`) |
| `VERDICT_RATE_LIMIT_WINDOW_MS` | `60000` for both limiters |
| `VERDICT_RATE_LIMIT_MAX`, `VERDICT_IP_RATE_LIMIT_MAX` | `60` per key, `120` per socket IP |
| `VERDICT_CLEARANCE_SECRET` | Unset; challenge routes return 503 without it |
| `VERDICT_CLEARANCE_TTL_SECONDS` | `300` |
| `VERDICT_DEMO_FORCE` | `0`; `1` enables `X-Verdict-Force: allow\|challenge\|block` |
| `TYPESAFE_API_KEY` | Unset; no external calls unless configured |
| `TYPESAFE_BASE_URL` | `https://api.typesafe.ai` |

Edge auth always uses the local heuristic, even if TypeSafe is configured. Decide optionally uses Jev with local fallback; Googlebot/Bingbot claims always use local DNS verification. Jev responses include confidence without a local risk score. Tests mock Jev and need no paid credentials; run them with `TYPESAFE_API_KEY` unset.

## Edge trust and proof-of-work

Caddy supplies `X-Forwarded-Method`, `X-Forwarded-Uri`, `User-Agent` and a sanitized `X-Forwarded-For` (first IP), with `X-Real-IP` as fallback. `X-Original-Method`/`X-Original-Uri` are also accepted. Without original method/URI headers the GET auth request and `/` are used. Edge auth passes all visible headers, including User-Agent, Accept-Language and client hints, into the heuristic. Proxy-observed header order is not assumed to be original browser order. Edge headers are trusted assertions: keep Verdict loopback-only and overwrite client-provided forwarding headers in the proxy.

The self-hosted challenge uses no third-party captcha or external assets. `GET /challenge/issue` returns a random `challenge_id`, `difficulty` and `expires_at` (Unix milliseconds). A same-origin Web Worker finds a decimal nonce such that SHA-256 of `challenge_id + ':' + nonce` has at least `difficulty` leading zero bits. `POST /challenge/verify` checks the proof on the server before granting clearance. Serve on HTTPS. Failure/expiry offers retry and an accessible form; the worker stops when leaving the page.

Edge-auth includes a signed, two-minute score hint in its challenge Location, bound to host, IP, UA and the safe return path. Difficulty is 16 bits below 0.45, 18 at 0.45, 20 at 0.65 and 22 at 0.75 or above (increments are not cumulative). Unsigned score parameters are ignored; direct challenges use 16 bits. Altered, expired or mismatched hints fail closed. A valid clearance bypasses the decision engine.

Pending challenges are browser-bound, single-use and expire after two minutes. Verification attempts with a valid challenge identity consume it even if the answer is wrong. Issuance is limited to 30 per IP prefix per two minutes, with a 10,000-entry pending cap and opportunistic expiry cleanup. The HTML form also consumes an issuance slot. Restarting clears pending challenges. Multiple processes/replicas require sticky routing for issue and verification; the in-memory store is not shared. Apply edge request limits as well.

The `fd_verdict_clearance` cookie signs the exact payload `exp.host.ipprefix.uahash` with HMAC-SHA256. Its wire format is `base64url(payload).base64url(hmac)`. Host is the lowercased, trimmed `X-Forwarded-Host` (otherwise Host), including port if present. IPs normalize to IPv4 /24 or IPv6 /64; IPv4-mapped IPv6 uses the IPv4 prefix. UA hash is the first eight hex characters of SHA-256 of the User-Agent. There are no wildcard clearances. All three bindings and expiry must match; old 0.2.0 cookies are invalid. TTL defaults to 300 seconds, with `HttpOnly; Secure; SameSite=Lax; Path=/`. Use a strong random `VERDICT_CLEARANCE_SECRET`, shared by auth and challenge handlers. Keep forwarding headers sanitized, including `X-Forwarded-Host`, and serve the challenge on the protected hostname.

The accessible form posts to `/challenge/verify-fallback` using a signed two-minute arithmetic puzzle, an explicit confirmation checkbox, a hidden honeypot and a minimum two-second completion time. It is single-use and browser-bound, but **weaker than PoW**: automated clients can solve arithmetic without comparable computation. It is an intentional accessibility escape hatch, not equivalent bot protection. No-JS users can expand the form and answer the labeled addition. The page ships FastDog logos and local CSS in `public/branding/`; Space Grotesk and Mulish use system fallbacks when fonts are not installed. Demo force must remain off in production.
