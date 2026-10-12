# Day 2 backlog (from the independent reviews of #32, #33, #34)

No HIGH findings. Items fixed before merge: bare `log {}` in the generated Caddy block, AGENT_TOKEN/EDGE_BIND startup guard, committed portal test artifacts, portal nav. Everything below is deliberately not built yet.

## Lane A (edge)
- MEDIUM: active claims are never re-verified or expired (`internal/claims.js`). Re-check routing and TXT periodically or on `/tls/ask`; demote after N failures; document an operator override.
- LOW: `RESERVED_SUFFIXES=""` empties the reserved list; always union with built-ins, treat empty as unset.
- LOW: `create` has no rate limit though the contract lists 429.
- LOW: credential lost if the verify response is dropped; first rotate after activation should not count against 5/day.
- LOW: internal server timeout returns 400 `invalid_json`; use 408/504.
- LOW: control routes (`/status`, `/health`, `/_fastdog/*`) are served on customer hostnames; restrict by Host in Caddy.
- LOW: `validCredential` rewrites the whole credentials file for `last_used_at`; throttle.
- INFO: 409 `hostname_unavailable` is an existence oracle, as the contract specifies.

## Lane B (portal)
- MEDIUM: anonymous sessions created on every `/api/me`; global 20000 cap makes login return 500 when full. Separate anonymous cap, short TTL, evict oldest, return `rate_limited`.
- MEDIUM: rate-limit map shares one 20000-entry cap across login-account and `rotate:*` keys. Cap per prefix, expire separately, avoid whole-file rewrite per attempt.
- LOW: per-account login lockout enables lock-out of a known email; also key on IP plus account.
- LOW: `trustProxy` only accepts a single-IP `X-Forwarded-For`; document that Caddy overwrites it or take the last hop.
- LOW: `sessions.get()` rewrites `sessions.json` on every request; touch `last_seen` at most once a minute.
- LOW: file mailer outbox keeps raw links; delete after delivery or TTL.
- LOW: whitelist fields of `/api/domain-requests` (do not return operator `notes`).
- LOW: tenant suspension has no path that deletes the tenant's hostnames and credentials.
- LOW: `isReserved` in `portal/src/hostname.js` is unused (edge enforces); keep or remove.

## Lane D (tests)
- MEDIUM — DONE (E3): revocation test after detach then re-activation by another tenant (old and rotated tokens refused).
- MEDIUM — DONE (E3): assert file mode 0600 on tenant and credential stores.
- MEDIUM — DONE (E3): portal tests for new session id on login, replay after logout, cookie Max-Age, password reset, token reuse, single-use invites, generic signup response.
- MEDIUM — DONE (E3): trusted-proxy and untrusted-source cases for the IP limit.
- MEDIUM — DONE (E3): name scanner roots miss `src/status`, `src/dns`, `src/operator`, `src/billing`, `agent/`, `config/`, `deploy/*.md`, `scripts/`, `README.md`, `site/`; widen or scan `git ls-files`.
- MEDIUM — DONE (E3): scanner `sensitiveFile` regex also skips `env.js`; match `.env*` only.
- MEDIUM — DONE (E3): test the access-log snippet (drops query, cookies, auth headers, token; `ip_mask`).
- MEDIUM — DONE (E3): `offline.cjs` blocks only `spawnSync`; also block `spawn`, `exec`, `execFile` and sync variants.
- MEDIUM — DONE (E3): `REQUIRE_LANES=1` so skip guards fail instead of skipping once lanes are merged (turn on after merge).
- LOW: `/tls/ask` header-spoof case; verify-after-expiry with valid DNS; require fragment (not query) for tokens in the portal helper; scanner skips (`.tmp-`, NUL files, `.md`); hostname-literal check limited by file prefix; `deny-names.json` as hashes; broaden log checks (401/409/429/500, POST body, IP truncation); keep `--lane` list in sync with the glob.

## Other
- Portal UI: brand is plain "Portal" (no logo); primary submit buttons look secondary; Connect page shows an empty select when there is no verified hostname.
- Apply `import fdlog <host>` to the real Caddyfile blocks (needs separate approval) and add a real-request log test.
