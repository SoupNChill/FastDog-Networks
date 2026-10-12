# Day 2 backlog (from the independent reviews of #32, #33, #34)

No HIGH findings. Items fixed before merge: bare `log {}` in the generated Caddy block, AGENT_TOKEN/EDGE_BIND startup guard, committed portal test artifacts, portal nav. Items marked DONE below are implemented; the remaining items are not built yet.
No HIGH findings. Items fixed before merge: bare `log {}` in the generated Caddy block, AGENT_TOKEN/EDGE_BIND startup guard, committed portal test artifacts, portal nav. Items marked DONE have been implemented; remaining items are not built yet.

## Lane A (edge)
- DONE (E1): opt-in routing re-checks every 6h; suspend after 3 authoritative mismatches, skipping resolver errors/timeouts. One lookup per active claim per run; defaults remain off.
- DONE (E1 review HIGH/MEDIUM): no automatic restoration of suspended claims; expire after 24h, require explicit routing + TXT proof, and preserve first-to-prove ownership across pending/suspended contenders.
- DONE (E1 review MEDIUM): revoke credentials on suspension and issue a fresh credential on restoration; regression coverage includes resolver outages, expiry and competing claims.
- LOW: `RESERVED_SUFFIXES=""` empties the reserved list; always union with built-ins, treat empty as unset.
- LOW: `create` has no rate limit though the contract lists 429.
- LOW: credential lost if the verify response is dropped; first rotate after activation should not count against 5/day.
- LOW: internal server timeout returns 400 `invalid_json`; use 408/504.
- LOW: control routes (`/status`, `/health`, `/_fastdog/*`) are served on customer hostnames; restrict by Host in Caddy.
- LOW: `validCredential` rewrites the whole credentials file for `last_used_at`; throttle.
- INFO: 409 `hostname_unavailable` is an existence oracle, as the contract specifies.

## Lane B (portal)
- DONE (E2 review): authenticated sessions are capped at 10 per user and 20000 globally; admission returns 429 without revoking existing sessions, and expired or revoked sessions free capacity.
- DONE (E2): anonymous sessions have a separate 5000 cap and 30-minute idle TTL; saturation returns `rate_limited` (429) without evicting existing CSRF bootstrap sessions.
- DONE (E2): rate-limit capacity is 20000 per prefix; expired entries are reclaimed before admission and existing keys remain usable at capacity. Account-map saturation fails closed with 429 before password verification, including valid credentials for new keys; existing account lockouts remain enforced.
- MEDIUM: persistent rate limits still rewrite the whole file per attempt; reduce write amplification.
- LOW: per-account login lockout enables lock-out of a known email; also key on IP plus account.
- LOW: `trustProxy` only accepts a single-IP `X-Forwarded-For`; document that Caddy overwrites it or take the last hop.
- DONE (E2): `sessions.get()` persists `last_seen` and sliding expiry at most once a minute.
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
- DONE (E4): Portal uses the site logo and favicon; compact mobile navigation keeps Sign out alongside links; submit buttons use the site accent; Connect hides the empty form and links to hostname setup when no verified hostname exists.
- Apply `import fdlog <host>` to the real Caddyfile blocks (needs separate approval) and add a real-request log test.


## Lane C (on-demand TLS ask)
- DONE: default-off `TLS_ASK_ENABLED`; direct-loopback-only ask, rejecting forwarded headers including empty values.
- DONE: normalized verified active claim / explicit active legacy attachment approval; reserved, malformed, pending, expired and unknown names denied. Ambiguous tunnel lists do not independently authorize issuance.
- DONE: bounded in-memory limits of 30 successful approvals/minute/client and 300/minute globally, with 429 and retry timing.
- DONE: offline handler tests for flag, authorization, normalization, spoofing, limits, resets and current-storage reads; existing ask fixtures explicitly opt in.
- DONE: unapplied Caddy global on-demand TLS snippet and operator documentation; deployment validation remains an operator step.
- DONE: review MEDIUM — denied/unknown SNI consumes neither approval budget; regression tests cover shared-loopback exhaustion.
- DONE: review MEDIUM — deny multiple active records and legacy/tenant coexistence; regression tests cover duplicate owners, invalid competing owners and pending claims.

## Open after Day 2 reviews (must fix before enabling the flag)
- MEDIUM (TLS ask, PR #38): deny path is unmetered and does synchronous disk reads per ask; meter denies and cache the owner index. Blocks enabling TLS_ASK_ENABLED.
- MEDIUM (claim re-check, PR #39): inconclusive DNS results are skipped forever; cap consecutive inconclusive checks so a stale tenant cannot hold a hostname. Blocks enabling RECHECK_ENABLED.
- MEDIUM (name scan, PR #36): about 60 legacy files exempt by line hash and three whole-file exemptions (two docs and deny-names.json); move docs to per-line exemptions and shrink the legacy list.
- Edge access logs: top-level `level`, `ts`, `logger`, `msg` fields still appear in fdlog output (Caddy adds them outside the filter); harmless, but the snippet comment should say so.

## Lane P (portal login and branding)
- DONE: standalone branded login, invite-only signup and email verification; shared site palette, local fonts, responsive header/footer, accessible labels and focus styles.
- DONE: active-session gates on every app page and business API, including domain search; noindex response headers and HTML metadata. Invalid invitations create no accounts.
- DONE: portal-local branding assets remove the sibling-directory deployment dependency; meaningful HTML and noscript guidance on every page, with page/MIME/CSP/asset regression tests. Root-origin proxy requirement documented.
