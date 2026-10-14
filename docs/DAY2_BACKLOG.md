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
- DONE (M1 follow-up): bounded in-memory deny budgets of 30/minute per normalized name and 300/minute globally, with 429 and retry timing; approved names bypass both budgets and no client budget applies.
- DONE: offline handler tests for flag, authorization, normalization, spoofing, limits, resets and current-storage reads; existing ask fixtures explicitly opt in.
- DONE: unapplied Caddy global on-demand TLS snippet and operator documentation; deployment validation remains an operator step.
- DONE: review MEDIUM (superseded by M1) — all denied/unknown SNI now consumes ask budgets; regression tests cover exhaustion.
- DONE: review MEDIUM — deny multiple active records and legacy/tenant coexistence; regression tests cover duplicate owners, invalid competing owners and pending claims.

## Open after Day 2 reviews (must fix before enabling the flag)
- DONE (M1, TLS ask, PR #38): meter only denied asks after owner lookup; cache the owner index, invalidate on local store writes and check external changes at most once per second. Unknown-name floods perform no hot-path disk reads; activation and flag-off regressions covered.
- MEDIUM (claim re-check, PR #39): inconclusive DNS results are skipped forever; cap consecutive inconclusive checks so a stale tenant cannot hold a hostname. Blocks enabling RECHECK_ENABLED.
- MEDIUM — DONE (M3, name scan, PR #36): removed whole-doc exemptions (planning doc pins 34 hashes; API contract needs none), pruned stale legacy hash, grouped paths by directory; only deny-names.json has a whole-file exemption. Stale hashes/files and unused occurrences fail; exact reviewed baselines are 61 files, 350 hashes and 398 line occurrences. Test header documents exemption review.
- Edge access logs: top-level `level`, `ts`, `logger`, `msg` fields still appear in fdlog output (Caddy adds them outside the filter); harmless, but the snippet comment should say so.

- DONE (M1 review HIGH/MEDIUM): active verified owners always bypass deny budgets without consuming them. Single-loopback-client regressions cover unknown floods followed by approval, repeated approvals, activation after budget exhaustion, and unknown-flood 429s without hot-path disk reads. `TLS_ASK_ENABLED` remains default-off.
- MEDIUM (TLS ask, PR #38): deny path is unmetered and does synchronous disk reads per ask; meter denies and cache the owner index. Blocks enabling TLS_ASK_ENABLED.
- DONE (M2, claim re-check, PR #39): persist `recheck_inconclusive`; the eighth consecutive inconclusive check (~48h at 6h intervals) and each later check advance the suspend failure counter. Configure `inconclusiveBeforeFailure` in claims/server options or per recheck run (default 8, positive integer). Any conclusive result or explicit activation resets the streak. With at least 10 active claims checked, more than 50% inconclusive tenant votes freezes all inconclusive counters for that run (one vote per tenant, inconclusive only when a strict majority of its checked claims are inconclusive); conclusive results still apply. Fake resolver/clock coverage includes three-tenant isolation and the exact 50% boundary.
- MEDIUM (name scan, PR #36): about 60 legacy files exempt by line hash and three whole-file exemptions (two docs and deny-names.json); move docs to per-line exemptions and shrink the legacy list.
- Edge access logs: top-level `level`, `ts`, `logger`, `msg` fields still appear in fdlog output (Caddy adds them outside the filter); harmless, but the snippet comment should say so.

- DONE (M2 follow-up): minimum outage sample defaults to `MIN_OUTAGE_SAMPLE = 10`, configurable via `minOutageSample` claims/server options or per run (positive integer). Smaller samples advance normally. Tests cover single-claim suspension, noisy-tenant isolation, strict majority boundaries and broad outages. Default suspension is the tenth inconclusive check (~60h); `RECHECK_ENABLED` remains off by default.
- DONE (M2 follow-up): untracked and deleted committed generated test state; ignore `test/**/.internal-*/` and `test/**/.tmp-*/`.
- MEDIUM — DONE (M3 follow-up): baseline counts require exact equality for increases and decreases. Tracked binary/NUL, invalid UTF-8, symlink and sensitive files fail unless explicitly exempted by path; only three existing site PNG assets, four fonts and three environment templates are exempted, each with a reason. Temporary Git fixtures cover rejection and exact-path exemptions; sensitive files are never read.
## Lane P (portal login and branding)
- DONE: standalone branded login, invite-only signup and email verification; shared site palette, local fonts, responsive header/footer, accessible labels and focus styles.
- DONE: active-session gates on every app page and business API, including domain search; noindex response headers and HTML metadata. Invalid invitations create no accounts.
- DONE: portal-local branding assets remove the sibling-directory deployment dependency; meaningful HTML and noscript guidance on every page, with page/MIME/CSP/asset regression tests. Root-origin proxy requirement documented.
## Lane H (handover documentation)
- DONE: source-based architecture, ASCII request flows, stores, feature defaults and trust boundaries in `ARCHITECTURE.md`.
- DONE: deploy, rollback, DNS sync, Caddy certificates, agent attach, portal invites/outbox and Verdict runbooks under `runbooks/`.
- DONE: dated decisions with repository/git provenance in `decisions/README.md`.
- DONE: per-box inventory and secret-location/owner skeleton in `INVENTORY.md`; unverified live facts remain `TODO(operator)`. No live deployment or outstanding security finding is marked complete by this lane.

## Open after the Day 3 reviews (flags stay off)
- MEDIUM (re-check): a tenant that controls its own authoritative DNS can answer conclusively once every few checks and so never reach the inconclusive cap. Consider a cumulative inconclusive ratio over a window instead of a streak.
- MEDIUM (suspension): suspending a tenant does not yet remove its edge hosts, tunnels or credentials. Until that ships, the operator revokes them per host (runbooks/portal-invites.md).
- MEDIUM (outbox): files in the outbox hold live verify and reset links and are never swept. Add a TTL sweep, or delete each file after delivery.
- DONE (lane K): agent 0.1.1 sends Bearer headers for registration and the tunnel; offline coverage verifies credential-free logs. Existing proxy query redaction remains required.

## Lane D (documentation refresh)
- DONE: root `AGENTS.md` documents layout, build/test/deploy procedures, documentation index and operational locks.
- DONE: reviewed architecture, all seven runbooks and inventory against current source; documented portal login without Caddy basic-auth, timestamped release backups, archive rollback and previous portal code. Secret records contain locations and owners only.
- DONE: migrated the decision log to dated, frontmatter-bearing records under `decisions/`, added an index and updated all old decision-log references.
- DONE: offline validation: `npm test` 280 passed and `npm run test:portal` 38 passed, zero failures/skips; name scanner, documentation links and decision structure checks pass. No runtime behavior changes or new tests.

## Open after the agent image review (Oct 13)
- DONE (lane K): agent and edge support Bearer headers with strict header precedence; package and lockfile are 0.1.1. Publishing the image remains operator work.
- DONE (lane K): removed built-in token, hostname and name defaults; missing or empty AGENT_TOKEN exits 1, while test imports remain supported.
- DONE (lane K): SIGTERM and SIGINT close the socket and exit 0 promptly; offline process tests cover both signals.

- OPEN (lane K migration): remove the deprecated tunnel query-token fallback after all agents are on 0.1.1+. Publish and verify 0.1.1 before changing installer or portal image pins.
- DONE (lane K follow-up): edge rejects missing, blank and built-in development tokens unless `FASTDOG_ALLOW_DEV_TOKEN=1` explicitly permits local development. `ALLOW_QUERY_TOKEN` defaults on for 0.1.0 compatibility; set it to `0` to reject query-only tunnel credentials. Local `/health` reports `queryTokenFallbackUses`, the successful query-authenticated tunnel connection count since process start, without credentials. Bearer precedence and default-off TLS/re-check behavior are unchanged.
