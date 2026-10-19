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
- DONE (open-signup flip): integration test boots the real portal on one data dir with the flag unset, `1`, then `0`, sending `accept_terms: true` and checking a sign-up without it is refused; runbooks/open-signup.md covers preflight (including `SITE_ORIGIN` and terms version bumps), flip, first hour, rollback and kill switch. Pending open registrations can still verify after rollback, and expired unverified ones are locked out until a re-flip (documented, not changed).
- DONE (#87, #88 merged into the flip PR): `portal/server.js` reads `MAIL_TRANSPORT` (file default, smtp opt-in) and runbooks/open-signup.md documents both, keeping file for the flip; the runbook's kill switch section now uses `portal/bin/tenant.js` suspend/resume/release, and the flip test suspends an open account through the CLI and checks its session and login are refused.
- DONE (OS-C2): sign-up requires a Terms/Privacy checkbox; the server refuses generically unless `accept_terms` is JSON `true` (invite, open and reclaimed open registrations) and stores its own document versions, acceptance time and a per-install salted IP hash.
- DONE (OS81 review): fixed trial signup constraints, preserved flag-off IP limiter restart behavior, added password-setting open verification and expired-registration recovery, checked global admission before domain allocation, deleted refunded empty limit entries and added global-limit alert metadata. Synthetic account fixtures and restart operations documented.
- DONE (first-run): authenticated `/start` page with three accessible progress steps, automatic status refresh, Start navigation and post-login routing from tenant-scoped hostname status. Live matches the existing active-claim plus connected-agent indicator, not an HTTPS probe. Copy explains the required CNAME and TXT records and operator-assigned plan limits. Offline validation: 304 root and 62 portal tests passed, zero failures/skips.
- DONE (E2 review): authenticated sessions are capped at 10 per user and 20000 globally; admission returns 429 without revoking existing sessions, and expired or revoked sessions free capacity.
- DONE (E2): anonymous sessions have a separate 5000 cap and 30-minute idle TTL; saturation returns `rate_limited` (429) without evicting existing CSRF bootstrap sessions.
- DONE (E2): rate-limit capacity is 20000 per prefix; expired entries are reclaimed before admission and existing keys remain usable at capacity. Account-map saturation fails closed with 429 before password verification, including valid credentials for new keys; existing account lockouts remain enforced.
- MEDIUM: persistent rate limits still rewrite the whole file per attempt; reduce write amplification.
- LOW: per-account login lockout enables lock-out of a known email; also key on IP plus account.
- LOW: `trustProxy` only accepts a single-IP `X-Forwarded-For`; document that Caddy overwrites it or take the last hop.
- DONE (E2): `sessions.get()` persists `last_seen` and sliding expiry at most once a minute.
- DONE (open signup B1): outbox files older than 7 days are deleted on startup and hourly; SMTP audit records always redact links/codes, including failures.
- LOW: whitelist fields of `/api/domain-requests` (do not return operator `notes`).
- DONE (#80): administrative suspension revokes tenant credentials and routes, reserves hostnames indefinitely, fences in-flight verification, and supports authenticated, idempotent administrative release; DNS suspension still expires after 24h.
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
- DONE (go-live prep): approval budgets (per-tenant 20/h by distinct hostname, global 100/h, 429 with retry_after), 60 s bounded deny cache cleared on store changes, separate anonymous check cap (600/min) that never blocks approved hosts, optional `TLS_ASK_STATIC_HOSTS`, fail-closed store errors and reason-code-only logs. Go-live Caddy snippet and `deploy/caddy/enable-on-demand-tls.sh` (dry run, backup, validate, atomic install, restore, `--rollback`) with fixture tests. Applying the Caddyfile and enabling `TLS_ASK_ENABLED` remain operator steps; `RECHECK_ENABLED` and Verdict enforce untouched.
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
- DONE (#88, suspension): `portal/bin/tenant.js suspend` calls the edge suspend route (credentials, tunnels and TLS removed; hostnames reserved); `resume` keeps a revocation epoch so pre-suspension credentials never revive; `release` (refused while suspended) frees the reservations. The portal re-checks suspension before every create, verify, rotate and connect-token call.
- MEDIUM (outbox) — DONE (open signup B1): startup/hourly TTL sweeps and a 10,000-file cap bound outbox retention; SMTP delivery leaves only redacted audit copies.
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

## Lane V (good-bot false positives)
- DONE: published IPv4/IPv6 bot ranges precede DNS in edge and shadow scoring; tiny Google bootstrap seed, special crawler claims, atomic validated refresh and resource-capped weekly unit files. Offline regression samples cover desktop/mobile bots and DNS fallbacks. OPEN: the shadow tailer needs a one-line await for opt-in DNS results (outside lane V file scope; approval pending). Deployment and timer activation remain operator work; shadow and DNS-off defaults remain unchanged.

- DONE (TLS ask third adversarial review): tenant-isolated domain budgets, expanded suffix grouping, active-only legacy conflicts, persisted daily host cap, 60/hour global default with static exemptions, canonical-name admission, proxy-header checks before methods, corrupt-state quarantine/recovery and rollout ask/adapt checks with rollback fixtures. Flags remain off.

- DONE (TLS ask fourth adversarial review): catch-all SNI/Host 421 and adapted-route check; global newcomer/static reserve and throttled warnings; persisted weekly host cap; malformed-proof rejection; test-tenant metadata cache; attach-domain reservation under overrides; signal-safe enable/rollback and explicit static-host health probe. Offline regressions added; RECHECK and Verdict enforce remain off.

- DONE (TLS ask fifth adversarial review): locked atomic per-host operator reset with ten-second state reload; fail-closed persistence and throttled hostname-free warnings; normalized native Caddy Host/SNI matching and adapted control-route 4xx handler checks. Offline regressions added; flags remain off.
- DONE (Docker connect review): paste-safe cleanup examples, numeric restricted-origin checks and single-label rejection in both builders, complete range errors, env-file replacement and failure cleanup with browser/server parity and offline regressions.

- DONE (Docker connect follow-up): failure cleanup preserves the calling shell; Docker responses expose the exact token-free env_file for cleanup; noclobber rejects planted paths. Covered by shell, API and builder parity regressions.

- DONE (TLS ask sixth adversarial review): candidate adapted-route preflight, soft weekly host warning, persisted daily tenant reserve and hourly new-account reserve limits, stale PID lock recovery, proxy-free probes and test-label revision invalidation; offline regressions added.

## TLS ask: accepted residuals (final adversarial pass, no HIGH)
- ACCEPTED (MEDIUM, budget): a few invited tenants at the per-tenant cap can fill the non-reserve 40/h global budget; others then rely on the 20-slot reserve. Follow-up: per-invite or account-age global sub-cap and an alert on approval_cap_global.
- ACCEPTED (MEDIUM, availability): first issuance requires the _fastdog-challenge TXT and routing to still resolve; a single-resolver NXDOMAIN/ENODATA is treated as not found (60 s cache). Follow-up: map SERVFAIL/NXDOMAIN-from-one-resolver to inconclusive (503); keep the "keep the TXT" note prominent in tenant docs.
- OPEN (LOW): per-host day cap counts approvals not issuances (operator reset: onboard.js tls-reset); stale-lock recovery race (use rename or flock); history rescans on capped hosts; revision-change reparse not throttled; 421 SNI check only in the catch-all; duplicate catch-all check is literal; --probe-host not mandatory.
- VERIFY AT DEPLOY: through the catch-all on an e2e test label, /_FASTDOG/metrics and //_fastdog/metrics must be denied by (fdctl).

## E2E test-label follow-ups
- DONE: operator test labels `e2e-<label>.<attach-domain>` are no longer treated as guardrail hosts by the attach domain's own denylist entry (claims create/verify and TLS ask); exact guardrail names and subdomains of every other entry stay refused.
- OPEN: the portal API-keys page has no "copy prompt for your AI assistant" for the key flow; only the post-verify connect-token prompt exists.
- OPEN: the v9 edge tarball shipped without `scripts/onboard.js`, so the deployed operator CLI lacks `test-tenant` and `tls-reset`. Include `scripts/onboard.js` in the next edge build.
- CORRECTED: ns2 (2.29.58.90, ns2-fastdog) IS reachable: `ssh root@2.29.58.90` with the edge key works from server3 (checked 2026-10-17, OpenSSH 9.6). The earlier note came from not finding an ns2 ssh config entry, not from a failed connection. Zone changes follow `docs/runbooks/dns-changes.md` on both servers.
- ACCEPTED (MEDIUM, review E2EFIX): docs now describe automatic certificates; correct for production since v9 enabled TLS ask. AGENTS.md updated to record that.
- OPEN (LOW): the guardrail exemption is derived from ATTACH_TARGET; a misconfigured target under a customer guardrail domain would exempt e2e-<label> names there. Follow-up: refuse at startup if attachDomain() equals any ENFORCE_DENYLIST entry other than the operator attach domain, or pin it in config.
- OPEN (LOW): test-label certificates count against the attach domain's Let's Encrypt per-registered-domain weekly limit (50); add a cross-tenant weekly cap for test labels (e.g. 20).
- OPEN (LOW): claims.verify checks the guardrail after the already-active early return; move it above (defence in depth; ask re-checks the guardrail anyway).
- OPEN (LOW): make attachTarget required for isGuardrailHost callers (or test that every call site passes it).
- OPEN (LOW): attachDomain() uses the last two labels; reject at startup if it is a public suffix (e.g. co.uk).
- OPEN (LOW): Verdict enforce uses exact names, so e2e labels under a guardrail apex are not enforce-guarded; confirm they stay out of enforce/forward_auth.

## Control-path normalisation (FDPATH)
- DONE: the edge answers 404 for any `/_fastdog` request whose canonical path (single percent-decode, collapsed slashes, `.`/`..` resolved, case-insensitive prefix) is under the namespace but whose raw path is not the exact lowercase control spelling, and for unmatched control routes; they are never forwarded to a tenant tunnel or origin. `scripts/add-customer-host.sh` now adds `import fdctl` to new blocks when the `(fdctl)` snippet is defined.
- OPEN (operator change, needs approval): existing live customer site blocks lack `import fdctl` (only the on-demand catch-all has it). The edge now refuses non-canonical `/_fastdog` paths itself, so this is defence in depth; add the import to live blocks in a backed-up, validated Caddy change.
- E2E run 2 (v10, 2026-10-17): PASS for the hostname, DNS, verify, TLS ask certificate and live HTTPS. Stalls: a `for` verify loop and a chained mkdir+curl were refused (the agent recovered on its own). The Docker connect step needed the user to approve python3, sh, rm and a file write, not just docker; llms.txt now says to ask for that approval up front. DONE: single-command Docker connect now uses the env-format API and a secret-free run template.
- OPEN (LOW): after an e2e hostname is deleted, Caddy keeps its on-demand certificate in storage until expiry. The name is unrouted (502) and has no DNS. Consider removing on-demand certs for detached hostnames.

- DONE: one-approval Docker connect path shipped: curl writes the private env file and one secret-free docker run consumes it. Tradeoff: the 0600 agent-key file remains until the user deletes it.

- DONE: Docker connect review clarifies initial header setup/curl approval, user-provided PORT, fresh env filenames, API Docker metadata and immediate user-run key-file cleanup with restart guidance.

- DONE: homepage AI onboarding hero and assistant setup section reuse existing styles; regression coverage pins the copy, links and unchanged pricing markup.

- DONE: homepage review clarifies connect-token versus agent-key lifetime and the docs link; pricing is pinned by SHA-256 without a duplicate fixture or exemption.

## Homepage claim sources (Oct 17 production E2E)

Operator-reported evidence for the homepage claim; logs live on the operator host, not in git.

- Test hostname pattern: `e2e-*` on an operator test tenant.
- First prompt: 17:35:17Z; first HTTPS 200: 17:37:17Z; status `live:true`: 17:38:05.8Z. Total: 2:48.8, including 63.4 s operator DNS and 29.3 s approval wait.
- Permission prompts: 1 (the `docker run`), with curl/WebFetch pre-allowed.
- AI usage: Claude Code reported `total_cost_usd` 0.1719446 (list-price estimate, cumulative session total).
- DNS: 2 records (CNAME + TXT) on our own authoritative nameservers.
- Single run, not a typical-outcome guarantee.
- Code facts: `CONNECT_TOKEN_TTL_MS=3600000` in [connect-tokens.js](../portal/src/connect-tokens.js); the [agent](../agent/index.js) opens only outbound connections and has no listening server, so no inbound ports are needed on the customer's server.

- DONE (PR 87 mail review): asynchronous SMTP auth delivery, shared persistent mailbox/recipient budgets with priority reserve, and explicit CLI delivery failure.

- DONE (PR 87 merge review): preserve open signup admission and Terms acceptance alongside guarded mail enqueue/send; retry contended mail locks three times at 10 ms intervals.

- MEDIUM — DONE (#87 mail review): preserve all three unexpired reset links when full and suppress further issuance until expiry or redemption; revoke all on redemption. Regressions cover three consecutive replacement requests under recipient/global caps and SMTP failure, plus delivery failures with available slots.
- MEDIUM — DONE (#87 mail review): share signup/invite/SMTP email normalization, supporting ASCII dot-atom local parts and punycode domains, with verification/reset delivery regressions.

- DONE (shadow retention): first-party shadow rows default to 30-day atomic age trimming with a seven-day configuration floor, oldest-first size backstop, idle maintenance and daily summary pruning. Offline regressions cover retention, atomic replacement and fail-open I/O; deployment remains operator work.

- DONE (portal terms): advisory re-accept prompt on login/account pages, CSRF-protected acceptance with bounded history and fail-open persistence; existing API access remains independent of terms versions.
