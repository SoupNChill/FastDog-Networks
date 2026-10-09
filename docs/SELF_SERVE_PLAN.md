# Self-serve portal: plan (DRAFT, planning only)

Status: draft for Pete. No code is written, nothing is deployed. Written 2026-10-09 against master `57c23d5`; every claim about what exists was read from the repo or checked read-only on the edge.

Goal: a customer signs up (by invite), attaches a hostname, connects an origin, and asks for a domain, without an operator typing commands. First customer: Pete's Postiz (`/opt/postiz` on prod1, new domain bought through FastDog). Nothing here touches prod1 or Postiz.

## 0. Read this first: three things on the edge today that block a second tenant

Found while reading the code. All are read-only observations; none has been changed.

1. **`/_fastdog/dns/*` has no authentication.** `src/dns/api.js` exposes `PUT /zones/:zone`, `POST/DELETE /zones/:zone/records` with no token check, and `src/edge/server.js` mounts it ahead of the catch-all. Caddy proxies every path of `edge.`, `attach.` and each attached hostname to `127.0.0.1:8787`, so these routes are reachable from the internet. (The apex is not affected: its catch-all rewrites to `/www…`.) I only issued GETs, not writes. A write changes the zone JSON in `/opt/fastdog-edge/zones/`, which the sync script would publish to ns1/ns2 on the next operator-run sync. The zone files' last write time is my own 04:32Z teardown, so there is no sign of tampering.
2. **`GET /_fastdog/agents`, `/routes`, `/metrics` are also unauthenticated and public.** They return every agent's hostname and `localUpstream` (internal addresses) and tunnel host list. Confirmed via `attach.fastdognetworks.com`.
3. **One shared secret does everything.** `AGENT_TOKEN` is the operator key for onboard, billing status and the operator UI, and `registerAgent` (`src/control/tunnels.js`) also accepts it for *any* hostname. Production has a custom 64-char value (checked by length only), but code defaults to `fastdog-local-dev-token` when unset.

**Recommended Step 0 (small, ship before anything else, needs Pete's OK because it touches the edge):** require the token on all of `/_fastdog/dns`, `/agents`, `/routes`, `/metrics` and `/routes/reload` (keep `/_fastdog/tunnel` and `/agents/register` working), plus a Caddy rule returning 404 for `/_fastdog/*` on customer hostnames. Add a test. Back up first, per the usual rules.

## 1. v1 screens and flows

Five screens, one column, calm. No dashboards, no charts.

1. **Sign up / log in (invite-gated).** Email + password + invite code. The invite is bound to an email at mint time. Wrong or used code gives one generic message. A "forgot password" link sends a one-time link.
2. **Add hostname.** Enter `app.example.com`. The portal shows the exact record, with a copy button:
   `app  300  CNAME  attach.fastdognetworks.com.`
   plus a TXT ownership record (see section 5). Apex names get the existing apex note (use a subdomain, or ALIAS/ANAME). A **Verify** button and an automatic re-check every 30 s for 10 min show live status: `waiting for DNS` → `DNS verified` → `certificate issued` → `serving`. Failure shows what we found and what we expected (the API already returns `found`/`expected`).
3. **Connect origin.** After verify, shows one copy-paste command that runs the agent (Docker one-liner; see sizing), with the token embedded once. A **connected** indicator driven by the tunnel state (`connected`, last seen) and a final check that `https://<host>/` answers. Token is shown once; **Rotate token** is one button.
4. **Domains.** The existing search box (`/api/domains/search`), but each available result has **Request this name** instead of "Email us". That creates a request record (name, tenant, price shown, status `requested`) and notifies the operator. Pete registers it by hand and marks it done; the customer then sees it as `registered` with the attach instructions. No checkout, no card, no registrar write path anywhere in code.
5. **Plan and billing.** Shows the plan Pete assigned (Hobby / Pro / Agency, matching the site) and a link out. Stripe stays **test mode only** until a real outside buyer exists; for now this screen says "Billing is arranged by email" and shows the operator-set plan and hostname limit.

Out of scope for v1: teams, API tokens for users, multiple origins per hostname, custom Caddy settings, usage graphs, self-serve domain purchase, annual plans.

## 2. Reuse versus new

| Need | Exists today | Path | Verdict |
| --- | --- | --- | --- |
| Invites | Random `fd-…` codes, max uses, expiry, atomic 0600 file | `src/onboard/invites.js`, `docs/INVITES.md` | **Reuse**; add `email` binding and redeem-at-signup. Today consumed only by `create-zone`. |
| Attach / verify host | `attachHost`, `verifyHost`, CNAME/A/chain check, fail-closed, detach | `src/onboard/attach.js`, `docs/HOSTNAME_ATTACH.md` | **Reuse the logic**; add tenant owner, TXT challenge, reserved-name rules, claim expiry. |
| Agent credentials | 32-byte random, sha256 stored, hostname-bound, shown once | `issueCredential`/`validCredential` in `src/onboard/store.js` | **Reuse**; add tenant id, revoke, last-used. Stop accepting the operator token for tenant hosts. |
| Agent + tunnel | Outbound WS agent, JSON frames | `agent/index.js`, `src/control/tunnels.js` | **Reuse**; needs packaging as a Docker image (today needs the repo + `npm install`). Limits in section 5. |
| Status page | `/status`, `/status.json`, probes for edge and both NS | `src/status/*`, `docs/STATUS.md` | **Reuse** as a footer link/summary. Per-hostname status is new. |
| Operator UI | Loopback-only dashboard: zones, invites, attach, tunnels | `src/operator/*`, `docs/operator-ui.md` | **Keep as is** (SSH tunnel only). Add a Tenants/Requests panel. |
| Domain search | Read-only LOOKUP + GET_PRICE, 10/IP/10 min, 300/day, cache | `domain-search/`, `site/js/domain-search.js` | **Reuse**; the request flow is new and calls our own portal, not the registrar. |
| Stripe test checkout | Test-only, session records, webhook, `paid_test` | `src/billing/*`, `docs/BILLING.md` | **Defer**. Plans there (Starter $9 / Pro $29) do not match the site (Hobby $9 / Pro $29 / Agency $149), keyed by zone, no tenant. Fix when billing goes live. |
| Design system | Tokens, fonts, layout | `site/css/site.css`, `site/fonts/`, `site/logos/` | **Reuse directly** (section 4). |
| Accounts, sessions, passwords, email | Nothing | n/a | **New** |
| Tenant model and ownership checks | Nothing; attachments and credentials have no owner | n/a | **New** |
| Caddy TLS for new hostnames | Manual block + reload per host (`generateCaddyBlock`) | `src/onboard/attach.js` | **New**: on-demand TLS with an `ask` endpoint |
| Domain request records | Nothing | n/a | **New** |
| Transactional email | Nothing in the repo | n/a | **New** (question 4) |

## 3. Data model and auth

**Shape.** A new standalone Node service `portal/`, same pattern as `domain-search/`: no framework, no npm dependencies, own systemd unit (User=fastdog or its own user, Nice, MemoryMax), listening on loopback, fronted by Caddy on its own hostname (proposed `app.fastdognetworks.com`; question 2). It serves static HTML/CSS from `site/` assets plus a small JSON API.

**Not exposed: the operator control plane.** The portal never proxies to `:8787`. The edge gains a narrow **internal** listener (loopback, separate port, its own key `PORTAL_KEY`) with exactly: attach, verify, detach, issue/revoke credential, agent status, and the Caddy `ask` check. The operator `AGENT_TOKEN` is never given to the portal and the operator UI stays on `127.0.0.1:8788`. Tenant ownership is enforced in the portal and again in the internal API (every call carries `tenant_id`; the edge rejects a hostname owned by another tenant).

**Storage.** Atomic JSON files in a `StateDirectory` (the pattern the edge already uses in `src/onboard/json.js`): `tenants`, `users`, `sessions`, `hostnames`, `domain_requests`. Fine for tens of tenants. Honest caveat: Node on the edge is 20.x, so built-in SQLite is not available; move to SQLite when we pass roughly 100 tenants or need concurrent writers. Single writer process, so no locking problem in v1.

| Record | Key fields |
| --- | --- |
| tenant | id, name, plan, hostname_limit, status |
| user | id, tenant_id, email (lowercased, unique), password_hash, email_verified_at |
| session | sha256(token), user_id, created, expires, last_seen |
| hostname | name (unique among active), tenant_id, status, txt_challenge, claimed_at, verified_at, credential_id |
| domain_request | id, tenant_id, name, quoted price, status, notes |
| invite (existing) | + email, tenant_id on redeem |

**Passwords.** `crypto.scrypt` (built in), N=2^15, r=8, p=1, 16-byte random salt, stored with parameters so they can be raised. Minimum length 12, no composition rules, check against a short common-password list. Constant-time compare.

**Sessions.** 32 random bytes; only the sha256 is stored. Cookie `__Host-fd_session`: Secure, HttpOnly, SameSite=Lax, Path=/. 14-day sliding expiry, 90-day absolute, all sessions revoked on password change. CSRF: reject non-GET requests whose `Origin` is not the portal origin, plus a per-session token header on every write. Strict CSP (`default-src 'self'`), no inline script, no third-party assets.

**Email verification.** Signup creates the user unverified; verifying (one-time 32-byte link, 1 h expiry, stored hashed) is required before add-hostname. Same mechanism for password reset. Needs an outbound mail path that does not exist yet (question 4). Until then an operator can send the link by hand (acceptable for the first few customers).

**Rate limits** (per IP and per account, in memory plus the daily file pattern used by domain-search): login 5 failures / 15 min / account and 20 / IP; signup 3 / hour / IP; verify-host 6 / min / tenant (it does live DNS lookups); domain search 10 / 10 min unauth, 30 / 10 min logged in; domain requests 3 open at a time; token rotation 5 / day. Failed-login responses are identical for unknown and known emails.

**Tenant tokens versus the operator key.**
- *Operator key* (`AGENT_TOKEN`): operator only; lives in `/opt/fastdog-edge/.env` (mode 600). Not accepted for tenant hostnames after v1.
- *Portal key* (`PORTAL_KEY`): portal to edge internal API only, rotatable, grants no DNS or zone writes.
- *Agent credential*: per hostname, issued by the portal at verify, shown once, sha256-stored (already how it works), revocable, rotation invalidates the old one and drops the live tunnel. Grants only: register and tunnel for that one hostname.
- *User API tokens*: not in v1. When added: per-tenant, scoped (`hostnames:read`, `hostnames:write`), hashed, last-used shown.

## 4. Look and feel

Match the new site: calm, sparse, no template look. Concretely:
- Link `/css/site.css` as is. Use the existing variables (`--bg --panel --rule --ink --sub --muted --accent --healthy`), which already switch for `prefers-color-scheme`, and the existing `.wrap`, `.split` (marker left, body right), `.section-marker` and `.eyebrow` patterns. Fonts: Space Grotesk for headings, Mulish for body, already bundled. Logos via the existing `picture` dark/light switch.
- Add a small `portal.css` (about 100 lines) for forms, the status row and the copy-command box. Tokens only, no new colors. Status uses `--healthy` and `--accent`, never red-on-green alarms; errors are plain sentences.
- One screen per task, left marker "01 / Hostname", right the content, like the marketing sections. Copy buttons are plain text buttons. No animation. 44 px touch targets and the 390 px dark/light checks used for the site.
- **No frameworks, no build step, no CDN.** Static HTML plus one small vanilla JS file per page, matching `domain-search.js`. Server-side templates are plain template strings. This also keeps the CSP strict.

## 5. Sizing and build order

Each step ships something usable. "S" is under a day, "M" a day or two, "L" several days of focused work. Codex is a good fit for steps marked (C): well-specified, test-heavy, standalone code. Anything touching the live edge, Caddy or DNS I would do by hand, with backups.

| # | Step | Ships | Size |
| --- | --- | --- | --- |
| 0 | Lock down `/_fastdog/*` (section 0) | Closes the open control routes | S, by hand |
| 1 | Postiz attach by hand, logging every step (section 7) | The spec for step 5, and a live first customer | S, by hand with Pete |
| 2 | Edge internal listener + tenant ownership on attach/credentials + reserved-name rules + TXT challenge | Safe multi-tenant primitives, tested | M (C) |
| 3 | Caddy on-demand TLS with `ask` endpoint (active hostnames only), tested on a throwaway name | No more per-host Caddy edits | M, by hand |
| 4 | `portal/` skeleton: accounts, sessions, scrypt, invite redeem, rate limits, email-link mechanism (manual send first) | Log in to an empty portal | M (C) |
| 5 | Add hostname + live verify + connect-origin screens, agent Docker image | Self-serve attach: Postiz re-done through the portal | L (C for code; image/test by hand) |
| 6 | Domain request flow + operator Requests panel | Customers ask for names | S (C) |
| 7 | Plan screen (operator-set) | Customer sees plan and limits | S (C) |
| 8 | Stripe live, only when an outside buyer exists | Real billing | M, not before |

Order is deliberate: 0 and 1 are needed regardless and teach us the most. A usable portal is steps 2 to 5, roughly 2 to 3 weeks of part-time work, most of it reviewable in small PRs.

## 6. Security risks and mitigations

| Risk | Mitigation |
| --- | --- |
| **Cross-tenant access** (reading or changing another tenant's hostname/credential) | Every record carries `tenant_id`; one data-access layer that always filters by it; the edge internal API re-checks ownership; tests that log in as tenant B and attempt every ID of tenant A; unguessable IDs; no list endpoints without tenant filter. |
| **Hostname takeover / squatting** (claiming someone else's name; dangling CNAME after a customer leaves) | Ownership by DNS proof for the *tenant*, not just "a CNAME exists": a per-claim TXT record `_fastdog-challenge.<host>` with a random value must match before activation. Pending claims expire after 24 h and do not block others. First verified claim wins; releasing needs detach by the owner or the operator. Detach removes the tunnel host and credential so a leftover CNAME serves nothing. |
| **Verification abuse** (using us to probe DNS, claiming our domains) | Rate limits on verify; resolver timeouts; reject `fastdognetworks.com` and subdomains, other FastDog-owned zones, IP literals, `localhost`, internal TLDs, wildcards, public suffixes; cap hostnames per plan; never certificate-issue before verification (`ask` endpoint only says yes for `active`). Watch Let's Encrypt rate limits. |
| **Credential issuance** | Only after verify, hostname-bound, shown once, hashed at rest, revocable, rotation drops the live tunnel; operator token no longer works for tenant hosts; tokens never logged; agent Docker command shown over HTTPS only. |
| **Domain search abuse** | The service can only LOOKUP and GET_PRICE. Today the 300/day cap is global and in memory, so a spammer can use up the day for everyone (it degrades to "unavailable", not to spend). Mitigate: persist the counter, lower unauthenticated limits, higher per-tenant quota, cache. The request flow has no registrar write path at all. |
| **Signup spam** | Invite-gated, email-bound invites, email verification, per-IP rate limit, no open signup in v1. |
| **Token / session leakage** | `__Host-` cookie, HttpOnly, strict CSP, Origin + CSRF checks, secrets only in 600 env files, no tokens in URLs, URLs for reset/verify are one-time and hashed at rest, log only path/status/time/truncated IP (as domain-search does). |
| **Tunnel limits (affects Postiz)** | The v0 protocol is single-host, JSON with base64 bodies, 30 s timeout, no WebSocket upgrade passthrough, no streaming, and the docs use `ws://` for the agent. Postiz media uploads and any websocket features may not work, and large bodies cost 33% overhead. Test with Postiz before promising anything; plan a v1 tunnel (TLS agent link, streaming) if it falls short. |
| **Blast radius** | The edge VPS is also ns1 and the CA/proxy for every site. The portal gets its own user, low memory/CPU caps and its own listener; no shell-outs; no access to zone files. Longer term, consider a separate small host. |
| **Billing mismatch** | Test Stripe plans differ from the site. Do not enable billing code paths in v1. |

## 7. Postiz attach log (to fill)

This is the spec for the **connect origin** flow. **The attach has not happened yet; nothing below is a measurement from Postiz.** Do not run it against prod1 until Pete says so.

### What we already know (from `deploy/HOSTNAME_ATTACH.md` and the 22 s timing test)

Flow today: (1) DNS: customer adds `host CNAME attach.fastdognetworks.com`; (2) `attach-host` creates a pending record and returns the CNAME text; (3) `verify-host` resolves the name (CNAME, CNAME chain up to 5 hops, or A = edge IP) and on success adds the host to `tunnel_hosts.json`, issues a hostname-bound credential (shown once) and returns a Caddy block; (4) the agent runs near the origin with `AGENT_TOKEN`, `AGENT_HOSTNAME`, `AGENT_LOCAL_UPSTREAM`, `EDGE_WS_URL` and registers, then opens the websocket; (5) operator pastes the Caddy block into `/etc/caddy/Caddyfile` and reloads, and Caddy gets a Let's Encrypt certificate by HTTP-01; (6) outside curl returns 200. Detach removes the attachment and tunnel host; the operator removes the Caddy block.

Timing test (`/workspace/site-refresh/prA/timing-log.txt`, test hostname `timing-test.fastdognetworks.com`, all run by one operator from scripts): **22.3 s** total.

| Step | Elapsed | Notes |
| --- | --- | --- |
| 1 CNAME in FastDog zone, sync to ns1+ns2 | 8.7 s | Only fast because we own the zone. A customer's registrar DNS adds propagation (docs say 5 to 10 min). |
| 2 attach-host | 0.9 s | |
| 3 verify-host | 2.8 s | Includes credential issue. |
| 4 origin + agent connect | 4.0 s | Script slept a fixed 4 s; real connect time not measured. |
| 5 Caddy block, validate, reload | 1.1 s | Certificate obtained about 4 s later. |
| 6 outside curl | ~1 s | 200, valid TLS. |

What this tells us: the automatable core is about 5 seconds of work; DNS propagation on a customer's registrar and the manual Caddy edit are what make real attaches slow. Postiz specifics still unknown: origin address from the agent's point of view (Docker network on prod1), upload size limits, websocket use, and callback/OAuth URLs that need the public hostname.

### Template (fill in during the real attach)

Record one row per manual action, in order. Include failures and retries. No secrets, tokens or registrant data in this table.

| # | Step | Command / action | Who runs it | Time taken | Could be automated? (how) | Notes / surprises |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Domain request | | | | | |
| 2 | Domain registered | | | | | |
| 3 | DNS: CNAME (and TXT) added | | | | | |
| 4 | attach-host | | | | | |
| 5 | verify-host (credential issued) | | | | | |
| 6 | Agent install on prod1 side | | | | | |
| 7 | Agent connects (indicator) | | | | | |
| 8 | Caddy block + reload | | | | | |
| 9 | Certificate issued | | | | | |
| 10 | First outside request OK | | | | | |
| 11 | Postiz app settings for the public URL | | | | | |
| 12 | Functional check (login, post scheduling, media upload) | | | | | |

Totals to record: wall-clock start to first 200; operator-minutes versus waiting time; number of copy-pastes; anything that required SSH to the edge (each is a thing the portal must do for the customer).

## 8. Questions for Pete

1. **Step 0 now?** May I lock down the unauthenticated `/_fastdog/*` routes (token required, plus Caddy 404 on customer hosts) before anything else? It touches the live edge (with backups).
2. **Portal hostname:** `app.fastdognetworks.com`, `portal.`, or `my.`? (Separate host keeps cookies away from the marketing site.)
3. **Who is customer #1's account:** Pete as a tenant on his own portal, with Postiz as the first hostname, after the manual attach?
4. **Email:** which sender and provider for verification and reset mail (the repo has none), and is a small monthly cost acceptable? Until then I would send links by hand.
5. **Open versus invite signup** after the first few customers: invite-only until a paying outside customer exists?
6. **Plan limits:** do the site's Hobby/Pro/Agency hostname limits (3 / 15 / 50) become hard limits in the portal from day one?
7. **Domain requests:** you register by hand and mark done; OK with no payment collection in the portal at all for now?
8. **Postiz tunnel risk:** should the manual attach test media upload and any websocket features first, and are you willing to wait for a better tunnel if they fail?
9. **Where it runs:** the portal on the edge VPS with strict limits (cheapest), or a separate small server later (needs spend approval)?
10. **Agent distribution:** Docker image on a public registry, or a single download file? (Either needs a place to host it.)
