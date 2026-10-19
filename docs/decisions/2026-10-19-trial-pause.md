---
type: decision
title: "Trial pause"
description: "Trial tenants get 7 days and 1 hostname; afterwards the edge serves a paused page instead of proxying, deleting nothing, until the plan is paid."
timestamp: 2026-10-19
---

## What

- The free trial (plan `trial`, no card) lasts 7 days from the tenant's creation time (`created_at`, rolling 7×24h, not midnight UTC) and allows 1 hostname, whatever `hostname_limit` says.
- From start + 7 days the tenant's hostnames are **paused**, never deleted: claims, agent credentials, `tunnel_hosts.json`, DNS and configuration all stay. The pause is lifted as soon as the effective plan is paid (Hobby, Pro, Agency, legacy `assigned`, or any plan that isn't unpaid).
- Prices and Stripe code are unchanged. The invite gate and `OPEN_SIGNUP` are unchanged.

## How

- **Edge.** `paused_tenants.json` (`{ tenants: { tid: { at } } }`) in the edge data directory is the only pause state. It is written only by `claims.pauseTenant` / `unpauseTenant`, exposed as `POST /internal/v1/tenants/:tid/pause|unpause` (portal key, same validation as suspend/release, idempotent). Pausing never touches claim records, credentials or tunnel hosts, never closes tunnels, and TLS ask keeps answering for paused active hosts so the paused page is served over HTTPS. The pause applies to the whole tenant, so a hostname verified while paused is paused too.
- **Request path.** `src/edge/paused-hosts.js` keeps an in-memory set of active claims whose tenant is paused. The set is built at startup and rebuilt off the request path, on `routesChanged` and by a 30 s background timer; a request only does a set lookup. Only customer routes (a tunnel agent, or a hostname in `tunnel_hosts`) can be paused, so a paused host whose agent is offline still shows the paused page. Static operator routes and the default upstream are never paused. A paused request gets `503`, `Retry-After: 3600`, `Cache-Control: no-store`, `X-Robots-Tag: noindex`, `x-fastdog-paused: 1` and a small self-contained page. If `PAUSED_UPGRADE_URL` is a valid https URL, the page links to it. Only customer content is paused: edge-wide routes registered before the catch-all (`/health`, `/status`, `/www`, billing, `/_fastdog/*`) still answer on a paused host.
- **Portal.** `portal/src/trials.js` has two files:
  - `trials.json` (`started_at`, `paused_at`, `unpaused_at`) is written only by the sweep.
  - `trial_overrides.json` (`extra_days`, `plan`) is written only by `portal/bin/tenant.js extend-trial|set-plan`.

  The start time is `tenant.created_at` (now set for open and invite sign-ups), else the recorded `started_at`. Legacy tenants without either get a full trial from the first sweep that sees them. The sweep pauses ended trials and unpauses paused tenants that became paid (via `accounts.json` or `set-plan`) or whose trial was extended past now. It writes state only after the edge call succeeds, appends `trial_audit.json` (last 5000), skips suspended tenants, and never deletes, releases or suspends anything. `/api/plan` and `/api/me` return the effective plan, the effective hostname limit and `trial`.
- **Overrides only upgrade.** If `accounts.json` has a paid plan, that plan is effective whatever the override says; an override plan `trial` never pauses or limits a paid tenant.
- **Hostname limit.** `set-plan` to a paid plan lifts the trial cap of 1 but does not raise `hostname_limit` in `accounts.json`. Until billing sets plan limits, the operator raises it separately.
- **Fail-safe reads.** For `/api/me`, `/api/plan` and hostname creation, an unreadable or wrongly shaped `trials.json` or `trial_overrides.json` counts as absent: the `accounts.json` plan and `hostname_limit` apply (still capped at 1 for `trial`), so paid tenants are never broken by a bad trial file.

## Fail-open and flags

- Bot-filter-style fail-open: an unreadable `paused_tenants.json` or `tenant_hostnames.json` keeps the last good paused set (empty at startup), with one warning per failure streak and no hostnames logged. Any error on the request path proxies normally.
- The portal sweep fails safe the other way. If `trials.json`, `trial_overrides.json` or `suspensions.json` has the wrong shape, it takes no action rather than a wrong one. An edge failure leaves the state unchanged for the next hourly run.
- `TRIAL_PAUSE_ENABLED=1` (portal, default off) schedules the sweep: first run after 60 s, then hourly, with no overlapping runs. With the flag off, nothing is ever paused. The edge routes and the paused page are inert until a tenant is listed.
- `PAUSED_UPGRADE_URL` (edge, optional): the https link shown on the paused page.

## Open questions

- Paused-page copy and whether to brand it; currently generic, no tenant or brand names.
- 503 (temporary, keeps search engines from dropping the site, `Retry-After`) versus 402 (Payment Required, semantically closer but unusual for browsers and crawlers).
- Grace period: pause exactly at start + 7 days, or add a short grace and an email warning before day 8 (no mail is sent today).
- Start-time definition: tenant creation, versus email verification or first hostname verification (a slow DNS setup currently eats into the trial).
- The override plan currently affects trial status, the hostname limit and plan display only. API key eligibility still follows `accounts.json`.
