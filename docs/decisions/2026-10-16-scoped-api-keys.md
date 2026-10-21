---
type: decision
title: "Scoped API keys (v1 built)"
description: "Tenant API keys are opt-in, scoped, hostname-restricted, expiring, hashed at rest and revocable; the 1-hour connect token is the first, narrowest instance."
timestamp: 2026-10-16
---

## Status

v1 built (`portal/src/api-keys.js`, routes under `/api/v1/`, UI at `/keys`), with the owner's decisions of 2026-10-16:

- v1 scopes are `hostnames:create` (add and verify), `status:read` and `connect`. Deleting hostnames is held for v2 and stays portal-only. `hostnames:read` is not a separate scope: reading one hostname needs `status:read` or `hostnames:create`. `credentials:rotate` is folded into `connect`.
- Keys work on every paid plan, Hobby included. There is no free plan.
- 90 days maximum, 30 by default; no renew action in v1 (create a new key). Connect tokens stay at 1 hour.
- Limits as below, except live keys are capped at 10 per tenant (not per hostname). The CIDR allow-list is not in v1.
- Verify through a key never returns an agent credential; only `connect` does.

The connect token (`portal/src/connect-tokens.js`) is unchanged.

## Trial keys (flag TRIAL_API_KEY_ENABLED, default off)

Added 2026-10-21 so a trial can use the "AI assistant puts your app on FastDog" flow. With the flag unset (anything but `1`) behaviour is unchanged: trials get `plan_required` and `available: false`. With it on:

- Eligible: effective plan is `trial` (`trials.js`, overrides respected), the trial is running (not ended, no `paused_at` or `pause_requested_at`, extensions count), tenant active and not suspended, creating user email-verified. An unreadable trial file means no trial key (fail closed). Paid plans keep the rules above unchanged.
- Limits, enforced server-side: exactly 1 hostname (`invalid_key`), 1 live key per tenant (`key_limit_reached`), `expires_at` = trial end (earlier only if a shorter lifetime is requested; never past it or 90 days). Records carry `trial: true`. Same password re-auth and rate limits.
- `/api/v1` accepts a key of a non-paid tenant only if it is a trial key with 1 hostname, unexpired, the flag is on and the trial still running; otherwise `unauthorized`. Suspension and `auth_version` checks run first, as before.
- A trial tenant that becomes paid keeps its trial key under paid rules until it expires (at the old trial end); it can then create normal keys.
- `GET /api/keys` adds `trial: { max_keys, max_hostnames, expires_at }` only when trial limits apply; the keys page explains them and asks for one hostname.

## Context

Customers increasingly set up servers with AI coding assistants and scripts. Today every portal action needs a browser session with CSRF, so automation either can't help or would need the user's password. Handing out a session cookie or password to a tool is worse than a narrow key.

## Decision

1. **Key format.** `fd<kind>_<43 chars base64url>` (32 random bytes). Kinds: `ct` connect token (1 hour), `ak` API key (long-lived). The prefix makes leaks greppable by secret scanners.
2. **Storage.** Only `sha256(secret)` plus metadata is stored (portal state, 0600). The secret is shown once at creation. Lookup is by digest; no plaintext comparison.
3. **Scopes** (a key holds one or more):
   - `connect`: read one hostname's connection status; issue its connect command once. Implemented as the connect token.
   - `status:read`: read live status (the Status page payload) for allowed hostnames.
   - `hostnames:read`: list hostnames and DNS records.
   - `hostnames:write`: add, verify and remove hostnames (counts against the plan's hostname limit).
   - `credentials:rotate`: issue connect commands (rotates the agent credential).
   No scope covers billing, account, password, invites, Verdict enforcement, or other tenants. Those stay session-only.
4. **Restrictions.** Every key is bound to one tenant and an optional hostname allow-list (exact names; no wildcards in v1). Optional CIDR allow-list. Mandatory expiry: connect tokens 1 hour; API keys at most 90 days, default 30, with a renew action.
5. **Transport.** `Authorization: Bearer <key>` only. Keys in query strings, bodies or cookies are rejected. Bearer routes ignore cookies, so CSRF does not apply and a key can't ride on a session.
6. **Tenant isolation.** The tenant comes from the key record, never from the request. Hostname scoping is enforced in the portal before any edge call; the edge still enforces tenant ownership on every internal route (defence in depth).
7. **Revocation.** Per key, per hostname (all keys touching it), and automatically when a hostname is removed, the tenant is suspended, or the user's password changes (API keys only). Revocation takes effect on the next request; there is no cache.
8. **Limits.** Per-key and per-IP rate limits; key creation 5/hour per tenant; at most 10 live API keys and 3 live connect tokens per hostname.
9. **Audit.** Each use logs key id (never the secret), scope, route template, status and time. Users see last-used time per key in the portal.
10. **Creation** requires a signed-in, email-verified session with CSRF. A key can never create another key.

## Consequences

- Assistants and scripts can do setup work without passwords or cookies, with a blast radius of one hostname and, for connect tokens, one hour.
- `credentials:rotate` and `connect` close the current agent connection when used. The portal warns about that, and so do the API responses.
- Open questions for the owner: whether `hostnames:write` ships at all in v1; whether API keys need a paid plan; maximum key lifetime (proposed 90 days).
