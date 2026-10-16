---
type: decision
title: "Scoped API keys (design, not built)"
description: "Tenant API keys are opt-in, scoped, hostname-restricted, expiring, hashed at rest and revocable; the 1-hour connect token is the first, narrowest instance."
timestamp: 2026-10-16
---

## Status

Proposed. Only the connect token (scope `connect`, below) is implemented, in `portal/src/connect-tokens.js`. Nothing else in this document is built.

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
- Open questions for Pete: whether `hostnames:write` ships at all in v1; whether API keys need a paid plan; maximum key lifetime (proposed 90 days).
