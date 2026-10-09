# First attach: pre-flight checklist (not started)

Purpose: the first real hostname attach is the spec for the self-serve "connect origin" flow. It has **not** started. Nothing here has been done to the app host, the app or the domain registrar. Fill in the log template in [SELF_SERVE_PLAN.md](SELF_SERVE_PLAN.md#9-postiz-attach-log-to-fill) while it happens.

This document is a checklist for the owner of the first origin; it stays tenant-agnostic in the code and tests (the first customer is data, not code).

## What the owner must decide or do first

1. **Pick the domain and a hostname.** Use the existing `/domains` search. Choose a subdomain for the app (for example `social.<new-domain>`), not the apex: a CNAME cannot sit at the apex.
2. **Approve the registration spend.** The operator registers it by hand at the registrar (the portal and search service have no registration path). Say the maximum price you accept and the number of years. Nothing is registered until you confirm.
3. **Registrant details.** Provide the registrant contact directly to the registrar console yourself (or tell the operator to use stored ones). These never go into git, chat logs or the attach log.
4. **Where DNS for the new domain lives.** Registrar default DNS, Cloudflare, or FastDog nameservers. Say which; it decides who adds the two records (CNAME to the attach target, and the TXT ownership challenge once lane A ships).
5. **Origin details on the app host (read-only questions for you):** is the app already running; on what local port or container name; which Docker network; can an extra small container join that network. Nothing on the app host will be changed until you say go.
6. **App settings that depend on the public URL.** The app's public-URL, frontend/backend URL and OAuth callback settings must be changed to the new hostname before social logins work. Collect the exact setting names from the app's docs; list them in the log (step 11).
7. **Which attach path.** Option 1: the current manual flow (attach-host, verify-host, Caddy block, today). Option 2: wait for Day 4 to Day 5 of the plan and attach through the new internal API and on-demand TLS. Option 1 gives the spec sooner; option 2 produces less throwaway work. Default: option 1, with every manual action logged.
8. **Agent to use.** The current Node agent (needs `npm install`; v0 tunnel: single host, JSON/base64 frames, 30 s timeout, no WebSocket passthrough) or the Docker image from lane E when it exists. Know the limits before testing uploads.
9. **Functional test list** (agree it up front): sign in, create a post, schedule a post, upload a small and a large media file, anything that uses WebSockets or long polling, OAuth connect of one social account (optional).
10. **Time window and who is present.** About 1 hour; the owner at the keyboard for the registrar, DNS and app steps.
11. **Rollback agreed:** detach the hostname (operator), remove the CNAME/TXT records, remove the agent container, restore any changed app settings.

## What the operator will do after the owner confirms

Create the hostname claim, give the exact DNS records, wait for verification, issue the agent credential (shown once, never written to the log), prepare the agent command, add TLS (Caddy block or on-demand), run the functional list, and fill the log with step, command, who, duration and automation notes. No registration, no change to the app host, and no DNS change happens before the explicit go.
