# Decisions log

Reconstructed on 2026-10-12 from repository documents, implementation and `git log`; dates below are repository commit dates, not inferred live deployment times. The binding [TENANT_API.md](TENANT_API.md) overrides earlier sketches. No live state was checked. New policy changes require a new dated entry rather than rewriting this history.

| Date | Decision and consequence | Repository evidence |
| --- | --- | --- |
| 2026-09-23 | Build a parallel edge/agent path; leave existing production delivery intact and prod1 untouched. No additional VPS/domain/payment spend is authorized | `41fb63a`, `0d76dca`; [local deployment](../deploy/LOCAL_PROD.md) |
| 2026-09-24 | ns1 shares the edge; ns2 is a separate Hetzner DNS-only host. Zones are exported/copied, not AXFR. Registrar changes remain a separate gated operation | `a7a001a`; [NS cut runbook](../deploy/NS_CUT.md) |
| 2026-09-24 | Billing scaffold is Stripe test mode only, with explicit test-key checks; it does not authorize live charging | `0b7cd15`; [billing](BILLING.md) |
| 2026-10-06 | Hostname attach is the default first-seat path; customer retains registrar/DNS, with NS cut optional | `110252c`, `5808979`; [attach design](HOSTNAME_ATTACH.md) |
| 2026-10-08 | Public pricing locked: Hobby $9/month, Pro $29/month, Agency $149/month. Domain pricing at cost. Legacy Starter/test checkout and assigned portal plans are separate implementations, not automatic production subscriptions | `e77d7a0`; [site source](../site/index.html), [plans](../src/billing/plans.js) |
| 2026-10-08 | Verdict default failure policy is open for bot-auth outages. Explicit off/shadow bypass enforcement; only the designated demo may be enforced operationally, and guardrail hosts never are | `fb1538b`, `d638a1b`; [edge guide](../verdict/deploy/EDGE.md), [host policy](../verdict/src/config/hosts.js) |
| 2026-10-08 | ASN data uses free iptoasn only, with a compact streamed refresh; no paid enrichment or new spend | `62240e2`, `fb1538b`; [ASN refresh](../verdict/scripts/asn-refresh.js), [edge guide](../verdict/deploy/EDGE.md) |
| 2026-10-08 | Domain search is read-only and budget-capped; lookup/pricing only, no registrar writes. Persist daily call budget across restarts when state is configured | `57c23d5`, `70607f4`; [search](../domain-search/README.md), [implementation](../domain-search/src/service.js) |
| 2026-10-09 | Tenant contract separates portal/internal/operator keys and enforces ownership twice. Tenant activation needs routing and TXT, not routing alone. Node built-ins only for new modules | `d3a8a87`; [contract](TENANT_API.md) |
| 2026-10-10 | Portal is invite-only, email-verified, single-writer JSON with file outbox and operator-assigned plans. No SMTP or automated purchase integration | `c227981`; [portal](../portal/README.md) |
| 2026-10-12 | Resource caps reject new sessions/rate-limit admissions without evicting valid existing entries; caps are a service safety boundary | `1f7c2ea`; [backlog](DAY2_BACKLOG.md) |
| 2026-10-12 | TLS ask and routing re-check are opt-in/default-off. Re-check suspension revokes credentials; recovery requires explicit routing plus TXT and a new credential | `386ebef`, `b4b9e38`; [internal operations](INTERNAL_API_OPS.md) |
| 2026-10-12 | Keep both flags off until denial-metering/owner-index and indefinitely inconclusive DNS findings are fixed. Handover completion does not close those findings | `5afa603`; [open reviews](DAY2_BACKLOG.md) |

Historical notes that say single NS, proposed pricing, unauthenticated control APIs or wildcard LAN binding are not current implementation guidance. Inventory values without evidence remain `TODO(operator)`. The handover's `fdportal` deployment target is a requirement, not a claim that a portal unit has been installed.
