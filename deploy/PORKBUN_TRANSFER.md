# Porkbun transfer dry-run

**DRY-RUN ONLY. No unlock, authorization code request, payment, approval, registrar change, or transfer start.** Pete must explicitly say go after Saturday 2026-09-26 about 10:46 AM Mountain Time. This is a checklist for that later decision, not authorization to act.

1. Record the domain, current registrar, expiration, lock status, current NS, DNSSEC/DS state, and all DNS records. Save the current registrar's transfer and rollback instructions.
2. After Pete's go, unlock the domain at its current registrar. Request the transfer authorization code and keep it private.
3. Start the transfer at Porkbun, enter the authorization code, review the exact domain, cost, term, and contact details, then pay only with Pete's approval.
4. Approve the transfer email or current registrar release request. Track status until completion. Do not assume a transfer changes nameservers automatically.
5. Before any NS change, confirm both Fastdog authoritative servers answer the complete intended zone. For `fastdognetworks.com`, configure registrar child host/glue `ns1.fastdognetworks.com` → `157.230.57.32` and `ns2.fastdognetworks.com` → `2.29.58.90`; check the matching zone A records.
6. Set custom NS to `ns1.fastdognetworks.com` and `ns2.fastdognetworks.com` only at the approved cutover. Save the timestamp and prior NS values.
7. Verify with `dig +trace <domain> NS`, `dig <domain> NS`, and direct `dig @157.230.57.32 <domain> SOA +norecurse` and `dig @2.29.58.90 <domain> SOA +norecurse`; compare serials and required records, including mail and verification records.
8. If delegation or records fail, restore the recorded prior NS at the registrar, keep the prior DNS zone available, and verify parent and recursive answers. Cached delegations can persist until TTL expiry.

For Fastdog's existing Cloudflare registrar cutover, follow [NS_CUT.md](NS_CUT.md). Do not touch Summit Lease or prod1 as part of this dry-run.
