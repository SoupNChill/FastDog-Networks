# Fastdog Networks DNS inventory (pre-cut)

Public DNS observations supplied for this preparation are from 2026-09-24. Cloudflare nameservers remain authoritative. Recheck live answers and the Cloudflare DNS UI before any cutover. `NoAnswer` means the queried type has no public answer; it does **not** prove that no other name or Cloudflare-only configuration exists. Live CoreDNS column verified post-sync on 2026-09-24 (MT) at serial `2026092401` via dig @157.230.57.32.

| Record | Currently public / Cloudflare | In Fastdog `zone.json`? | In live CoreDNS? |
| --- | --- | --- | --- |
| Apex NS | `duke.ns.cloudflare.com`, `melany.ns.cloudflare.com` | Yes: `ns1` only for soak | Yes: `ns1` only |
| Apex SOA | Cloudflare SOA | Yes: `2026092401` | Yes: `2026092401` (synced) |
| Apex A | NoAnswer | Yes: `157.230.57.32` placeholder | Yes: `157.230.57.32` |
| Apex AAAA | NoAnswer | No | No |
| Apex MX | NoAnswer | No | No |
| Apex TXT | NoAnswer | No | No |
| Apex CAA | NoAnswer | No | No |
| `edge` A | `157.230.57.32`, grey-cloud | Yes: `157.230.57.32` | Yes: `157.230.57.32` |
| `whoami` A | `157.230.57.32`, grey-cloud | Yes: `157.230.57.32` | Yes: `157.230.57.32` |
| `ns1` A | NXDOMAIN | Yes: `157.230.57.32` | Yes: `157.230.57.32` |
| `ns2` A | NXDOMAIN | No; real host and address TBD | No |
| `www` A/CNAME | NXDOMAIN | No | No |
| `mail` A/CNAME | NXDOMAIN | No | No |
| `_fastdog` TXT | Not reported in public baseline; verify | Yes: `fastdog-edge-phase1-coredns` | Yes: same marker |
| Other named records | Not enumerable from public DNS | Unknown until CF UI audit | Unknown until CF UI audit |

The Fastdog zone is a **candidate** authoritative zone, not the current public zone. Its apex A is a placeholder and must be approved before cutover. Repo and live PoP both serve SOA serial `2026092401` after sync on 2026-09-24.

## Gaps Pete must confirm in CF UI

- MX priorities and mail host A/AAAA/CNAME records, plus whether any email service exists despite public apex MX NoAnswer.
- All TXT records: SPF, DKIM selectors, DMARC, service/domain verifications, and any named TXT owners.
- All CAA policies, including names below the apex.
- Every orange-cloud hostname, wildcard, redirect, Worker, or rule. `dig` cannot enumerate names and may show proxy IPs instead of origin records.
- Intended `www` behavior: A/AAAA/CNAME, redirect, or deliberately absent.
- Whether the Fastdog apex A placeholder should stay `157.230.57.32`, be changed, or be removed before cutover.

Resolve these in the [NS cutover runbook](NS_CUT.md) checklist before Pete approves the flip.
