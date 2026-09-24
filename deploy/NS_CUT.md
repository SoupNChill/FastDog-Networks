# Fastdog Networks nameserver cutover runbook

**Status: preparation only. DO NOT change registrar nameservers yet.** Pete must approve the cutover after every gate below is green. This runbook applies only to `fastdognetworks.com`.

## Roles and prerequisites

- `ns1.fastdognetworks.com` stays on the existing DigitalOcean `edge-fastdog` PoP, `157.230.57.32`, where CoreDNS serves the zone on UDP and TCP port 53. Keep edge and whoami HTTPS healthy.
- `ns2.fastdognetworks.com` is a future Hetzner DNS-only secondary in Helsinki (`hel1`), geographically separate from the NYC DigitalOcean PoP. **It has no address now. Do not publish its A or NS record until the host is real and serving the complete zone.**
- Confirm CoreDNS and both HTTPS hosts have soaked without errors for at least 48 hours. After ns2 is commissioned, soak **both** nameservers for at least 48 hours with matching answers before the flip.
- Obtain Pete's explicit approval for Hetzner spending/provisioning and, separately, for the registrar flip. Do not provision ns2 during preparation.
- Complete the [record inventory](ZONE_INVENTORY.md) in Cloudflare's DNS UI. Copy every needed public record into the Fastdog JSON zone and serve it from both nameservers. Resolve the apex A and `www` behavior with Pete.
- Create Cloudflare Registrar child nameserver/host (glue) records for **both** `ns1` and `ns2` using their real public IPv4 addresses **before** changing the registrar nameservers. Verify their addresses and parent delegation via `dig`/WHOIS or the registrar UI. Glue is separate from A records in the authoritative zone.
- Keep the current Cloudflare NS pair, `duke.ns.cloudflare.com` and `melany.ns.cloudflare.com`, recorded for rollback.

## Record migration checklist

Use the Cloudflare DNS UI as the complete source of truth: public DNS cannot enumerate orange-cloud records or all names. Add every required record to the Fastdog zone before the flip and compare answers on **both** servers. The table is a starting checklist, not proof the Cloudflare zone is complete.

| Record | Must exist in Fastdog zone before flip | Verify in Cloudflare UI |
| --- | --- | --- |
| Apex SOA and NS | SOA serial current; NS includes real `ns1` and `ns2` | Current Cloudflare delegation; later registrar glue for both |
| `ns1` A, `ns2` A | Both real public IPv4 addresses; ns1 = `157.230.57.32` | Child nameserver/glue addresses match zone A records |
| `edge` A | `157.230.57.32` | Grey-cloud A and any AAAA/CNAME |
| `whoami` A | `157.230.57.32` | Grey-cloud A and any AAAA/CNAME |
| Apex A/AAAA | Pete-approved destination; current Fastdog A is a placeholder at `157.230.57.32` | Check all apex records and intended service |
| `www` A/AAAA/CNAME | Pete-approved destination or explicit decision to leave absent | Check record, proxy state, redirect/page rule |
| MX and `mail` host records | Every active mail-routing and mail-host record, if any | Check MX priorities and A/AAAA/CNAME for mail hosts |
| TXT | SPF, DKIM, DMARC, verification and other needed TXT values | Check apex and every named TXT owner; include `_fastdog` marker as applicable |
| CAA | Every intended CAA policy, if any | Check apex and named CAA records |
| Other A/AAAA/CNAME/SRV/CAA/TXT | Every required hostname and value | Review full Cloudflare export/UI, including orange-cloud and wildcard records |

If Cloudflare proxy, redirects, Workers, or rules currently implement a hostname, decide how that behavior will work after the zone leaves Cloudflare DNS; copying an orange-cloud A value alone may not preserve it. Record each resolution in the inventory.

## Future ns2 build (placeholder; do not execute now)

1. After Pete authorizes spending, choose a Hetzner CX23 or the least expensive suitable VM with public IPv4 in Helsinki (`hel1`); verify current plan, IPv4 availability, and price at order time. Keep it DNS-only.
2. Permit inbound `53/udp`, `53/tcp`, and `22/tcp` only; restrict SSH source where practical. Do not expose CoreDNS health/metrics ports. Install and configure CoreDNS using [installation notes](coredns/INSTALL.md) adapted for the second host.
3. Export the **same** `fastdognetworks.com` JSON zone to BIND format on ns2. This is a file-synced second authoritative server; no AXFR/secondary automation exists yet. Ensure CoreDNS can reload it safely.
4. Add the real `ns2` A and second apex NS to `zones/fastdognetworks.com.json`, bump the SOA serial, then run `scripts/sync-coredns.sh fastdognetworks.com` on **both PoPs** (or copy the locally exported zone file and send SIGUSR1). Confirm serial and all answers match.
5. Create registrar child nameserver/glue records for ns1 and ns2 with their real addresses. Test from outside both hosts and soak both for at least 48 hours. Do not flip if either fails.

## Pre-flight (before Pete says go)

From an external machine, save complete outputs, including status, authority, and TTL; `+short` alone can hide NXDOMAIN versus NoAnswer. Substitute ns2's **real** IP only after it exists.

```sh
dig fastdognetworks.com NS
dig fastdognetworks.com SOA
dig edge.fastdognetworks.com A
dig whoami.fastdognetworks.com A
dig fastdognetworks.com MX
dig fastdognetworks.com TXT
dig fastdognetworks.com CAA
dig +trace fastdognetworks.com NS

dig @157.230.57.32 fastdognetworks.com SOA +norecurse
dig @157.230.57.32 fastdognetworks.com NS +norecurse
dig @157.230.57.32 ns1.fastdognetworks.com A +norecurse
dig @157.230.57.32 ns2.fastdognetworks.com A +norecurse
dig @157.230.57.32 edge.fastdognetworks.com A +norecurse
dig @157.230.57.32 whoami.fastdognetworks.com A +norecurse
dig @157.230.57.32 _fastdog.fastdognetworks.com TXT +norecurse

# Set this only after ns2 has a real public address; then repeat the full list:
NS2_IP='replace-with-real-public-IPv4'
dig @"$NS2_IP" fastdognetworks.com SOA +norecurse
dig +tcp @"$NS2_IP" fastdognetworks.com SOA +norecurse
dig @"$NS2_IP" fastdognetworks.com NS +norecurse
```

Compare all rows of the migration checklist at `@ns1` and `@ns2`; both must be authoritative and return the same SOA serial and intended records. Check `dig +tcp` against ns1 too. Confirm glue and parent delegation resolve both nameserver addresses, and test `https://edge.fastdognetworks.com/` and `https://whoami.fastdognetworks.com/`.

## Registrar flip (only after Pete explicitly approves)

In Cloudflare Registrar for **fastdognetworks.com**, verify both child nameserver/glue host records are present and point at the actual IPv4 addresses. Set custom nameservers to `ns1.fastdognetworks.com` and `ns2.fastdognetworks.com`. Save the registrar change and its timestamp. Do not change any other domain.

## Soak after flip

For at least 48 hours, repeatedly query public resolvers and each authoritative server for SOA, NS, ns1/ns2 A, edge A, whoami A, apex A, `_fastdog` TXT, and every migrated mail/verification/CAA record. Compare serials and watch for SERVFAIL, lame delegation, missing glue, and unexpected NXDOMAIN. Verify both UDP and TCP port 53 and check CoreDNS service logs on both hosts. Check edge and whoami HTTPS and real application behavior during the soak. If a record or server fails, fix it promptly or roll back.

## Rollback

At Cloudflare Registrar, set nameservers back to **`duke.ns.cloudflare.com` and `melany.ns.cloudflare.com`**. Keep the Cloudflare DNS zone intact and verify its records before relying on rollback. Check parent delegation and recursive resolver answers afterward, plus edge and whoami HTTPS. Cached delegation and records may persist according to their TTLs; allow up to 48 hours for broad propagation and monitor both old and new paths. Record the rollback timestamp and incident details.

## DO NOT

- Do not change Cloudflare registrar nameservers before Pete explicitly approves the flip and all gates pass.
- Do not provision or pay for Hetzner/DO resources during preparation; do not publish a fake ns2 address or NS record.
- Do not touch `trysummitlease.com`, Summit Lease, or `prod1`.
- Do not break `whoami` or edge HTTPS; do not expose CoreDNS health/metrics ports publicly.
- Do not treat the current single-NS zone as production-ready or assume public DNS lists all Cloudflare records.
- Do not commit or print secrets from `deploy/whoami-public/.env`.
