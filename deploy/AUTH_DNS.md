# Authoritative DNS — Phase 1 (Prove Before Cutover)

Fastdog Edge Phase 1 authoritative DNS using CoreDNS on ns1 `edge-fastdog` (157.230.57.32, DigitalOcean) and ns2 `ns2-fastdog` (2.29.58.90, Hetzner hel1 DNS-only). Registrar NS flip still pending.

**Status:** Soak / prove mode. Do NOT change Cloudflare registrar NS until Pete approves.

## Overview

```
                          ┌───────────────────────────────────┐
                          │  edge-fastdog (157.230.57.32)     │
                          │  Ubuntu 24.04 DigitalOcean        │
                          ├───────────────────────────────────┤
dig @157.230.57.32 ──────►│  CoreDNS :53 (UDP/TCP)            │
                          │    └── /etc/coredns/zones/        │
                          │         └── fastdognetworks.com.zone
                          ├───────────────────────────────────┤
https://edge.* ──────────►│  Caddy → fastdog-edge :8787       │
                          │    └── /_fastdog/dns/* (API)      │
                          └───────────────────────────────────┘
```

- **Control plane:** fastdog-edge serves zones from `zones/*.json` via API
- **Export:** `npm run export-zones` or `scripts/sync-coredns.sh` converts to BIND format
- **Authoritative:** CoreDNS serves BIND zone files on port 53

## Prove It Works (Before Changing Anything)

Test authoritative responses directly against the PoP — no registrar changes needed:

```sh
# SOA record
dig @157.230.57.32 fastdognetworks.com SOA +short
# Expected after latest sync: ns1.fastdognetworks.com. hostmaster.fastdognetworks.com. 2026092401 3600 600 604800 300

# NS record
dig @157.230.57.32 fastdognetworks.com NS +short
# Expected: ns1.fastdognetworks.com.

# A records
dig @157.230.57.32 ns1.fastdognetworks.com A +short
# Expected: 157.230.57.32

dig @157.230.57.32 edge.fastdognetworks.com A +short
# Expected: 157.230.57.32

dig @157.230.57.32 whoami.fastdognetworks.com A +short
# Expected: 157.230.57.32

dig @157.230.57.32 fastdognetworks.com A +short
# Expected: 157.230.57.32

# TXT marker
dig @157.230.57.32 _fastdog.fastdognetworks.com TXT +short
# Expected: "fastdog-edge-phase1-coredns"
```

If all queries return expected values, CoreDNS is serving correctly.

## Firewall (UFW)

Open port 53 for DNS traffic:

```sh
sudo ufw allow 53/tcp comment 'CoreDNS TCP'
sudo ufw allow 53/udp comment 'CoreDNS UDP'
sudo ufw status
```

Verify from outside:

```sh
# From any machine with internet access
dig @157.230.57.32 fastdognetworks.com SOA
```

## Installation

See [coredns/INSTALL.md](coredns/INSTALL.md) for step-by-step CoreDNS setup.

Quick summary:

```sh
# 1. Install CoreDNS binary
# 2. Create coredns user and directories
# 3. Copy Corefile to /etc/coredns/
# 4. Export zones: ./scripts/sync-coredns.sh
# 5. Install and start systemd unit
```

## Zone Management

### View zones (control plane API)

```sh
curl -sS https://edge.fastdognetworks.com/_fastdog/dns/zones
curl -sS https://edge.fastdognetworks.com/_fastdog/dns/zones/fastdognetworks.com
```

### Edit zones

1. Edit `zones/fastdognetworks.com.json` (bump SOA serial!)
2. Commit and deploy to PoP
3. Run sync script:

```sh
./scripts/sync-coredns.sh fastdognetworks.com
```

Or export manually:

```sh
npm run export-zones -- fastdognetworks.com > /etc/coredns/zones/fastdognetworks.com.zone
sudo systemctl reload fastdog-coredns
```

### Add a new zone

1. Create `zones/newdomain.com.json` with SOA, NS, and records
2. Add a `file` directive to `/etc/coredns/Corefile`:
   ```
   file /etc/coredns/zones/newdomain.com.zone newdomain.com
   ```
3. Run `./scripts/sync-coredns.sh newdomain.com`
4. Restart CoreDNS: `sudo systemctl restart fastdog-coredns`

## Registrar NS Cutover — DO NOT CHANGE NS YET

Use the full [NS cutover runbook](NS_CUT.md) and [zone inventory](ZONE_INVENTORY.md). **DO NOT change Cloudflare registrar NS yet.** The `whoami` A record is now in the Fastdog zone for direct CoreDNS verification; Cloudflare remains publicly authoritative.

**Requirements before changing Cloudflare registrar NS:**

1. ✅ CoreDNS serving correct responses (prove with dig)
2. ⬜ Pete approval
3. ⬜ ns2 exists (second nameserver for redundancy)
4. ⬜ Both nameservers serve matching complete zones and have soaked for at least 48h with no issues
5. ⬜ Cloudflare Registrar glue/host records exist for both nameservers
6. ⬜ Cloudflare UI record inventory is complete and rollback plan is ready

**When ready (NOT NOW):**

At Cloudflare registrar for fastdognetworks.com:
- Change nameservers from Cloudflare to:
  - `ns1.fastdognetworks.com` (157.230.57.32)
  - `ns2.fastdognetworks.com` (TBD — second droplet)

**Rollback:** Change NS back to Cloudflare nameservers. TTL propagation takes up to 48h.

## Limitations (Phase 1)

| Limitation | Impact | Resolution |
|------------|--------|------------|
| Single NS (ns1 only) | No redundancy — RFC violation for production | Add ns2 on second droplet before cutover |
| No DNSSEC | Zone not signed | Future: add DNSSEC plugin to CoreDNS |
| Manual sync | Zone edits require SSH + script | Future: API-driven push or pull |
| No secondary/AXFR | Can't slave to ns2 | Future: configure zone transfer |

## Troubleshooting

### CoreDNS not responding

```sh
# Check service status
sudo systemctl status fastdog-coredns
journalctl -u fastdog-coredns -n 50

# Check if port 53 is bound
sudo ss -tulnp | grep ':53'

# Check firewall
sudo ufw status | grep 53
```

### Zone not loading

```sh
# Validate zone file syntax
coredns -conf /etc/coredns/Corefile -plugins | grep file
cat /etc/coredns/zones/fastdognetworks.com.zone

# Check CoreDNS logs for parse errors
journalctl -u fastdog-coredns | grep -i error
```

### systemd-resolved conflict

If port 53 is already bound by systemd-resolved:

```sh
sudo mkdir -p /etc/systemd/resolved.conf.d
echo -e "[Resolve]\nDNSStubListener=no" | sudo tee /etc/systemd/resolved.conf.d/no-stub.conf
sudo systemctl restart systemd-resolved
```

## Related Docs

- [NS_CUT.md](NS_CUT.md) — prerequisites, migration, flip, soak, and rollback
- [ZONE_INVENTORY.md](ZONE_INVENTORY.md) — public and candidate zone inventory
- [coredns/INSTALL.md](coredns/INSTALL.md) — CoreDNS installation steps
- [LOCAL_PROD.md](LOCAL_PROD.md) — LAN deployment (server3)
- [PARALLEL_DOGFOOD.md](PARALLEL_DOGFOOD.md) — Summit Lease parallel path (unchanged)

## Do NOT

- ❌ Change Cloudflare registrar NS without Pete's approval
- ❌ Touch trysummitlease.com zone or DNS (Summit Lease cutover is PARKED)
- ❌ Expose CoreDNS health/metrics ports to public internet
- ❌ Claim or provision a second droplet for ns2 without approval
- ❌ Assume this is production-ready (single NS = soak only)
