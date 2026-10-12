# Operator inventory skeleton

As of repository base `5afa603`, 2026-10-12. **Source evidence only; no live audit.** `TODO(operator)` means fill from an authorized operator inspection. Paths with `<...>` are deliberate placeholders to avoid copying personal/customer identifiers. Exact legacy paths remain in the linked deployment sources. Record secret locations and owners only, never values. Do not paste environment files, process environments, outbox links or credential stores here.

## Edge / ns1 — 157.230.57.32

Documented DigitalOcean Ubuntu 24.04 box. Evidence: [NS cut](../deploy/NS_CUT.md), [self-serve plan](SELF_SERVE_PLAN.md), [Verdict deployment](../verdict/deploy/EDGE.md), [search unit](../deploy/domain-search.service). Installed versions/unit status and all backup retention policies: `TODO(operator)`.

| Service / unit | User | Ports / exposure | Code, state and config | Backups |
| --- | --- | --- | --- | --- |
| Caddy / `caddy` | TODO(operator) | Public HTTP/HTTPS 80/443; admin exposure TODO(operator) | `/etc/caddy/Caddyfile`; certificate storage TODO(operator); `/var/log/caddy/` | `/etc/caddy/Caddyfile.bak-<tag>-<date>`; certificate/import backups TODO(operator) |
| Edge / unit TODO(operator) | TODO(operator) | `127.0.0.1:8787`; operator `8788`; optional internal `8789` | `/opt/fastdog-edge`; configured `DATA_DIR` TODO(operator), default `data/`; `config/routes.yaml`, `zones/` | Restricted coherent state/release backup path TODO(operator) |
| CoreDNS / `fastdog-coredns` | `coredns` in template | UDP/TCP 53; template health `:8053`, metrics `:9153` | `/usr/local/bin/coredns`, `/etc/coredns/Corefile`, `/etc/coredns/zones/` | Zone/Corefile backups TODO(operator) |
| Portal / unit TODO(operator) | `fdportal` handover target; installed account TODO(operator) | `127.0.0.1:8790` | Release path TODO(operator); target `/var/lib/fastdog-portal/`, private `outbox/` | Path/schedule/retention TODO(operator) |
| Domain search / `domain-search` template | `fastdog` | `127.0.0.1:8791` | `/opt/fastdog/domain-search`; `StateDirectory=domain-search` gives `/var/lib/domain-search/daily-count.json` | Persistent budget backup TODO(operator) |
| Verdict / `verdict-edge` template | `root` (dedicated user permitted by guide) | `127.0.0.1:8089` | `/opt/verdict`, `/opt/verdict/data/` | Keys/usage/release backups TODO(operator) |
| Verdict shadow + summary/ASN timers | `root` in templates | No listener | `verdict-shadow.service`, `verdict-shadow-summary.timer`, `verdict-asn-refresh.timer`; `/opt/verdict/data/` | Log/summary/ASN retention TODO(operator) |
| Marketing / static assets | Served by configured web process; owner TODO(operator) | HTTPS through Caddy | Repository `site/`; installed root TODO(operator) | Release backup TODO(operator) |

ns1's checked-in Corefile binds health/metrics without loopback; its firewall/live binding is `TODO(operator)`. Do not assume it matches ns2's safer loopback template. Keep these ports private.

| Secret location | Owner |
| --- | --- |
| `/opt/fastdog-edge/.env` | TODO(operator) |
| Portal environment file: TODO(operator) | TODO(operator); service identity `fdportal` |
| Edge `DATA_DIR/agent-credentials.json`, `invites.json`, `tenant_hostnames.json` | TODO(operator) |
| `/var/lib/fastdog-portal/accounts.json`, `sessions.json`, `outbox/` (target) | `fdportal` target; verify installation |
| `/etc/fastdog/domain-search.env` | `root:root` documented |
| `/etc/fastdog/verdict.env` | `root` documented |
| `/opt/verdict/data/keys.json` | `root` under supplied unit; verify substitutions |
| Caddy certificate/private-key storage: TODO(operator) | TODO(operator) |
| DNS sync SSH private-key path: TODO(operator) | TODO(operator) |

## ns2 — Hetzner

[NS cut source](../deploy/NS_CUT.md) records IPv4 `2.29.58.90`, CX23, hel1/Helsinki, Ubuntu 24.04 and CoreDNS 1.14.7 at commissioning. Current versions remain `TODO(operator)`.

| Service / unit | User | Ports / exposure | Paths | Backups |
| --- | --- | --- | --- | --- |
| CoreDNS / `fastdog-coredns` | `coredns` template | UDP/TCP 53; `127.0.0.1:8053` health, `127.0.0.1:9153` metrics | `/usr/local/bin/coredns`, `/etc/coredns/Corefile`, `/etc/coredns/zones/`; repo template `Corefile.ns2` | Zone/config backup path and retention TODO(operator) |
| SSH / unit TODO(operator) | TODO(operator) | 22/tcp; documented UFW permits 22 and DNS only | Authorized-key/config paths TODO(operator) | Recovery access TODO(operator) |

| Secret location | Owner |
| --- | --- |
| Host/access private-key locations: TODO(operator) | TODO(operator) |

File-copy sync, no AXFR. No edge, portal, registrar or Verdict credential is required by this DNS-only role. Additional installed services: `TODO(operator)`.

## server3 — LAN engineering

Documented LAN address `192.168.200.42`. Sources: [server3](../deploy/SERVER3.md), [local deployment](../deploy/LOCAL_PROD.md), [edge unit](../deploy/fastdog-edge.service). Personal account names are deliberately replaced below.

| Service / unit | User | Ports / exposure | Paths | Backups |
| --- | --- | --- | --- | --- |
| Script edge OR optional `fastdog-edge` | `<operator>`; confirm account | Edge 8787 on configured LAN/loopback; operator 8788 loopback; optional 8789 loopback | `~/projects/fastdog-edge`; `data/`, `logs/edge.pid`, `logs/edge.log`; `deploy/start-edge.sh` | TODO(operator) |
| Agent / optional `fastdog-agent` | `<operator>` | Outbound tunnel, no listener | Same checkout `agent/` | Private agent config backup TODO(operator) |
| Mock upstream | `<operator>` | `127.0.0.1:9999` | `scripts/mock-upstream.js` | Disposable lab state |
| Existing LAN Verdict | TODO(operator) | Legacy README reports 8080; actual bind TODO(operator) | Separate `~/projects/verdict`; leave running service alone | TODO(operator) |

| Secret location | Owner |
| --- | --- |
| `~/projects/fastdog-edge/.env` | `<operator>`; TODO(operator) actual account |
| `~/projects/fastdog-edge/data/` credential/invite stores | `<operator>`; TODO(operator) actual account |
| LAN Verdict secret paths: TODO(operator) | TODO(operator) |

Do not start a second edge manager or restart the running master deployment to run tests. Boot persistence/linger and active process manager are `TODO(operator)`.

## prod1 — read-only reference

Documented LAN address `192.168.200.7`. [Parallel deployment](../deploy/PARALLEL_DOGFOOD.md) and [agent template](../deploy/prod1-fastdog-agent/README.md) describe a separate outbound agent alongside existing production delivery. These notes do not authorize access or modification.

| Service / unit | User | Ports / exposure | Paths | Backups |
| --- | --- | --- | --- | --- |
| Existing application / compose | TODO(operator) | Documented agent upstream `http://app:3450` on existing Docker network; published ports TODO(operator) | `/opt/<existing-application>/`; exact paths in legacy guide | TODO(operator) |
| Existing Cloudflare tunnel / manager TODO(operator) | TODO(operator) | Existing outbound delivery; preserve | TODO(operator) | TODO(operator) |
| Separate agent / compose template | `<origin-owner>`; actual account TODO(operator) | Outbound to edge; no new inbound listener | `/home/<origin-owner>/fastdog-agent/`; external Docker network name in legacy guide | TODO(operator) |

| Secret location | Owner |
| --- | --- |
| `/home/<origin-owner>/fastdog-agent/.env` | `<origin-owner>`; TODO(operator) actual account |
| Existing application/tunnel secret paths: TODO(operator) | TODO(operator) |

Operator completion checklist: confirm managers/users, release revisions, binds/firewalls, effective data paths, backup destinations/retention/restore test date and secret-file ownership without exposing values. Reconcile historical deployment notes with current records before any operational action.

## Live edge facts (operator-verified 2026-10-12)

Edge facts (live, Oct 12): units: caddy, fastdog-edge (:8787, plus :8788 and :8789 in the same process), fastdog-portal (:8790), domain-search, fastdog-coredns (53 tcp/udp, 8053, 9153 metrics), verdict-edge, verdict-shadow, verdict-asn-refresh.timer, verdict-shadow-summary.timer, fail2ban, droplet-agent. Unknown node listeners: :8791, :8089.
Caddy: :80, :443 tcp+udp, admin on 127.0.0.1:2019. Caddyfile: /etc/caddy/Caddyfile, with backups in /etc/caddy/Caddyfile.bak-* and /root/backups/.
Secrets (path, owner, mode 600): /opt/fastdog-edge/.env (fastdog); /etc/fastdog/{domain-search,opensrs,opensrs_live_registrant_profile,opensrs_test_registrant,portal,verdict}.env and verdict-panel.key (root); /root/portal-review-credentials.txt, /root/portal-invites.txt, /root/*-invite*.txt (root); edge data /opt/fastdog-edge/data/agent-credentials.json (fastdog). Portal state: /var/lib/fastdog-portal (fdportal, 700).
Backups: /root/backups (edge-d2-*, Caddyfile.pre-edgeph-20261012-154808, edge.env.pre-internal-*, domain-search-*).
