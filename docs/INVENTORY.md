# Operator inventory skeleton

As of repository base `5afa603`, 2026-10-12. **Source review plus operator-supplied facts below; no live audit performed for this update.** `TODO(operator; see live sections below)` means fill from an authorized operator inspection. Paths with `<...>` are deliberate placeholders to avoid copying personal/customer identifiers. Exact legacy paths remain in the linked deployment sources. Record secret locations and owners only, never values. Do not paste environment files, process environments, outbox links or credential stores here.

## Edge / ns1 — 157.230.57.32

Documented DigitalOcean Ubuntu 24.04 box. Evidence: [NS cut](../deploy/NS_CUT.md), [self-serve plan](SELF_SERVE_PLAN.md), [Verdict deployment](../verdict/deploy/EDGE.md), [search unit](../deploy/domain-search.service). Installed versions/unit status and all backup retention policies: `TODO(operator; see live sections below)`.

| Service / unit | User | Ports / exposure | Code, state and config | Backups |
| --- | --- | --- | --- | --- |
| Caddy / `caddy` | TODO(operator; see live sections below) | Public HTTP/HTTPS 80/443; admin exposure TODO(operator) | `/etc/caddy/Caddyfile`; certificate storage TODO(operator); `/var/log/caddy/` | `/etc/caddy/Caddyfile.bak-<tag>-<date>`; certificate/import backups TODO(operator) |
| Edge / `fastdog-edge` (operator record) | TODO(operator; see live sections below) | `127.0.0.1:8787`; operator `8788`; optional internal `8789` | `/opt/fastdog-edge`; configured `DATA_DIR` TODO(operator), default `data/`; `config/routes.yaml`, `zones/` | `/root/backups/<tag>-<timestamp>/code.tgz`; separate restricted state/config backups |
| CoreDNS / `fastdog-coredns` | `coredns` in template | UDP/TCP 53; template health `:8053`, metrics `:9153` | `/usr/local/bin/coredns`, `/etc/coredns/Corefile`, `/etc/coredns/zones/` | Zone/Corefile backups TODO(operator; see live sections below) |
| Portal / `fastdog-portal` (operator record) | `fdportal` handover target; installed account TODO(operator; see live sections below) | `127.0.0.1:8790` | `/opt/fastdog-portal`; previous code `/opt/fastdog-portal.old`; target `/var/lib/fastdog-portal/`, private `outbox/` | `/root/backups/<tag>-<timestamp>`; schedule/retention TODO(operator) |
| Domain search / `domain-search` template | `fastdog` | `127.0.0.1:8791` | `/opt/fastdog/domain-search`; `StateDirectory=domain-search` gives `/var/lib/domain-search/daily-count.json` | Persistent budget backup TODO(operator; see live sections below) |
| Verdict / `verdict-edge` template | `root` (dedicated user permitted by guide) | `127.0.0.1:8089` | `/opt/verdict`, `/opt/verdict/data/` | Keys/usage/release backups TODO(operator; see live sections below) |
| Verdict shadow + summary/ASN timers | `root` in templates | No listener | `verdict-shadow.service`, `verdict-shadow-summary.timer`, `verdict-asn-refresh.timer`; `/opt/verdict/data/` | Log/summary/ASN retention TODO(operator; see live sections below) |
| Marketing / static assets | Served by configured web process; owner TODO(operator; see live sections below) | HTTPS through Caddy | Repository `site/`; installed root TODO(operator) | Release backup TODO(operator) |

ns1's checked-in Corefile binds health/metrics without loopback; its firewall/live binding is `TODO(operator; see live sections below)`. Do not assume it matches ns2's safer loopback template. Keep these ports private.

| Secret location | Owner |
| --- | --- |
| `/opt/fastdog-edge/.env` | `fastdog` (operator record) |
| `/etc/fastdog/portal.env` | `root`; service identity `fdportal` |
| Edge `DATA_DIR/agent-credentials.json`, `invites.json`, `tenant_hostnames.json` | TODO(operator; see live sections below) |
| `/var/lib/fastdog-portal/accounts.json`, `sessions.json`, `outbox/` (target) | `fdportal` target; verify installation |
| `/etc/fastdog/domain-search.env` | `root:root` documented |
| `/etc/fastdog/verdict.env` | `root` documented |
| `/opt/verdict/data/keys.json` | `root` under supplied unit; verify substitutions |
| Caddy certificate/private-key storage: TODO(operator; see live sections below) | TODO(operator) |
| DNS sync SSH private-key path: TODO(operator; see live sections below) | TODO(operator) |

## ns2 — Hetzner

[NS cut source](../deploy/NS_CUT.md) records IPv4 `2.29.58.90`, CX23, hel1/Helsinki, Ubuntu 24.04 and CoreDNS 1.14.7 at commissioning. Current versions remain `TODO(operator; see live sections below)`.

| Service / unit | User | Ports / exposure | Paths | Backups |
| --- | --- | --- | --- | --- |
| CoreDNS / `fastdog-coredns` | `coredns` template | UDP/TCP 53; `127.0.0.1:8053` health, `127.0.0.1:9153` metrics | `/usr/local/bin/coredns`, `/etc/coredns/Corefile`, `/etc/coredns/zones/`; repo template `Corefile.ns2` | Zone/config backup path and retention TODO(operator; see live sections below) |
| SSH / unit TODO(operator; see live sections below) | TODO(operator) | 22/tcp; documented UFW permits 22 and DNS only | Authorized-key/config paths TODO(operator) | Recovery access TODO(operator) |

| Secret location | Owner |
| --- | --- |
| Host/access private-key locations: TODO(operator; see live sections below) | TODO(operator) |

File-copy sync, no AXFR. No edge, portal, registrar or Verdict credential is required by this DNS-only role. Additional installed services: `TODO(operator; see live sections below)`.

## server3 — LAN engineering

Documented LAN address `192.168.200.42`. Sources: [server3](../deploy/SERVER3.md), [local deployment](../deploy/LOCAL_PROD.md), [edge unit](../deploy/fastdog-edge.service). Personal account names are deliberately replaced below.

| Service / unit | User | Ports / exposure | Paths | Backups |
| --- | --- | --- | --- | --- |
| Script edge OR optional `fastdog-edge` | `<operator>`; confirm account | Edge 8787 on configured LAN/loopback; operator 8788 loopback; optional 8789 loopback | `~/projects/fastdog-edge`; `data/`, `logs/edge.pid`, `logs/edge.log`; `deploy/start-edge.sh` | TODO(operator; see live sections below) |
| Agent / optional `fastdog-agent` | `<operator>` | Outbound tunnel, no listener | Same checkout `agent/` | Private agent config backup TODO(operator; see live sections below) |
| Mock upstream | `<operator>` | `127.0.0.1:9999` | `scripts/mock-upstream.js` | Disposable lab state |
| Existing LAN Verdict | TODO(operator; see live sections below) | Legacy README reports 8080; actual bind TODO(operator) | Separate `~/projects/verdict`; leave running service alone | TODO(operator) |

| Secret location | Owner |
| --- | --- |
| `~/projects/fastdog-edge/.env` | `<operator>`; TODO(operator; see live sections below) actual account |
| `~/projects/fastdog-edge/data/` credential/invite stores | `<operator>`; TODO(operator; see live sections below) actual account |
| LAN Verdict secret paths: TODO(operator; see live sections below) | TODO(operator) |

Do not start a second edge manager or restart the running master deployment to run tests. Boot persistence/linger and active process manager are `TODO(operator; see live sections below)`.

## prod1 — read-only reference

Documented LAN address `192.168.200.7`. [Parallel deployment](../deploy/PARALLEL_DOGFOOD.md) and [agent template](../deploy/prod1-fastdog-agent/README.md) describe a separate outbound agent alongside existing production delivery. These notes do not authorize access or modification.

| Service / unit | User | Ports / exposure | Paths | Backups |
| --- | --- | --- | --- | --- |
| Existing application / compose | TODO(operator; see live sections below) | Documented agent upstream `http://app:3450` on existing Docker network; published ports TODO(operator) | `/opt/<existing-application>/`; exact paths in legacy guide | TODO(operator) |
| Existing Cloudflare tunnel / manager TODO(operator; see live sections below) | TODO(operator) | Existing outbound delivery; preserve | TODO(operator) | TODO(operator) |
| Separate agent / compose template | `<origin-owner>`; actual account TODO(operator; see live sections below) | Outbound to edge; no new inbound listener | `/home/<origin-owner>/fastdog-agent/`; external Docker network name in legacy guide | TODO(operator) |

| Secret location | Owner |
| --- | --- |
| `/home/<origin-owner>/fastdog-agent/.env` | `<origin-owner>`; TODO(operator; see live sections below) actual account |
| Existing application/tunnel secret paths: TODO(operator; see live sections below) | TODO(operator) |

Operator completion checklist: confirm managers/users, release revisions, binds/firewalls, effective data paths, backup destinations/retention/restore test date and secret-file ownership without exposing values. Reconcile historical deployment notes with current records before any operational action.

## Live edge facts (operator-verified 2026-10-12)

Edge facts (live, Oct 12): units: caddy, fastdog-edge (:8787, plus :8788 and :8789 in the same process), fastdog-portal (:8790), domain-search, fastdog-coredns (53 tcp/udp, 8053, 9153 metrics), verdict-edge, verdict-shadow, verdict-asn-refresh.timer, verdict-shadow-summary.timer, fail2ban, droplet-agent. Listeners :8791 and :8089 match the search and Verdict source defaults; process attribution still needs operator confirmation.
Caddy: :80, :443 tcp+udp, admin on 127.0.0.1:2019. Caddyfile: /etc/caddy/Caddyfile, with backups in /etc/caddy/Caddyfile.bak-* and /root/backups/.
Secrets (path and owner only): /opt/fastdog-edge/.env (fastdog); /etc/fastdog/{domain-search,opensrs,opensrs_live_registrant_profile,opensrs_test_registrant,portal,verdict}.env and verdict-panel.key (root); /root/portal-review-credentials.txt, /root/portal-invites.txt, /root/*-invite*.txt (root); edge data /opt/fastdog-edge/data/agent-credentials.json (fastdog). Portal state: /var/lib/fastdog-portal (fdportal, 700).
Release backups: `/root/backups/<tag>-<timestamp>/code.tgz`; rollback untars code at the recorded extraction root and restarts the affected unit. Previous portal code: `/opt/fastdog-portal.old`. Retention remains `TODO(operator; see live sections below)`.

Portal authentication: own invite-only login; Caddy basic-auth gate removed. These deployment facts are operator-supplied, not inferred from a checked-in live Caddyfile.

## server3 (operator-verified 2026-10-12, read-only)

| Item | Value |
| --- | --- |
| Address / OS | LAN 192.168.200.42, Ubuntu kernel 6.8 |
| Role | Build and CI box: git worktrees `~/wt-*`, main checkout `~/projects/fastdog-edge`, coding-agent sandboxes `~/claude-sandbox`, `~/claude-home`; logs `~/day1-logs` |
| Units | `ssh`, `fail2ban`, `verdict` (Verdict dev/test instance) |
| Listeners | 22, 8080, 8787 (public interfaces, LAN only); 127.0.0.1:8089, 127.0.0.1:8788 |
| Backups | None of its own; the repo on GitHub is the source of truth |

| Secret location | Owner |
| --- | --- |
| `~/.ssh/fastdog_edge_vps_ed25519` (edge root key) | `mranderson` |
| `~/.ssh/fastdog_github_ed25519` (GitHub deploy/push key) | `mranderson` |
| `~/portal-review-pw.txt` (retired review-gate credential, 600) | `mranderson` |
| Coding-agent logins under `~/claude-home`, `~/.codex` | `mranderson` |

## ns2 live check

As of 2026-10-12, neither server3 nor the edge has a key for ns2 (2.29.58.90), so its live state is unverified. It is only observed through DNS: it serves the zone with an authoritative SOA (edge status check is green). An operator with ns2 access should fill in the remaining items.

## prod1 (operator-verified 2026-10-12, read-only; do not modify)

| Item | Value |
| --- | --- |
| Address | LAN 192.168.200.7, login user per operator SSH config |
| Units | `docker`, `containerd`, `ssh`, `fwupd` |
| Workloads | About 20 Docker compose containers from 7 projects under `/opt/<project>/`. Project names are not recorded here, per the name-scan rule (see the operator notes). They include two independent customer stacks with their own Cloudflare tunnels; they are out of scope and must not be touched. |
| FastDog pieces | Two outbound `fastdog-agent` containers (node:20-bookworm-slim) with no published ports |
| Listeners | 22, 80, 443, 4000, 8000, 8080, 7880/7881, 3478 (TURN); 127.0.0.1:2019, 127.0.0.1:7430 |
| Secrets | Per-project `.env` files under `/opt/<project>/` (owner: project operator) and agent tokens in the agent compose env (owner: origin owner). Paths are verified by the operator only. |
