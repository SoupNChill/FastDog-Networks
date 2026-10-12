# DNS changes and ns1/ns2 synchronization

Source: `zones/*.json`, `src/dns/`, [CoreDNS deployment](../../deploy/coredns/INSTALL.md) and [NS cut gates](../../deploy/NS_CUT.md). ns1 is on edge `157.230.57.32`; ns2 is the documented Hetzner DNS-only box `2.29.58.90`. These addresses are repository facts, not a fresh reachability check. There is no AXFR; both servers need the same exported file.

1. Confirm the exact authorized zone and current delegation. Distinguish an attach CNAME/TXT change at the existing DNS provider from changing FastDog's authoritative zone. Do not change unrelated zones or registrar NS. Preserve mail, verification, CAA and all other records; public queries cannot enumerate an entire provider zone.
2. Record each server's current SOA serial and record set during the authorized online window. Back up source JSON, each deployed BIND zone and Corefile with timestamp and owner. Stop/constrain the control-plane writer while editing source.
3. Edit only the required records. Increase the serial field inside the SOA record’s `content` string in `records[]` (the JSON has no separate `soa.serial` property) above both deployed serials and the repository serial, conventionally `YYYYMMDDnn`; multiple same-day edits increment `nn`. Do not reuse or decrement serials on rollback. The infrastructure zone in base `5afa603` has serial `2026101201`; older examples are historical, not values to copy.
4. Validate without network or writes (replace the synthetic zone with the exact approved zone already present in the checkout):

   ```sh
   COREDNS_SYNC_DRY_RUN=true bash scripts/sync-coredns.sh example.test
   node src/dns/export-cli.js example.test > /tmp/example.test.zone.candidate
   ```

   Use the Node exporter directly for clean BIND output; ordinary `npm run` adds script banners unless silent. Review the candidate against the saved zone. Built-in validation checks SOA/NS and nameserver addresses; it is not a substitute for the installed DNS server parsing the complete candidate.
5. For an authorized deployment, stage the reviewed BIND file on both boxes, preserving `coredns` ownership under `/etc/coredns/zones/`. Verify identical content/checksums before installation, replace each zone, then `sudo systemctl reload fastdog-coredns` on each. A new zone also needs a reviewed `file` entry in each `/etc/coredns/Corefile`; use the documented restart for Corefile changes. Confirm service health and parse errors after reload.
6. If using automated Node sync, explicitly review `COREDNS_POP_TARGETS`, `COREDNS_SSH_USER`, key path, remote zones directory and reload command before enabling `COREDNS_SYNC_ENABLED`. Record results in `DATA_DIR/audit/coredns-sync.jsonl`. **The shell script writes local zones and reloads even when this flag is false; only its explicit dry-run prevents that.** Remote copy is not a distributed atomic operation, and reload commands can mask failure. A success exit/audit entry does not prove matching live answers.
7. Query both ns1 and ns2 with `dig @<NS_IP> example.test SOA +norecurse`, then repeat with `+tcp`; replace placeholders for authorized live checks. Require authoritative (`aa`) answers, matching increased serials and all intended NS/A/AAAA/CNAME/MX/TXT/CAA records. Verify affected HTTPS/application behavior separately. If only one server updates, stop the rollout and repair the mismatch or publish known-good records with a newer serial to both.

Keep a record of old/new serials, checksums, backup paths and verification times. Registrar delegation/glue changes require the separate NS-cut gates, complete provider inventory and soak; a zone sync does not perform or authorize them. For rollback, keep serials increasing and follow [rollback.md](rollback.md).
