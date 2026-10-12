# Rollback

Trigger rollback for a new release causing listener/authentication failures, cross-tenant access, broken proxying, missing state or sustained tunnel disconnects. Record the failing release and symptoms without secrets. Scope changes to the affected service; do not restart prod1 or unrelated LAN services.

1. Preserve the failed release and a restricted snapshot of current state for diagnosis. Stop the affected writer before any restore. Locate the pre-deploy backup from [deploy.md](deploy.md); do not guess a backup directory or restore over a running JSON writer.
2. Prefer reverting application code/configuration while retaining current compatible state. Inspect schema compatibility before restarting. Never blindly restore stale credential, invite, session or key files: that can revive revoked access, consumed invites or reset links. If a state restore is unavoidable, reconcile post-backup activations, detachments and revocations with the operator and rotate affected access before reopening service.
3. Restore the previous reviewed release from `/root/backups/<tag>-<timestamp>/code.tgz`: inspect its member paths privately, then untar it into the extraction root recorded at backup time (`tar -xzf /root/backups/<tag>-<timestamp>/code.tgz -C <recorded-extraction-root>`; substitute confirmed paths). Remove or isolate failed-release code first so newly added files do not survive the restore; preserve external runtime env/state. Use the same manager, ownership and loopback binds. Keep a single writer. Restore Caddy using [cert-caddy.md](cert-caddy.md): save the current file, validate the saved candidate, then reload. Keep control-route blocking and guardrail protections in the restored config.
4. Restart only affected units after extraction, for example `sudo systemctl restart fastdog-edge` or `sudo systemctl restart fastdog-portal` for the corresponding restored service. Repeat the deployment acceptance checks, including ownership isolation and agent reconnection. Preserve the domain-search daily call counter. Record recovery time, revision and remaining issues.

| Change | Specific rollback |
| --- | --- |
| TLS ask | Restore the prior explicit-host Caddy configuration and validate/reload first; disable `TLS_ASK_ENABLED` and restart edge. Disabling ask does not revoke cached certificates |
| Claim re-check | Disable `RECHECK_ENABLED` and restart edge; this stops scheduling but does not restore suspended claims or revoked credentials. Restore routing/TXT and explicitly verify, then install the fresh agent credential |
| Internal tenant API | Disable `INTERNAL_ENABLED` and restart edge; portal hostname operations stop, but stored active hosts/credentials and public control authentication remain |
| Portal release | Untar the release backup and restart `fastdog-portal`; `/opt/fastdog-portal.old` also retains the previous code for comparison/recovery. Preserve accounts and revocations. Keep the portal login and removed Caddy basic-auth gate unchanged. Password reset revokes sessions; do not reverse that by restoring old session state |
| DNS records | Reapply known-good records with a serial higher than every published version, export/sync both servers and verify; see [dns-changes.md](dns-changes.md) |
| Verdict | Remove demo forward-auth using a validated Caddy candidate to restore application access; revert only `verdict-edge` if needed. Preserve key revocations, usage and logs |

Registrar rollback is distinct from zone rollback and requires the separately authorized [NS cut procedure](../../deploy/NS_CUT.md). Confirm the current prior delegation with the operator; historical nameserver notes are not a current inventory. Cache TTLs can delay recovery. No registrar or DNS-provider changes are implied here.
