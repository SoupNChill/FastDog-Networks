# Rollback

Trigger rollback for a new release causing listener/authentication failures, cross-tenant access, broken proxying, missing state or sustained tunnel disconnects. Record the failing release and symptoms without secrets. Scope changes to the affected service; do not restart prod1 or unrelated LAN services.

1. Preserve the failed release and a restricted snapshot of current state for diagnosis. Stop the affected writer before any restore. Locate the pre-deploy backup from [deploy.md](deploy.md); do not guess a backup directory or restore over a running JSON writer.
2. Prefer reverting application code/configuration while retaining current compatible state. Inspect schema compatibility before restarting. Never blindly restore stale credential, invite, session or key files: that can revive revoked access, consumed invites or reset links. If a state restore is unavoidable, reconcile post-backup activations, detachments and revocations with the operator and rotate affected access before reopening service.
3. Restore the previous reviewed release with the same manager, ownership and loopback binds. Keep a single writer. Restore Caddy using [cert-caddy.md](cert-caddy.md): save the current file, validate the saved candidate, then reload. Keep control-route blocking and guardrail protections in the restored config.
4. Start only affected services. Repeat the deployment acceptance checks, including ownership isolation and agent reconnection. Preserve the domain-search daily call counter. Record recovery time, revision and remaining issues.

| Change | Specific rollback |
| --- | --- |
| TLS ask | Restore the prior explicit-host Caddy configuration and validate/reload first; disable `TLS_ASK_ENABLED` and restart edge. Disabling ask does not revoke cached certificates |
| Claim re-check | Disable `RECHECK_ENABLED` and restart edge; this stops scheduling but does not restore suspended claims or revoked credentials. Restore routing/TXT and explicitly verify, then install the fresh agent credential |
| Internal tenant API | Disable `INTERNAL_ENABLED` and restart edge; portal hostname operations stop, but stored active hosts/credentials and public control authentication remain |
| Portal release | Restore compatible code; preserve accounts and revocations. Password reset revokes sessions; do not reverse that by restoring old session state |
| DNS records | Reapply known-good records with a serial higher than every published version, export/sync both servers and verify; see [dns-changes.md](dns-changes.md) |
| Verdict | Remove demo forward-auth using a validated Caddy candidate to restore application access; revert only `verdict-edge` if needed. Preserve key revocations, usage and logs |

Registrar rollback is distinct from zone rollback and requires the separately authorized [NS cut procedure](../../deploy/NS_CUT.md). Confirm the current prior delegation with the operator; historical nameserver notes are not a current inventory. Cache TTLs can delay recovery. No registrar or DNS-provider changes are implied here.
