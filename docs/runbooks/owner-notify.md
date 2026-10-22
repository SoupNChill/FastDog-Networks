# Owner notifications and daily digest

Operator-only mail about portal activity. Both features are off by default and
fail open: a mail or data problem never changes a customer response or account.
Settings live in the portal environment file `/etc/fastdog/portal.env` (owner
`root`); edit it with your usual editor and never paste its contents into chat,
tickets or logs. Keys and behaviour: [portal README](../../portal/README.md)
("Owner notifications" and "Owner digest").

- Instant notices (sign-up, first verification, trial pause) come from the running
  portal when `OWNER_NOTIFY_EMAIL` is set.
- The daily digest is `portal/bin/owner-digest.js`, started by
  `fastdog-owner-digest.timer` at 08:00 America/Denver, for the previous
  Mountain-time day. It needs `OWNER_DIGEST_ENABLED=1` and `OWNER_NOTIFY_EMAIL`.

## Digest classification settings

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `OWNER_DIGEST_INTERNAL_EMAILS` | Empty | Comma-separated exact internal addresses, normalized case-insensitively; invalid entries ignored. |
| `OWNER_DIGEST_INTERNAL_AUTO` | `1` | Set `0` to disable owner/plus-address and reserved test-domain detection. Explicit addresses and tenant/user `internal: true` or `test: true` flags still apply. |
| `OWNER_DIGEST_SHADOW_FILE` | Unset (off) | Absolute path to Verdict shadow JSONL; windowed challenge/block prefix+path matches count as bots. Missing/unreadable files are skipped. The digest unit needs read access to this file, which is not granted today; an operator must arrange file permissions and unit sandbox access before enabling. |

Customer totals and trials exclude internal tenants; hostname inventory still covers
all non-suspended tenants. The digest shows an internal account count without emails.
Visitors count humans only; empty/scanner UAs and probe paths count as bots, with
probe requests counted across all methods/statuses. Shadow joins are bounded at
200,000 entries per collector and expose `shadow_join` as `on`, `off`, or `unavailable`.

## Enable

1. Back up as in the [deploy runbook](deploy.md) and stage the new portal build.
2. In the portal environment file set `OWNER_NOTIFY_EMAIL` to the operator
   address and `OWNER_DIGEST_ENABLED=1`. For visitor counts
   also set `OWNER_DIGEST_VISITORS=1` and `OWNER_DIGEST_SITE_LOGS=access-site.json`
   (file names in `/var/log/caddy` only); optionally `OWNER_DIGEST_FUNNEL_LOG`.
   The `fdportal` account reads the logs through the `caddy` group
   (`SupplementaryGroups=caddy`); the log files must be group-readable.
3. Restart the portal unit so instant notices pick up the address.
4. Install and start the timer:

   ```sh
   sudo install -m 0644 deploy/fastdog-owner-digest.service deploy/fastdog-owner-digest.timer /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now fastdog-owner-digest.timer
   systemctl list-timers fastdog-owner-digest.timer
   ```

The service runs as `fdportal` with `Nice=10`, `CPUQuota=20%`, `MemoryMax=96M`
and idle I/O, writes only under `/var/lib/fastdog-portal` and reads
`/var/log/caddy`. If `OUTBOX_DIR` points elsewhere, add it to `ReadWritePaths`.

## Test

Run as the service would, without reading the environment file in a shell:

```sh
# Preview: prints the summary lines, sends and writes nothing (works while disabled).
sudo systemd-run --wait --pipe --quiet -p User=fdportal -p Group=fdportal -p SupplementaryGroups=caddy \
  -p EnvironmentFile=/etc/fastdog/portal.env -p WorkingDirectory=/opt/fastdog-portal \
  -E STATE_DIRECTORY=/var/lib/fastdog-portal /usr/bin/node portal/bin/owner-digest.js --dry-run

# One owner-event mail ("Test notice from the FastDog portal (owner notifications are on).").
sudo systemd-run --wait --pipe --quiet -p User=fdportal -p Group=fdportal \
  -p EnvironmentFile=/etc/fastdog/portal.env -p WorkingDirectory=/opt/fastdog-portal \
  -E STATE_DIRECTORY=/var/lib/fastdog-portal /usr/bin/node portal/bin/owner-digest.js --test-notice

# A real digest now (skips with reason already_sent if today's went out).
sudo systemctl start fastdog-owner-digest.service
journalctl -u fastdog-owner-digest.service -n 5 --no-pager
```

The journal line is `{"event":"owner_digest","result":"sent"}` (or `skipped`,
`disabled`, `failed` with a reason code). Exit 1 means invalid configuration;
exit 2 means the mailer did not deliver (the day is not marked sent, so the next
run or `--force` retries). Exit 3 (`sent` with reason `state_write_failed`) means
the mail went out but the day could not be recorded, so check the state directory
before the next run or it sends again. With `MAIL_TRANSPORT=file` the outbox holds
only an audit record (`to`, `kind`), never the summary lines, so the result is
`queued_file` and the day is never marked sent. `--dry-run` always masks
addresses, whatever `OWNER_NOTIFY_SHOW_EMAIL` says. One run at a time: a second run
while the lock directory `owner-digest.lock` is held logs `skipped`/`locked`; a
lock older than 10 minutes is treated as left by a crash and taken over.

## Disable

- Digest only: set `OWNER_DIGEST_ENABLED=0` (runs then print
  `owner digest disabled`) and `sudo systemctl disable --now fastdog-owner-digest.timer`.
- Everything: blank `OWNER_NOTIFY_EMAIL=` and restart the portal unit; also
  disable the timer as above.

Rollback of the code follows the [rollback runbook](rollback.md); the only state
file is `/var/lib/fastdog-portal/owner_digest.json` (`last_sent_day`), safe to
delete.
