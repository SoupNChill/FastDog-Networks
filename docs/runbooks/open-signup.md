# Open signup: flip and rollback

This runbook does not authorize a deploy or the flip. The operator approves each step separately and follows [deploy.md](deploy.md) and [rollback.md](rollback.md). `portal/test/open-signup-flip.test.js` models the checks below on one data dir.

## What the flag does

- `OPEN_SIGNUP=1` lets anyone register without an invite. Any other value, or unset, keeps invite-only signup. Default: off.
- An invite, when offered, always takes the invite path. A wrong invite never falls back to open signup.
- Open accounts get a fixed `trial` tenant (`source: open`): 1 hostname, no API keys, 3 connect tokens per hour. Portal connect is allowed. Email verification is required before the first hostname, connect token or API key. Verification also sets the account password.
- Mail goes to the file outbox (`<state-dir>/outbox`, or `OUTBOX_DIR`). That is the only transport in this release; `MAIL_TRANSPORT=file` is the default and real sending is not wired yet.
- The portal reads `OPEN_SIGNUP`, the limits and the disposable list at startup only. Every change needs a restart of `<portal-unit>`.
- Signup answers are always the generic `{ "ok": true }`, whether an account was created or refused.

## Preflight

- [ ] The portal release that contains open signup is deployed with the flag off and passes the deploy acceptance checks. `/api/me` reports `open_signup: false`.
- [ ] Mail transport decided. With the file outbox, someone must hand-deliver verification links or new users cannot verify. Do not flip until delivery is agreed.
- [ ] Legal pages: `site/terms/` and `site/privacy/` are still marked DRAFT. The owner must finalize and publish them before launch. Do not flip with draft pages.
- [ ] Abuse limits reviewed (defaults shown): `SIGNUP_IP_PER_HOUR=3`, `SIGNUP_DOMAIN_PER_DAY=5`, `SIGNUP_BIGMAIL_PER_DAY=200`, `SIGNUP_GLOBAL_PER_DAY=100`. Trial values (`OPEN_SIGNUP_PLAN`, `OPEN_SIGNUP_HOSTNAME_LIMIT`, `OPEN_CONNECT_TOKENS_PER_HOUR`) are fixed; other values fail startup.
- [ ] Alerting knows the log reason codes (structured JSON, `event: signup`, `source: open`):
  - `outcome: created` / `reclaimed`: account made, or an expired unverified one re-issued.
  - `reason: exists`, `disposable`, `invalid_domain`, `domain_limit`: refused, normal noise.
  - `reason: global_limit` with `level: error`, `alert: signup_global_limit`: admission outage. All open registrations are refused until the daily window resets.
- [ ] Disposable list (`portal/src/data/disposable-domains.txt`) refreshed if stale, with `portal/bin/update-disposable.sh` from a reviewed copy. No network from the host.
- [ ] Backup of the portal code and state taken per [deploy.md](deploy.md) under `/root/backups/<tag>-<timestamp>`.

## Flip

1. Record the release, the time and `<portal-unit>`.
2. Set `OPEN_SIGNUP=1` in the portal service environment (the protected env file or a unit drop-in). Do not print the file.
3. Restart: `sudo systemctl restart <portal-unit>`.
4. Verify:
   - `/api/me` reports `open_signup: true`.
   - Register a synthetic test address. The response is generic and one `verify-email` file appears in the outbox for it.
   - Log in with the registration password: login works, `email_verified` is false, and adding a hostname is refused.
   - Open the outbox link and set a password. Log in again with the new password; the old one no longer works.
   - Tenant shows `plan: trial`, `hostname_limit: 1`. A second hostname gets `hostname_limit_reached`. API key creation gets `plan_required`. The 4th connect token in an hour gets 429.
   - Logs carry reason codes only: no addresses, links or tokens.
5. Record the synthetic test account and suspend it once the tenant CLI is available (see Kill switch).

## First hour

- Watch the `signup` log lines. Expect mostly `created` and a few refusals.
- Any `signup_global_limit` alert: investigate abuse before raising the cap. Roll back if needed.
- Many `disposable` or `domain_limit` from one source: look for a pattern; tighten limits or roll back.
- Check the outbox is drained (links are valid for one hour).
- Check edge load and new hostname claims for odd patterns.

## Rollback

1. Set `OPEN_SIGNUP=0` (or remove it) in the portal service environment.
2. `sudo systemctl restart <portal-unit>`. Without the restart open signup stays on.
3. Verify `/api/me` reports `open_signup: false` and a fresh test registration creates nothing and writes no outbox file.

What happens to data:

- Accounts created while open stay. They can log in, keep their hostnames, and keep the trial limits (1 hostname, no API keys, 3 connect tokens per hour). The limits come from the tenant, not the flag.
- Pending (unverified) registrations: the user and trial tenant already exist. An unexpired verification link (up to one hour after registration) still completes verification after rollback, giving a working trial account. Registering the same address again sends no new link. After the link expires the account stays unverified and cannot add hostnames. To block pending ones at once, suspend those tenants.
- Invites keep working as before.
- Do not restore old state files to undo signups; see [rollback.md](rollback.md).

## Kill switch

To stop a single abusive account without a full rollback, suspend its tenant with the tenant CLI (suspend / resume / release). Pending the kill switch PR: the CLI and its exact commands land separately. A suspended account's hostnames stay blocked for every other account until an admin explicitly releases them.
