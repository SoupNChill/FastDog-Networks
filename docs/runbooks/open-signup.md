# Open signup: flip and rollback

This runbook does not authorize a deploy or the flip. The operator approves each step separately and follows [deploy.md](deploy.md) and [rollback.md](rollback.md). `portal/test/open-signup-flip.test.js` models the checks below on one data dir.

## What the flag does

- `OPEN_SIGNUP=1` lets anyone register without an invite. Any other value, or unset, keeps invite-only signup. Default: off.
- An invite, when offered, always takes the invite path. A wrong invite never falls back to open signup.
- Open accounts get a fixed `trial` tenant (`source: open`): 1 hostname, no API keys, 3 connect tokens per hour. Portal connect is allowed. Email verification is required before the first hostname, connect token or API key. Verification also sets the account password.
- Mail: `MAIL_TRANSPORT=file` (the default, also when unset) writes each message to the private outbox (`<state-dir>/outbox`, or `OUTBOX_DIR`); someone hand-delivers the links. `MAIL_TRANSPORT=smtp` is opt-in: it submits via STARTTLS using the `SMTP_*` and `MAIL_*` settings in the protected env file and keeps only redacted audit copies in the outbox. Any other value fails startup. Keep `file` for the flip unless the operator decides otherwise; the verify steps below assume it. See [TENANT_API.md](../TENANT_API.md) for queueing and budget rules.
- The portal reads `OPEN_SIGNUP`, `MAIL_TRANSPORT`, the limits and the disposable list at startup only. Every change needs a restart of `<portal-unit>`; setting `OPEN_SIGNUP=0` without a restart does not stop admission.
- Signup answers are always the generic `{ "ok": true }`, whether an account was created or refused.
- Every sign-up (invite or open) must send `accept_terms: true` from the Terms/Privacy checkbox; anything else is refused generically. The server stores its own document versions from `portal/src/terms.js`.

## Preflight

- [ ] The portal release that contains open signup and the tenant CLI (`portal/bin/tenant.js`) is deployed with the flag off and passes the deploy acceptance checks. `/api/me` reports `open_signup: false`.
- [ ] Mail transport decided. With the file outbox (default), someone must hand-deliver verification links or new users cannot verify. Do not flip until delivery is agreed. Switching to `smtp` is a separate operator decision with its own restart and checks.
- [ ] Legal pages: `site/terms/` and `site/faq/` are final copy in git (`TERMS_VERSION` `2026-10-19`, DRAFT markers removed, real support contact). `site/privacy/` is final (`PRIVACY_VERSION` `2026-10-20`). Keep noindex on all three until the flip; remove it from all three as a flip step and publish the final pages before opening signup. Do not flip with draft Terms.
- [ ] Site copy that describes self-serve sign-up and the 7-day trial (homepage hero and pricing, `/edge/`, FAQ, Terms §6) goes live in the same window as the trial pause (`TRIAL_PAUSE_ENABLED=1`) and this flip. If the flip or the trial pause is rolled back for more than a short window, roll that copy back too, so the site does not promise self-serve sign-up or a trial pause that is not running.
- [ ] `SITE_ORIGIN` in the portal service environment is the real public site origin (`https://` origin, no path). If it is unset or invalid, the checkbox links point at `https://example.invalid`. Check the Terms and Privacy links on `/signup`.
- [ ] Abuse limits reviewed (defaults shown): `SIGNUP_IP_PER_HOUR=3`, `SIGNUP_DOMAIN_PER_DAY=5`, `SIGNUP_BIGMAIL_PER_DAY=200`, `SIGNUP_GLOBAL_PER_DAY=100`. The 200/day provider cap is intentionally subordinate to the 100/day global cap. Trial values (`OPEN_SIGNUP_PLAN`, `OPEN_SIGNUP_HOSTNAME_LIMIT`, `OPEN_CONNECT_TOKENS_PER_HOUR`) are fixed; other values fail startup.
- [ ] Alerting knows the log reason codes (structured JSON, `event: signup`, `source: open`):
  - `outcome: created` / `reclaimed`: account made, or an expired unverified one re-issued.
  - `reason: exists`, `disposable`, `invalid_domain`, `domain_limit`: refused, normal noise.
  - `reason: global_limit` with `level: error`, `alert: signup_global_limit`: admission outage. All open registrations are refused until the daily window resets.
- [ ] Disposable list (`portal/src/data/disposable-domains.txt`) refreshed if stale, with `portal/bin/update-disposable.sh` from a reviewed copy. No network from the host.
- [ ] Kill switch dry run understood (see Kill switch): the operator can run `tenant.js` as the portal service user and knows where `PORTAL_KEY` lives without printing it.
- [ ] Backup of the portal code and state taken per [deploy.md](deploy.md) under `/root/backups/<tag>-<timestamp>`.

## Flip

1. Record the release, the time and `<portal-unit>`.
2. Set `OPEN_SIGNUP=1` in the portal service environment (the protected env file or a unit drop-in). Leave `MAIL_TRANSPORT` unset or `file`. Do not print the file.
3. Restart: `sudo systemctl restart <portal-unit>`.
4. Verify:
   - `/api/me` reports `open_signup: true`.
   - Register a synthetic test address. The response is generic and one `verify-email` file appears in the outbox for it.
   - Log in with the registration password: login works, `email_verified` is false, and adding a hostname is refused.
   - Open the outbox link and set a password. Log in again with the new password; the old one no longer works.
   - Tenant shows `plan: trial`, `hostname_limit: 1`. A second hostname gets `hostname_limit_reached`. API key creation gets `plan_required`. The 4th connect token in an hour gets 429.
   - Logs carry reason codes only: no addresses, links or tokens.
5. Record the synthetic test account, then suspend it with the tenant CLI (Kill switch, step 1) and confirm it can no longer log in. Leave it suspended, or resume and release it when its test hostname should return to the pool.

## First hour

- Watch the `signup` log lines. Expect mostly `created` and a few refusals.
- Any `signup_global_limit` alert: investigate abuse before raising the cap. Roll back if needed.
- Many `disposable` or `domain_limit` from one source: look for a pattern; tighten limits or roll back.
- Check the outbox is drained (links are valid for one hour).
- Check edge load and new hostname claims for odd patterns. Suspend abusive accounts with the kill switch.

## Rollback

1. Set `OPEN_SIGNUP=0` (or remove it) in the portal service environment.
2. `sudo systemctl restart <portal-unit>`. Without the restart open signup stays on.
3. Verify `/api/me` reports `open_signup: false` and a fresh test registration creates nothing and writes no outbox file.

What happens to data:

- Accounts created while open stay. They can log in, keep their hostnames, and keep the trial limits (1 hostname, no API keys, 3 connect tokens per hour). The limits come from the tenant, not the flag.
- Pending (unverified) registrations: the user and trial tenant already exist. An unexpired verification link (up to one hour after registration) still completes verification after rollback, giving a working trial account. Registering the same address again sends no new link. After the link expires the account stays unverified and cannot add hostnames. It is also locked out: re-issuing an expired registration only happens while `OPEN_SIGNUP=1`, so re-registering after rollback sends no link and the address cannot be reused. Recovery needs a re-flip, or the operator clearing the stale registration under the backup procedure. To block pending ones at once, suspend those tenants with the kill switch; verification links of a suspended tenant are refused, and links issued before a suspension stay dead after resume.
- Invites keep working as before.
- Do not restore old state files to undo signups; see [rollback.md](rollback.md).

## Kill switch (suspend, resume, release)

Stops a single abusive account without a full rollback. Run as the portal service user with `STATE_DIRECTORY=<state-dir>` set; `suspend`, `release` and a `resume` after a failed edge suspend also need `PORTAL_KEY` (from the protected runtime env file, never echoed) and optionally `EDGE_INTERNAL_URL=<edge-internal-url>`. Safe while the portal runs. Commands take `tenant-cli.lock` in the state directory and run one at a time, so only one operator acts at once (a second command waits up to 15 s, then exits 1; a lock left by a dead process is taken over). Always pass a `--reason`; it goes to `admin_audit.json`. Output is one JSON summary line with no keys or tokens. A malformed `suspensions.json` fails closed: the portal refuses requests until it is fixed.

1. `node portal/bin/tenant.js suspend <tenant_id|email> --reason "<ticket>"`. Expect `edge:"ok"` and exit 0: portal access ends (sessions, API keys and connect tokens are revoked on next use, login answers like a wrong password), and on the edge the tenant's agent credentials and tunnel routes are removed, agents disconnected, TLS ask refused and every claimed hostname held as an administrative reservation. Exit 2 (`edge:"failed"`) means the portal side is in place; fix edge reachability and re-run the same command. A hostname request already in flight when the command runs can still leave a pending claim; re-run `suspend` after a few seconds to reserve it too (the command is idempotent).
2. `node portal/bin/tenant.js resume <tenant_id|email> --reason "<ticket>"` restores sign-in only. It re-confirms the edge suspend first: if that never succeeded, resume retries it and the account stays suspended (exit 2, `edge:"failed"`) until it does. Old sessions, API keys, connect tokens and email links stay invalid; the customer signs in again and issues new ones. Hostnames stay reserved and unusable.
3. `node portal/bin/tenant.js release <tenant_id|email> --reason "<ticket>"` frees the reservations so any account can claim them with fresh DNS proof. The CLI refuses it while the account is suspended (exit 1): resume first, or leave the names reserved for as long as the account stays suspended. Reservations never expire on their own; only this explicit release returns them to the pool.
