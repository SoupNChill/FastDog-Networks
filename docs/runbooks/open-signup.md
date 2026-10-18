# Open signup flag operations

`OPEN_SIGNUP=0` and file outbox mail are the defaults. This PR does not authorize deployment or enabling signup. Follow the deploy and rollback runbooks for any separately authorized change.

The portal reads `OPEN_SIGNUP` and the disposable-domain list at startup. Changing either requires restarting the portal unit; setting `OPEN_SIGNUP=0` without a restart does not disable admission. Existing accounts continue to work after disabling signup.

Monitor structured signup reason codes. Treat `alert:signup_global_limit` (`level:error`) as an admission outage: all subsequent open registrations are refused generically until the daily window resets. Investigate abuse before adjusting the cap. The 200/day provider cap is intentionally subordinate to the default 100/day global cap. Only reason codes are logged; do not log addresses, links or tokens.

## Kill switch (suspend, resume, release)

Run as the portal service user with `STATE_DIRECTORY` set; `suspend`, `release` and a `resume` after a failed edge suspend also need `PORTAL_KEY` (from the protected runtime env file, never echoed) and optionally `EDGE_INTERNAL_URL`. Safe while the portal runs. Commands take `tenant-cli.lock` in the state directory and run one at a time (a second waits up to 15 s, then exits 1; a lock left by a dead process is taken over). Always pass a `--reason`; it goes to `admin_audit.json`. A malformed `suspensions.json` fails closed: the portal refuses requests until it is fixed.

1. `node portal/bin/tenant.js suspend <tenant_id|email> --reason "<ticket>"`. Expect `edge:"ok"` and exit 0: portal access ends, and on the edge the tenant's agent credentials and tunnel routes are removed, agents disconnected, TLS ask refused and every claimed hostname held as an administrative reservation. Exit 2 (`edge:"failed"`) means the portal side is in place; fix edge reachability and re-run the same command. A hostname request already in flight when the command runs can still leave a pending claim; re-run `suspend` after a few seconds to reserve it too (the command is idempotent).
2. `node portal/bin/tenant.js resume <tenant_id|email> --reason "<ticket>"` restores sign-in only. If the edge suspend never succeeded, resume first retries it and stays suspended (exit 2, `edge:"failed"`) until it does. Old sessions, API keys and connect tokens stay invalid; the customer signs in again and issues new ones. Hostnames stay reserved and unusable.
3. `node portal/bin/tenant.js release <tenant_id|email> --reason "<ticket>"` frees the reservations so any account can claim them with fresh DNS proof. It is refused while the account is suspended: resume first, or leave the names reserved for as long as the account stays suspended. Reservations never expire on their own.
