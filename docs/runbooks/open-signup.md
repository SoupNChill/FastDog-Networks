# Open signup flag operations

`OPEN_SIGNUP=0` and file outbox mail are the defaults. This PR does not authorize deployment or enabling signup. Follow the deploy and rollback runbooks for any separately authorized change.

The portal reads `OPEN_SIGNUP` and the disposable-domain list at startup. Changing either requires restarting the portal unit; setting `OPEN_SIGNUP=0` without a restart does not disable admission. Existing accounts continue to work after disabling signup.

Monitor structured signup reason codes. Treat `alert:signup_global_limit` (`level:error`) as an admission outage: all subsequent open registrations are refused generically until the daily window resets. Investigate abuse before adjusting the cap. The 200/day provider cap is intentionally subordinate to the default 100/day global cap. Only reason codes are logged; do not log addresses, links or tokens.
