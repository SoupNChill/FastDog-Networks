# Add a customer host by hand

Use this only during an authorized edge change. It adds an explicit Caddy site; it does not claim a domain, change DNS, issue an agent credential or bypass ownership verification. Keep `TLS_ASK_ENABLED` and `RECHECK_ENABLED` off.

1. Follow [deployment](deploy.md) and [Caddy/TLS](cert-caddy.md): record the release and `caddy` unit, confirm the active tenant's ownership and DNS proofs and intended origin, stop configuration writers, and take the required restricted backup under `/root/backups/<tag>-<timestamp>`. Do not read or copy secrets into a ticket.
2. Run from a reviewed checkout on the edge with Bash, Node 18/20, `flock`, Caddy and systemd available. The script imports the canonical `ENFORCE_DENYLIST` from `verdict/src/config/hosts.js`; keep that module with the checkout. It refuses those names and their subdomains, as well as any address whose first label is `lease`.
3. Ensure the active Caddyfile already imports `deploy/caddy/access-logs.snippet` and preserves public control-route exclusions. Review imports and wildcard sites for conflicts too: duplicate detection is conservative and checks literal names in the main file only.
4. Preview without changing files or running Caddy:

   ```sh
   sudo scripts/add-customer-host.sh --dry-run app.example.test
   ```

5. Substitute the verified customer address and apply:

   ```sh
   sudo scripts/add-customer-host.sh app.example.test
   ```

The example is synthetic and cannot obtain a public certificate. The script lowercases the address and checks strict DNS label lengths and characters. It copies the existing attached-host generator (`src/onboard/attach.js`) exactly:

```caddyfile
app.example.test {
    import fdlog app.example.test
    reverse_proxy localhost:8787
}
```

The filtered `fdlog` import is required. There is no Verdict enforcement or `forward_auth`. No deployed Caddyfile is shipped in this checkout; confirm the installed configuration follows this pattern before use.

The script locks the Caddyfile against concurrent runs, refuses an existing literal hostname, and backs up `/etc/caddy/Caddyfile` to `/etc/caddy/Caddyfile.bak-addhost-<host>-<timestamp>`. It appends the block, runs `caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile`, then `systemctl reload caddy`. Validation or reload failure restores the saved file and exits unsuccessfully. If reload fails, check the running configuration and use the printed rollback command to validate and reload the restored file. Coordinate other configuration writers; they must respect the lock or remain stopped.

The rollback command is printed before the change. Retain it with the change record. During the authorized online acceptance window, confirm HTTPS serves the intended website, agent connectivity remains healthy, public control exclusions still hold, and logs remain filtered. On failure, run the printed rollback command and repeat the acceptance checks. See [rollback](rollback.md).

For offline tests only, `CADDYFILE` selects a temporary configuration and `BIN` selects a directory containing stub `caddy` and `systemctl` executables. These overrides do not bypass the root check for writes. Preview mode can run without root. Never point tests at the deployed configuration.

Lane H: DONE — install tabs, root-domain guidance, and the hand-add helper with offline regression coverage. The shared backlog is outside this lane's file scope.
