# Certificates and Caddy

The active configuration path documented by the repo is `/etc/caddy/Caddyfile`; installed version, imports, storage directory and owner need operator confirmation. Repo snippets under `deploy/caddy/` are unapplied examples. An active hostname claim does not prove a certificate exists. Use explicit verified-host blocks while TLS ask remains blocked by [open review findings](../DAY2_BACKLOG.md).

1. Confirm the verified hostname, routing proof, ownership TXT for tenant claims, connected agent, public DNS and intended upstream. `app.example.test` below is a placeholder; never attempt public issuance for it. Keep the current public control-route exclusions and guardrail host handling when adding a host.
2. Before each edit, save the current Caddyfile as `/etc/caddy/Caddyfile.bak-<tag>-<date>`, with a descriptive tag and UTC timestamp, for example `Caddyfile.bak-attach-20261012-120000`. Preserve ownership/mode and protect included files too. The repo records an earlier `ctlblock` backup; its existence today must be checked by the operator.
3. Build a candidate beside the active file so relative imports resolve consistently. Add the verified host routing to `127.0.0.1:8787` (portal instead uses `8790`). Do not expose `8788` or `8789`. Preserve the block for public `/_fastdog/*` except the intended registration/tunnel routes. Review Host routing because the edge has a default upstream.
4. If adding access logging, import `deploy/caddy/access-logs.snippet` once and use `import fdlog app.example.test` in the host block, with its actual hostname at deployment. Logs must drop queries, headers/cookies and TLS details and mask IPs. Rotation is 5 MiB, five files, seven days. Top-level Caddy `level`, `ts`, `logger`, `msg` can remain outside the filter. Do not add `log_credentials`. This is especially necessary while agent credentials travel in WebSocket queries.
5. Run the installed Caddy binary on the complete candidate before replacing the active file:

   ```sh
   sudo caddy adapt --config /etc/caddy/Caddyfile.candidate --adapter caddyfile --pretty
   sudo caddy validate --config /etc/caddy/Caddyfile.candidate --adapter caddyfile
   ```

   Inspect adapted output privately: live configuration may contain credentials. Do not paste it into logs/tickets. Stop on any validation failure. In an isolated test, check query/header redaction using synthetic values. Repo snippet tests do not establish installed-binary compatibility.
6. Install the validated candidate preserving the active file's ownership/mode, then validate the installed path and reload:

   ```sh
   sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
   sudo systemctl reload caddy
   ```

   Require reload success and check sanitized service logs. During authorized online verification, check the hostname's certificate name/expiry and actual application response. A successful edge `/health` is insufficient. Diagnose DNS/CAA, challenge reachability, rate limits and upstream connectivity separately; avoid repeated issuance retries.

Optional on-demand TLS is **not ready to enable** until its backlog blocker is closed. Later it requires both internal and ask flags, one global `on_demand_tls` block, and a direct loopback ask URL without forwarded headers. The ask approves only unambiguous active ownership, not arbitrary tunnel-list entries. Review catch-all exposure before enabling; use [internal operations](../INTERNAL_API_OPS.md).

Rollback: copy the selected saved backup to a candidate, validate it, restore with original permissions, validate `/etc/caddy/Caddyfile`, then reload and repeat checks. Do not delete Caddy certificate storage as a rollback step. Certificate-storage backup location and retention are `TODO(operator)`.
