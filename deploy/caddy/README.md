# Per-host access logs

This is an unapplied Caddy v2 snippet. Import `access-logs.snippet` once at the top of a candidate Caddyfile. Inside each site block, add `import fdlog app.example.com`, substituting that block's literal hostname. Files follow `/var/log/caddy/<hostname>.log`; use a distinct hostname argument for each block.

The JSON filter retains request method, URI path, masked client IP, status and duration. It strips the entire query and deletes headers, cookies, TLS and other standard access-log fields. Rotation is 5 MiB, five retained files, seven days. Do not add `log_credentials`, header appenders or extra fields. Review filters when upgrading Caddy because new default fields need a corresponding deletion.

Before any application, the operator should copy the current configuration to a backup, build a candidate, and run the installed binary against that candidate:

```
caddy adapt --config ./Caddyfile.candidate --adapter caddyfile --pretty
caddy validate --config ./Caddyfile.candidate --adapter caddyfile
```

Inspect the adapted filter and, in an isolated local test, send a synthetic request containing a query, cookie and authorization header. Confirm the log contains only the retained fields, a path without a query, and masked addresses. Caddy versions may differ; adaptation and validation on the target version are required. This repository test checks snippet text only; no Caddy binary was available for validation during this build.

After separately approved application, rollback means restore the saved Caddyfile and reload Caddy using the operator's normal procedure. Removing the `import fdlog` lines and snippet import disables this logging configuration. No configuration has been installed or reloaded by this lane.


## Optional on-demand TLS (not applied)

`on-demand-tls.snippet` shows Caddy 2.11's global `on_demand_tls { ask ... }` placement. Merge it into the candidate Caddyfile's single global options block; do not import a second global block inside a site. Replace port 8789 with the edge's `INTERNAL_PORT` and enable both `INTERNAL_ENABLED=1` and `TLS_ASK_ENABLED=1`. The ask URL must reach the edge directly over loopback without forwarded headers. Caddy supplies the `domain` query parameter.

The commented `https://` site illustrates `tls { on_demand }` and the edge upstream. Review catch-all routing and control endpoint exposure before enabling it. The endpoint approves verified active tenant claims and explicit active legacy attachments; ambiguous tunnel-list entries alone are denied. See [internal API operations](../../docs/INTERNAL_API_OPS.md) for limits and rollback.

No network documentation lookup or Caddy binary validation was performed for this snippet. The offline test checks its global-block structure only. Run the adaptation and validation commands above using the installed Caddy 2.11 binary before application, then inspect the adapted ask URL. Roll back by restoring the previous Caddyfile and reloading; disable the edge flag separately if desired. This snippet has not been installed or imported by this change.
