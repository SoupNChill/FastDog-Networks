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


## On-demand TLS (go-live form; not applied by the repository)

`on-demand-tls.snippet` is the go-live configuration for Caddy 2.11: a global `on_demand_tls { ask http://127.0.0.1:8789/tls/ask }` block and a catch-all `https:// { tls { on_demand } import fdctl reverse_proxy 127.0.0.1:8787 }` site. `fdctl` is the existing snippet in the live Caddyfile that hides `/_fastdog/*` except tunnel/register; it must be defined before use. Explicit site blocks keep precedence over the catch-all. Replace 8789 with the edge's `INTERNAL_PORT` (the script reads `INTERNAL_PORT` and `UPSTREAM_PORT` from its environment) and set `INTERNAL_ENABLED=1` and `TLS_ASK_ENABLED=1` on the edge. The ask URL must reach the edge directly over loopback without forwarded headers; Caddy supplies the `domain` query parameter.

### Applying

As an authorized operator on the edge, after backing up per the deploy runbook:

```
deploy/caddy/enable-on-demand-tls.sh --dry-run /etc/caddy/Caddyfile   # prints the diff, writes nothing
deploy/caddy/enable-on-demand-tls.sh /etc/caddy/Caddyfile
```

The script refuses a Caddyfile that already has an `on_demand_tls` block or a catch-all `https://` site, writes `Caddyfile.bak-ondemand-<timestamp>` next to it, builds a candidate (global block inserted at the very top, or merged into an existing multi-line global block; catch-all appended; existing site blocks are never edited), runs `caddy validate --adapter caddyfile --config <candidate>` (as the `caddy` user when root, so validation cannot leave root-owned log files), installs it by atomic rename, runs `systemctl reload caddy` and checks the unit is active, then requires `http://127.0.0.1:${INTERNAL_PORT:-8789}/health` to answer (3 tries). It refuses a Caddyfile without a `(fdctl)` snippet definition and locks the sidecar `Caddyfile.lock` (not the Caddyfile itself); `scripts/add-customer-host.sh` takes the same lock, so the two never edit the Caddyfile concurrently. After success it records the installed file as `Caddyfile.enabled-ondemand-<timestamp>`. Any failure, including an unhealthy ask endpoint,  restores the backup: the restored file is validated, then reloaded; if the reload fails or the unit is not active the script runs `systemctl restart caddy` and re-checks. "Restored" is only printed when Caddy is active. If Caddy is still down it prints `CADDY IS DOWN` and exits 3 (exit 1 means the change failed but Caddy is running). Set `BIN` to a directory containing `caddy`, `curl` and `systemctl` only for fixtures.

### Rollback

```
deploy/caddy/enable-on-demand-tls.sh --rollback /etc/caddy/Caddyfile.bak-ondemand-<timestamp> /etc/caddy/Caddyfile
```

Rollback refuses (exit 1, with a `diff -u` hint) when the current Caddyfile differs from the recorded post-enable file, for example after `add-customer-host.sh` added a site, because it would discard those edits. Review the diff, then add `--force` (`--rollback <backup> --force [Caddyfile]`) to roll back anyway; without a post-enable record it also needs `--force`. Otherwise it validates the backup, saves the current file as `Caddyfile.bak-ondemand-prerollback-<timestamp>`, installs the backup and reloads (restoring the pre-rollback file, with the same validate, reload, restart fallback and exit 3 on `CADDY IS DOWN`, if the reload fails). Optionally unset `TLS_ASK_ENABLED` and restart the edge to stop the ask endpoint; Caddy then cannot obtain new on-demand certificates but already issued ones stay cached.

### Edge settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `TLS_ASK_ENABLED` | off | Must be `1` to enable the ask route. |
| `TLS_ASK_STATIC_HOSTS` | empty | Comma list of existing static hosts to approve (the only way reserved names are approved). |
| `TLS_ASK_TENANT_MAX_PER_HOUR` | 10 | New approvals per tenant per hour, counted per distinct hostname. |
| `TLS_ASK_DOMAIN_MAX_PER_HOUR` | 5 | New approvals per registered domain per hour (distinct hostnames; `x.example.co.uk` counts toward `example.co.uk`). Keeps issuance under Let's Encrypt per-domain limits. |
| `TLS_ASK_DOMAIN_WEEK_MAX` | 40 | New approvals per registered domain per 7 days (Let's Encrypt allows 50). Approvals are persisted in `DATA_DIR/tls_ask_approvals.json`, so restarts do not reset budgets. |
| `TLS_ASK_GLOBAL_MAX_PER_HOUR` | 100 | New approvals per hour across all hosts. |
| `TLS_ASK_LIVE_VERIFY` | 1 | `0` disables the live DNS re-check before a first approval of a tenant claim (see below). |
| `TLS_ASK_CHECKS_PER_MINUTE` | 600 | Anonymous (non-approvable) checks per minute; approved hosts are never blocked by it. |

Over a cap the ask route returns 429 with `retry_after` (reasons `approval_cap_global`, `approval_cap_tenant`, `approval_cap_domain`, `approval_cap_domain_week`, `approval_state_unavailable`). Before the first approval of a tenant claim in a window the edge re-checks the claim's DNS proof (routing to the edge plus the `_fastdog-challenge` TXT record, so keep that TXT in place); present proof is cached 10 minutes, missing proof 60 seconds. Missing proof returns 404 `live_verify_failed`; a DNS error or timeout (3 s) returns 503 `live_verify_unavailable` (fail closed, cached 10 seconds), which Caddy treats as a refusal and retries later. Static hosts and legacy attachments have no claim proof and are not live-verified. See [internal API operations](../../docs/INTERNAL_API_OPS.md) for the full rules, deny caching and log reason codes.

### Known limit

Hosts served only by the catch-all do not get per-host access logs (no `import fdlog <host>` line), so status traffic and shadow counts show not available for them until an explicit site block is added, for example with `scripts/add-customer-host.sh`.

The offline tests use fixture binaries only; no Caddy binary validation was performed in this repository. Run `caddy adapt` and `caddy validate` with the installed Caddy 2.11 (the script does the latter) and inspect the adapted ask URL before relying on it.
