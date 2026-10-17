# Repository guidance

## Layout and documentation

- `src/edge/`, `src/control/`, `src/internal/`: edge, tunnels and tenant API. `src/onboard/`, `src/dns/`, `src/operator/`, `src/status/`, `src/billing/`: supporting services.
- `agent/`: outbound origin agent. `portal/`: standalone invite-only portal, browser assets and tests. `site/`: static marketing assets.
- `domain-search/`: read-only registrar lookup/pricing. `verdict/`: bot decisions, shadow jobs and ASN refresh.
- `config/`, `zones/`: routing and DNS inputs. `deploy/`, `scripts/`: deployment templates and operator utilities. `test/`: root regression suite and offline helpers.
- [Tenant API](docs/TENANT_API.md) is binding. Start with [architecture](docs/ARCHITECTURE.md), [inventory](docs/INVENTORY.md), [decisions](docs/decisions/README.md) and [backlog](docs/DAY2_BACKLOG.md).
- Runbooks: [deploy](docs/runbooks/deploy.md), [rollback](docs/runbooks/rollback.md), [DNS changes](docs/runbooks/dns-changes.md), [Caddy/TLS](docs/runbooks/cert-caddy.md), [agent attach](docs/runbooks/agent-attach.md), [portal invites](docs/runbooks/portal-invites.md), [Verdict](docs/runbooks/verdict.md).
- Supporting docs: [portal](portal/README.md), [internal operations](docs/INTERNAL_API_OPS.md), [hostname attach](docs/HOSTNAME_ATTACH.md), [onboarding](docs/ONBOARDING.md), [billing](docs/BILLING.md). Older deployment notes are historical; verify against current code and runbooks.

## Build, test and deployment

Use Node 18/20 and ESM (domain search uses Node 20). There is no compile/bundle step for edge, portal or static assets. Edge retains its existing dependencies; new code uses Node built-ins only. Use prepared dependencies or an approved offline artifact; do not fetch packages during offline work.

Before finishing, run both suites from the repository root with external access blocked by the existing preload (local loopback fixtures are allowed):

```sh
NODE_OPTIONS="--require=$PWD/test/helpers/offline.cjs" npm test
NODE_OPTIONS="--require=$PWD/test/helpers/offline.cjs" npm run test:portal
```

Require zero failures and zero new skips. The name-scan test `test/no-hardcoded-names.test.js` must pass; do not relax its reviewed baselines to hide new names. Add tests for every behavior change. Keep diffs small and scoped; mark completed items DONE in the backlog. Do not commit or push; the operator commits.

Deploy only within the authorized operational scope using the deploy and rollback runbooks: record the release and unit, stop writers, back up, stage code without overwriting runtime state, validate Caddy, restart the affected unit and verify acceptance checks. Backups live under `/root/backups/<tag>-<timestamp>`; rollback untars `code.tgz` and restarts the unit. Retain previous portal code at `/opt/fastdog-portal.old`.

## Rules and locks

- Keep code, tests and examples tenant-agnostic: synthetic tenant IDs and `example.test` or `.invalid` hostnames; no customer/person names or real hostnames.
- Never read or print secrets or environment files during repository work. No secrets in git, logs, URLs or chat. Configured secrets live in protected runtime env files only; application-managed credential/session state stays private. Document secret locations and owners only, never values.
- Guardrail hosts never receive Verdict enforce or `forward_auth`. Fail-open is the default for bot-filter outages; authentication and tenant ownership still fail closed.
- `TLS_ASK_ENABLED` and `RECHECK_ENABLED` default off in code. Production enabled `TLS_ASK_ENABLED=1` with v9 (operator-approved, 2026-10-17); `RECHECK_ENABLED` stays off pending operational review. Do not change either without operator approval.
- Pricing is locked at Hobby $9 / Pro $29 / Agency $149, monthly USD.
- No load tests on the shared PoP. Back up before every edge change, including configuration changes.
- OpenSRS is read-only (`LOOKUP`/`GET_PRICE`) unless the operator approves. Purchases and spend require operator approval.
- Background jobs run with `nice` and CPU/memory caps. Use free iptoasn data only.
- No network calls during repository work beyond isolated loopback test fixtures. Live probes, deployment and DNS changes belong to separately authorized operator procedures.
