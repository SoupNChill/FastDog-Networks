Production challenge routes could issue clearance through an arithmetic form without PoW, and demo forcing lacked a hostname check. Edge auth also ignored runtime denylist/off/shadow policy. This security pass restricts fallback to the demo host, gates demo forcing by trusted peer and canonical host, and ensures guardrail and explicitly non-enforcing hosts never challenge or block.

The patch also restricts forwarded-host trust, rejects proxied bootstrap by default, protects metrics with bearer auth, bounds config/request/state/log resources, and replaces config files atomically. Version advances to 0.3.1. The full eight-area findings report and deployment prerequisites are in `verdict/CODEX_LAST_MESSAGE.md`.

Compatibility changes:
- Metrics scrapers need a bearer key; read-only keys work.
- Production hosts require PoW; the arithmetic fallback is demo-only.
- Caddy snippet generation remains available, but `--apply` now refuses before writes. Automatic imports, command execution, reloads and live probes were removed because rollback did not restore overwritten snippets. Review and apply through the operator workflow.
- Config parent directories must remain operator-owned. Caddy must overwrite forwarding assertions. Unconfigured hosts retain existing heuristic behavior.

Validation: `cd verdict && npm test` — **136 passed, 0 failed** with paid-provider credentials excluded. Added adversarial HTTP tests against ephemeral local fixtures plus pure-function/filesystem/CLI tests. No secrets printed, money spent, production/PoP/live-edge load tests, merge, deployment, service restart, or live Caddy/DNS edits.
