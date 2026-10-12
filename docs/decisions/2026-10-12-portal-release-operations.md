---
type: decision
title: "Portal login and release recovery"
description: "Use portal login without a Caddy basic-auth gate and retain recoverable release backups."
timestamp: 2026-10-12
---

## Context

The portal implements invite-only signup, login and session gates in `portal/src/app.js`. The operator supplied deployment and recovery facts for this update; no live inspection was performed.

## Decision

The portal uses its own login; the Caddy basic-auth gate has been removed. Back up before every edge change under `/root/backups/<tag>-<timestamp>`, with release code in `code.tgz`. Keep the portal's previous code at `/opt/fastdog-portal.old`.

## Consequences

Rollback untars `code.tgz` at its recorded extraction root and restarts the affected unit. Preserve compatible current state and revocations; previous code is not a state backup. See [deploy](../runbooks/deploy.md) and [rollback](../runbooks/rollback.md). Record secrets only by path and owner.
