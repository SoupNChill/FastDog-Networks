---
type: decision
title: "Invite-only portal accounts"
description: "Portal is invite-only, email-verified, single-writer JSON with file outbox and operator-assigned plans."
timestamp: 2026-10-10
---

## Context

This records the repository policy at the dated revision, not a live deployment audit. Evidence: `c227981`; [portal](../../portal/README.md).

## Decision

Portal is invite-only, email-verified, single-writer JSON with file outbox and operator-assigned plans. No SMTP or automated purchase integration.

## Consequences

Keep single-writer state and private outbox delivery; no automatic purchases.
