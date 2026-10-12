---
type: decision
title: "Default-off TLS and re-check"
description: "TLS ask and routing re-check are opt-in/default-off."
timestamp: 2026-10-12
---

## Context

This records the repository policy at the dated revision, not a live deployment audit. Evidence: `386ebef`, `b4b9e38`; [internal operations](../INTERNAL_API_OPS.md).

## Decision

TLS ask and routing re-check are opt-in/default-off. Re-check suspension revokes credentials; recovery requires explicit routing plus TXT and a new credential.

## Consequences

Recovery requires explicit proof and a fresh credential.
