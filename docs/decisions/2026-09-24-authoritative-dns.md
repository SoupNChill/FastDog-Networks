---
type: decision
title: "Separate authoritative DNS roles"
description: "ns1 shares the edge; ns2 is a separate Hetzner DNS-only host."
timestamp: 2026-09-24
---

## Context

This records the repository policy at the dated revision, not a live deployment audit. Evidence: `a7a001a`; [NS cut runbook](../../deploy/NS_CUT.md).

## Decision

ns1 shares the edge; ns2 is a separate Hetzner DNS-only host. Zones are exported/copied, not AXFR. Registrar changes remain a separate gated operation.

## Consequences

Publish exported zones to both servers; registrar changes require separate authorization.
