---
type: decision
title: "Hostname attach first"
description: "Hostname attach is the default first-seat path; customer retains registrar/DNS, with NS cut optional."
timestamp: 2026-10-06
---

## Context

This records the repository policy at the dated revision, not a live deployment audit. Evidence: `110252c`, `5808979`; [attach design](../HOSTNAME_ATTACH.md).

## Decision

Hostname attach is the default first-seat path; customer retains registrar/DNS, with NS cut optional.

## Consequences

Keep registrar and DNS changes optional.
