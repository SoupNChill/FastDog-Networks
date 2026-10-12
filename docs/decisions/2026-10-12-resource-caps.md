---
type: decision
title: "Bounded authentication state"
description: "Resource caps reject new sessions/rate-limit admissions without evicting valid existing entries; caps are a service safety boundary."
timestamp: 2026-10-12
---

## Context

This records the repository policy at the dated revision, not a live deployment audit. Evidence: `1f7c2ea`; [backlog](../DAY2_BACKLOG.md).

## Decision

Resource caps reject new sessions/rate-limit admissions without evicting valid existing entries; caps are a service safety boundary.

## Consequences

Reject excess admissions without evicting valid entries.
