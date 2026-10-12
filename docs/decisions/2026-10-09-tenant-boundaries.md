---
type: decision
title: "Separate tenant trust boundaries"
description: "Tenant contract separates portal/internal/operator keys and enforces ownership twice."
timestamp: 2026-10-09
---

## Context

This records the repository policy at the dated revision, not a live deployment audit. Evidence: `d3a8a87`; [contract](../TENANT_API.md).

## Decision

Tenant contract separates portal/internal/operator keys and enforces ownership twice. Tenant activation needs routing and TXT, not routing alone. Node built-ins only for new modules.

## Consequences

Scope ownership twice and use Node built-ins for new code.
