---
type: decision
title: "Read-only domain search"
description: "Domain search is read-only and budget-capped; lookup/pricing only, no registrar writes."
timestamp: 2026-10-08
---

## Context

This records the repository policy at the dated revision, not a live deployment audit. Evidence: `57c23d5`, `70607f4`; [search](../../domain-search/README.md), [implementation](../../domain-search/src/service.js).

## Decision

Domain search is read-only and budget-capped; lookup/pricing only, no registrar writes. Persist daily call budget across restarts when state is configured.

## Consequences

OpenSRS is limited to LOOKUP/GET_PRICE unless the operator approves; purchases and spend require approval.
