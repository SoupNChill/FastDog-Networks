---
type: decision
title: "Test-only billing"
description: "Billing scaffold is Stripe test mode only, with explicit test-key checks; it does not authorize live charging."
timestamp: 2026-09-24
---

## Context

This records the repository policy at the dated revision, not a live deployment audit. Evidence: `0b7cd15`; [billing](../BILLING.md).

## Decision

Billing scaffold is Stripe test mode only, with explicit test-key checks; it does not authorize live charging.

## Consequences

Do not use the scaffold for live charging.
