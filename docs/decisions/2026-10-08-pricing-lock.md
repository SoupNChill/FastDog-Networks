---
type: decision
title: "Locked public pricing"
description: "Public pricing locked: Hobby $9/month, Pro $29/month, Agency $149/month."
timestamp: 2026-10-08
---

## Context

This records the repository policy at the dated revision, not a live deployment audit. Evidence: `e77d7a0`; [site source](../../site/index.html), [plans](../../src/billing/plans.js).

## Decision

Public pricing locked: Hobby $9/month, Pro $29/month, Agency $149/month. Domain pricing at cost. Legacy Starter/test checkout and assigned portal plans are separate implementations, not automatic production subscriptions.

## Consequences

Preserve Hobby $9, Pro $29 and Agency $149, monthly USD.
