---
type: decision
title: "Fail-open bot filtering"
description: "Verdict default failure policy is open for bot-auth outages."
timestamp: 2026-10-08
---

## Context

This records the repository policy at the dated revision, not a live deployment audit. Evidence: `fb1538b`, `d638a1b`; [edge guide](../../verdict/deploy/EDGE.md), [host policy](../../verdict/src/config/hosts.js).

## Decision

Verdict default failure policy is open for bot-auth outages. Explicit off/shadow bypass enforcement; only the designated demo may be enforced operationally, and guardrail hosts never are.

## Consequences

Never add enforce or forward_auth to guardrail hosts; authentication still fails closed.
