---
type: decision
title: "MCP server plan (plan only, not built)"
description: "A thin, read-mostly MCP server over the scoped-key portal API, run locally by the customer's assistant; no new edge surface."
timestamp: 2026-10-16
---

## Status

Plan only. Do not build until scoped API keys ([design](2026-10-16-scoped-api-keys.md)) are approved and implemented.

## Goal

Let a customer's AI assistant (Claude Desktop, Cursor, Codex and so on) set up and check a FastDog website through Model Context Protocol tools instead of hand-written HTTP calls. It should be safe enough that a confused or prompt-injected assistant can't do damage beyond one hostname.

## Shape

- **Package:** `@fastdog/mcp` (Node, no dependencies beyond the MCP SDK), stdio transport, run locally by the assistant: `npx @fastdog/mcp`. Not hosted by FastDog in v1, so there's no new public service, no new edge surface, and no shared secret on our side.
- **Auth:** the user pastes a connect token or scoped API key into the assistant's MCP config as `FASTDOG_TOKEN`. The server sends it as a Bearer header to the portal's `/api/connect/v1/*` (and later `/api/v1/*`) endpoints. It never logs the token or puts it in tool output.
- **Config:** `FASTDOG_PORTAL_URL` (default: the production portal), `FASTDOG_TOKEN`.

## Tools (v1)

| Tool | Scope needed | Notes |
| --- | --- | --- |
| `get_connection_status(hostname?)` | `connect` or `status:read` | agent connected, origin answering, last seen |
| `get_site_status(hostname)` | `status:read` | Status page payload: live, cert expiry, 24h requests, p50, shadow counts |
| `test_site(hostname)` | `status:read` | Test it through the edge (rate limited server-side) |
| `list_hostnames()` | `hostnames:read` | with the DNS records still to add |
| `check_dns(hostname)` | `hostnames:write` | runs verify; returns plain-language fixes (grey cloud and so on) |
| `get_connect_command(hostname, origin, platform)` | `connect` or `credentials:rotate` | returns the command with a warning that it replaces the current connection; marked destructive so clients ask the user first |

Resources: `fastdog://docs/llms.txt` (the public llms.txt), `fastdog://hostnames/{name}/status`.

Prompts: `connect-my-server` (asks for the port, gets the command, tells the user to run it, polls status).

## Not in v1

No tools for billing, account, invites, deleting hostnames, Verdict enforcement, or anything touching other tenants. No shell execution: the assistant's own terminal tool runs the command, under the user's normal approval.

## Safety

- Destructive tools carry MCP `destructiveHint`, so clients prompt the user.
- Tool output never includes the agent key outside `get_connect_command`, and that output says to run it once and not echo it.
- Server-side scopes, hostname allow-lists, expiry and rate limits are the real boundary. The MCP server adds no authority of its own.

## Work plan (when approved)

1. Implement scoped API keys (portal) and `/api/v1` read routes behind them, with tests mirroring `portal/test/connect-token.test.js`.
2. Build `mcp/` in this repo with tool handlers as thin HTTP wrappers, with unit tests against a fake portal (no network).
3. Claude review, then publish to npm. Publishing needs Pete's approval.
4. Docs: an "Use with your AI assistant" section on /docs and in llms.txt, with example MCP configs.

Estimate: about 1 day for keys, about 1 day for the MCP package and tests.
