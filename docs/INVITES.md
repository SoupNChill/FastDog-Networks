# Invite codes (LAN dogfood)

`INVITE_REQUIRED=true` by default. When enabled, `create-zone` needs an invite code in the CLI (`--invite`) or HTTP body (`invite_code`). A successful zone creation consumes one use and records the zone and redemption time. Invalid, expired, or exhausted codes reject the request. Existing zones and invalid zone inputs do not consume a use. Set `INVITE_REQUIRED=false` in the edge and CLI environment to disable this gate.

Invites are operator controlled. The HTTP routes use the same `AGENT_TOKEN` authentication as the rest of `/_fastdog/onboard`: send `x-fastdog-token: <AGENT_TOKEN>` or `token` in JSON. Keep this API on a trusted LAN. `GET /invites` returns plaintext codes so the operator can copy them. Codes are random (`fd-` plus 24 random bytes in hex) and saved in `$DATA_DIR/invites.json` with mode `0600` using an atomic replacement.

## CLI

```sh
npm run onboard -- generate-invite --max-uses 2 --expires-in-hours 48 --note 'LAN trial'
npm run onboard -- list-invites
npm run onboard -- redeem-invite fd-<code> --redeemed-by operator
npm run onboard -- create-zone example.com --invite fd-<code>
```

`--max-uses` defaults to 1. For a fixed expiry use `--expires-at 2026-10-01T12:00:00Z` instead of `--expires-in-hours`. Expiry is optional. `--note` is optional.

## HTTP

All routes below are under `/_fastdog/onboard`:

| Method | Path | Body | Result |
| --- | --- | --- | --- |
| `POST` | `/invites` | `max_uses?`, `expires_at?` or `expires_in_hours?`, `note?` | Created invite including code |
| `GET` | `/invites` | None | All invites including codes and redemptions |
| `POST` | `/invites/redeem` | `code`, `redeemed_by?` | Updated invite |
| `POST` | `/zones` | `zone`, `invite_code` when required, other zone options | Created zone; invite use consumed |

Example:

```sh
curl -sS -X POST http://127.0.0.1:8787/_fastdog/onboard/invites \
  -H "x-fastdog-token: $AGENT_TOKEN" -H 'content-type: application/json' \
  -d '{"max_uses":1,"expires_in_hours":24,"note":"dogfood"}'
```

The standalone redeem route consumes a use immediately. Zone creation consumes it automatically, so do not redeem a code first if it is intended for that zone. This thin JSON store assumes one control process writes invites at a time.
