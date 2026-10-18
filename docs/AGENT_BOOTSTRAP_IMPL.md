# Agent bootstrap implementation

Milestone 1 implements edge issuance and exchange only. No deployment, image publication, portal change or default connect command change is included. Keep the feature disabled until the remaining milestones and operational acceptance gates pass.

## Flags and configuration

`AGENT_BOOTSTRAP_ENABLED=1` enables the internal bootstrap operations and the canonical public exchange route. Unset, `0` and other values disable them. `AGENT_BOOTSTRAP_AUDIENCE` must specify the configured edge HTTPS audience; it is part of the signed transcript and issuance binding. Factory tests inject `bootstrapEnabled`, `bootstrapAudience`, `now` and `issuerCheck`. The production entry point deliberately has no issuer checker configured: exchange fails closed with `503 bootstrap_unavailable` until the authenticated checker is implemented and wired in milestone 3. A checker must return the boolean `true`; false means unauthorized (401); missing, nonboolean, throwing or timed-out checks mean unavailable (503).

TLS ask, recheck, pricing, the agent image pin and portal commands are unchanged.

## Status against the plan

- Section 3: issuance, 15-minute TTL, signed RSA-3072 exchange, pending key-bound credentials, two-minute encrypted recovery, binding-first errors, bounded attempt budgets and durable known-code/claim counters are implemented. Issuance charges the shared five-per-UTC-day hostname budget and eight-per-day absolute ceiling. The latter becomes independently reachable when refund accounting exists.
- Section 4: portal-key internal issuance/status/cancel endpoints are implemented on the existing internal listener with its limits. The issuer-check interface exists; portal HMAC transport, reply authentication and issuer-expiry capping remain milestone 3 work. Issuers must remain eligible at each exchange and recovery check.
- Section 5: downgrade protection is implemented: pending, held and key-bound credentials cannot use active registration or tunnel authentication. Upgrade authentication rechecks current credential state. Shared version validation preserves heartbeat's existing accepted set. Agent volume/state machine, protocol client, register/WS proof header and replay cache remain unimplemented.
- Section 6: exchange leaves the selected owner credential and existing tunnel intact. Cancellation, rotation, detach, suspension and release invalidate bootstrap recovery and pending credentials. Candidate registration, readiness, promotion, owner confirmation and promotion hold remain milestone 2 work.
- Sections 7–9: portal issuance, capability metadata, Docker image/volume integration and operator diagnostics remain future work. Refund accounting is not included in milestone 1.
- Section 10: offline unit and handler tests cover milestone 1. Actual Caddy sentinel/redaction tests, Docker tests, promotion tests and end-to-end acceptance remain required before enablement.
- Section 11: no rollout is performed. Migration and rollback need the stopped-writer, backup and validation procedures below. Older edge code that ignores combined state is not a supported rollback target.

## Storage and serialization

The implementation follows the plan's single combined file for authoritative authentication data: `agent-auth-state.json` holds version 1, claims, credential records and bootstrap state (codes, recovery ciphertext, issuance and attempt budgets). Existing callers continue using the JSON store API's logical filenames; those reads/writes are redirected into the combined snapshot. Existing route lists and unrelated stores retain their own files. They do not grant credential authority.

First enabled startup imports the legacy claims and credentials into one atomic snapshot. This import must be performed with other writers stopped and a validated backup. Once the combined file exists it is authoritative even with bootstrap disabled; there is no fallback to legacy files. Corrupt or unreadable combined state fails closed. Legacy files are retained solely for the operator's migration audit, never updated as a second authority. Do not remove the combined file or use old binaries to roll back.

All combined-store writes use an exclusive 0600 temporary file in the same directory, file fsync, rename and directory fsync. Memory is not an authority: each transaction rereads the snapshot. Synchronous transactions cannot yield and nest under the same writer lock. An exclusive `.agent-auth.lock` also rejects competing processes; a lock left by a crash intentionally blocks mutations. With writers stopped, validate the combined snapshot and remove only the stale lock before restart. Automated stale-lock recovery and a migration/repair CLI are not included.

Issuance and redemption each commit their complete mutation in one snapshot. Issuer checks occur outside the lock; redemption rechecks the owner, claim creation generation, selected credential generation and cancellation under the lock after the check. Expired pending credentials are revoked on bootstrap operations and credential validation, without relying on timers. Immutable key fingerprints cannot be rewritten through the store API. Combined-store active validation does not persist last-used telemetry; the existing legacy-store telemetry behavior remains unchanged.

## Wire encoding

The proof transcript concatenates UTF-8 values, each prefixed by a four-byte unsigned big-endian byte length, in this order:

1. `fastdog-agent-bootstrap-v1`
2. `POST`
3. `/_fastdog/agents/bootstrap/exchange`
4. Configured audience
5. Lowercase hex SHA-256 of the bootstrap code
6. `hostname`, `origin`, `deployment_id`, `request_id`, `recipient_public_key`, `agent_version`

RSA-PSS uses SHA-256 and a 32-byte salt. The proof is base64url. The request fingerprint hashes this transcript, excluding the randomized proof. Key fingerprints hash SPKI DER. Public keys must be RSA-3072, exponent 65537, public SPKI PEM. Tokens are 32 random bytes encoded as 64 hex characters; only their SHA-256 is stored. RSA-OAEP uses SHA-256 and UTF-8 label `fastdog-agent-bootstrap-v1`. Matching retries return the stored ciphertext, never re-encrypt it.

Origins use a port of the portal validator, with parity tests; issuance canonicalizes and exchange requires the canonical spelling. The service does not fetch the origin. Limits use only the direct socket peer address, never forwarded headers. Known-code and claim attempt counters survive restarts; IP and global counters are process-local. The combined live limiter entry cap is 20,000, with admission failure rather than live-entry eviction.

## Review and operational limits

No candidate credential can authenticate in this milestone, so successful exchange alone cannot connect a new agent. Recovery expires exactly 120 seconds after redemption, even if the original issuance TTL has elapsed. Issuance status never returns the code again. A lost issuance response requires explicit cancellation and fresh issuance.

Code tombstones and daily budget history currently have no background retention job. A production retention policy and migration/repair tooling should be reviewed before enablement. No credentials, codes, request bodies, headers or ciphertext are logged by the new handlers; deployment must still validate actual proxy logging with sentinels.
