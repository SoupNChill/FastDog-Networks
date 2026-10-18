# Agent bootstrap implementation

Milestone 1 implements edge issuance and exchange. Milestone 2 adds key-bound register/tunnel proofs, candidate registration, the promotion hold and owner confirmation on the edge. No deployment, image publication, portal change or default connect command change is included. Keep the feature disabled until the remaining milestones and operational acceptance gates pass.

## Flags and configuration

`AGENT_BOOTSTRAP_ENABLED=1` enables the internal bootstrap operations and the canonical public exchange route. Unset, `0` and other values disable them. `AGENT_BOOTSTRAP_AUDIENCE` must specify the configured edge HTTPS audience; it is part of the signed transcript and issuance binding. Factory tests inject `bootstrapEnabled`, `bootstrapAudience`, `now` and `issuerCheck`. The production entry point deliberately has no issuer checker configured: exchange fails closed with `503 bootstrap_unavailable` until the authenticated checker is implemented and wired in milestone 3. A checker must return the boolean `true`; false means unauthorized (401); missing, nonboolean, throwing or timed-out checks mean unavailable (503).

`AGENT_BOOTSTRAP_ABSENT_FOR_SECONDS` sets the promotion-hold absence (default 300; an integer from 60 to 3600, otherwise enabled startup fails). It is read only when bootstrap is enabled. Disabled, the edge gives no proof context or candidate mode. It keeps the existing JSON parser and the existing register/upgrade calls, so behaviour matches master. Consequently, once a key-bound credential has been promoted, disabling the flag makes that agent fail closed with 401 until the flag is re-enabled or the owner reissues a legacy credential. Factor this into rollback.

TLS ask, recheck, pricing, the agent image pin and portal commands are unchanged.

## Status against the plan

- Section 3: issuance, 15-minute TTL, signed RSA-3072 exchange, pending key-bound credentials, two-minute encrypted recovery, binding-first errors, bounded attempt budgets and durable known-code/claim counters are implemented. Issuance charges the shared five-per-UTC-day hostname budget and eight-per-day absolute ceiling. The latter becomes independently reachable when refund accounting exists.
- Section 4: portal-key internal issuance/status/cancel endpoints are implemented on the existing internal listener with its limits. The issuer-check interface exists; portal HMAC transport, reply authentication and issuer-expiry capping remain milestone 3 work. Issuers must remain eligible at each exchange and recovery check.
- Section 5 is implemented on the edge:
  - Downgrade protection: pending and held credentials never use active registration or tunnel authentication.
  - Proofs: key-bound credentials authenticate only with a valid `X-Fastdog-Agent-Proof` (below). This is enforced inside `validCredential` and the separate `validCandidateCredential`.
  - Rechecks: upgrade authentication rechecks current credential state only when bootstrap is enabled or combined state is authoritative. Legacy flag-off upgrades retain master behaviour.
  - Versions: shared version validation preserves heartbeat's existing accepted set.

  The agent volume/state machine and protocol client remain unimplemented.
- Section 6 is implemented on the edge:
  - Exchange leaves the selected owner credential and existing tunnel intact.
  - Candidate registration, WS readiness, the default promotion hold, owner confirmation (internal endpoint) and atomic promotion are in place.
  - Cancellation, reissue, rotation, detach, suspension and release revoke candidates and remove them from the registry.

  Still open:
  - Issuer eligibility is not yet rechecked at candidate auth and promotion. The authenticated issuer checker is milestone 3 work, and production exchange is fail-closed until then, so no candidate can exist in production.
  - The cancel-by-reissue principal limits (3/hour, 6/day) are enforced by the portal and are also milestone 3.
- Sections 7–9: portal issuance, capability metadata, Docker image/volume integration and operator diagnostics remain future work. Refund accounting is not included in milestone 1.
- Section 10: offline unit, handler and flag-on HTTP/WS tests cover milestones 1–2, including proof, replay, skew, isolation, hold timing and confirmation tests. Actual Caddy sentinel/redaction tests, Docker tests and end-to-end acceptance remain required before enablement.
- Section 11: no rollout is performed. Migration and rollback need the stopped-writer, backup and validation procedures below. Older edge code that ignores combined state is not a supported rollback target.

## Storage and serialization

The implementation follows the plan's single combined file for authoritative authentication data: `agent-auth-state.json` holds version 1, claims, credential records and bootstrap state (codes, recovery ciphertext, issuance and attempt budgets). Existing callers continue using the JSON store API's logical filenames; those reads/writes are redirected into the combined snapshot. Existing route lists and unrelated stores retain their own files. They do not grant credential authority.

First enabled startup imports the legacy claims and credentials into one atomic snapshot. This import must be performed with other writers stopped and a validated backup. Once the combined file exists it is authoritative even with bootstrap disabled; there is no fallback to legacy files. Corrupt or unreadable combined state fails closed. Legacy files are retained solely for the operator's migration audit, never updated as a second authority. Do not remove the combined file or use old binaries to roll back.

All combined-store writes use an exclusive 0600 temporary file in the same directory, file fsync, rename and directory fsync. Memory is not an authority: each transaction rereads the snapshot. Synchronous transactions cannot yield and nest under the same writer lock. An exclusive `.agent-auth.lock` records the writer PID, a nonce and its creation time.
- A live competing holder is retried three times with 2, 5 and 10 ms pauses (at most about 17 ms of synchronous wait) before `503`.
- Dead-PID locks recover automatically. Any lock older than the 30-second ceiling (`LOCK_CEILING_MS`) recovers even if its PID is live or reused. An empty or partial lock is judged by file age against the same ceiling.
- Recovery uses an exclusive `.agent-auth.lock.reap` hard-link claim plus a content check to avoid removing a replacement lock.
- A reaper that crashed while holding its claim leaves `.reap` behind. That claim is removed once its inode ctime (set by the link) is older than the same 30-second ceiling. A fresh claim is busy. Residual: two processes that remove the same abandoned claim at the same instant could both reap; the edge is the only routine writer.

A migration/repair CLI is not included.

Issuance and redemption each commit their complete mutation in one snapshot. Issuer checks occur outside the lock; redemption rechecks the owner, claim creation generation, selected credential generation and cancellation under the lock after the check. Expired pending credentials are revoked on bootstrap operations and credential validation. An enabled-only, unreferenced 30-second sweep also removes expired recovery ciphertext on idle services. Immutable key fingerprints cannot be rewritten through the store API. Combined-store active validation does not persist last-used telemetry; the existing legacy-store telemetry behavior remains unchanged.

## Wire encoding

The proof transcript concatenates UTF-8 values, each prefixed by a four-byte unsigned big-endian byte length, in this order:

1. `fastdog-agent-bootstrap-v1`
2. `POST`
3. `/_fastdog/agents/bootstrap/exchange`
4. Configured audience
5. Lowercase hex SHA-256 of the bootstrap code
6. `hostname`, `origin`, `deployment_id`, `request_id`, `recipient_public_key`, `agent_version`

RSA-PSS uses SHA-256 and a 32-byte salt. The proof is base64url. The request fingerprint hashes this transcript, excluding the randomized proof. Key fingerprints hash SPKI DER. Public keys must be RSA-3072, exponent 65537, public SPKI PEM. Tokens are 32 random bytes encoded as 64 hex characters; only their SHA-256 is stored. RSA-OAEP uses SHA-256 and UTF-8 label `fastdog-agent-bootstrap-v1`. Matching retries return the stored ciphertext, never re-encrypt it. Exchange stores the bound SPKI DER (base64) as `public_key` beside `key_fingerprint`. Both are immutable through the store API.

### Register/tunnel proof (`X-Fastdog-Agent-Proof`)

The signed transcript uses the same length-prefixed encoding with these values in order:

1. `fastdog-agent-proof-v1`
2. HTTP method (`POST` for register, `GET` for the upgrade)
3. The exact request target, i.e. path plus raw query as sent: `/_fastdog/agents/register?candidate=1` or `/_fastdog/tunnel?agentId=<id>&candidate=1`. This binds the WS `agentId` and the candidate selector.
4. The configured audience. This is the host binding; the request `Host` header is not trusted.
5. Credential ID from the exchange response.
6. Timestamp as decimal Unix seconds.
7. Nonce.
8. Lowercase hex SHA-256 of the raw request body bytes (the empty body for upgrades).

The header is base64url of exactly `{"v":1,"nonce":"<43 chars>","timestamp":<int>,"signature":"<512 chars>"}`. Any other key order, whitespace, extra or duplicate field, non-canonical base64url, more than 2 KiB decoded, or more than one header occurrence is rejected.

The clock window is ±60 seconds inclusive. The nonce cache is in memory and shared by register and upgrade. It is keyed by credential ID and nonce, retains each accepted nonce until its timestamp plus 60 seconds, and is capped at 128 per credential and 20,000 globally. At the global cap it sweeps expired entries at most once per second, then fails closed; it never evicts live nonces. A nonce is consumed only after the signature verifies. An edge restart clears the cache. Residual: a proof captured less than 60 seconds before a restart (which also requires the bearer token) could be replayed once after it. With bootstrap enabled, the `/_fastdog` JSON parser retains the raw body for this hash. Proof headers and bodies are never logged.

### Candidates

Candidate mode is explicit (`candidate=1`) and takes the bearer token only from `Authorization`. `validCandidateCredential` requires all of:
- matching token hash;
- bound key and a valid proof;
- status `pending` before `activate_by` or `held` before `hold_until` (redemption + 1 hour), not revoked;
- the active owner's tenant and hostname;
- an issuing code that is not cancelled and whose claim and selected-credential generations still match the owner;
- a credential ID different from the selected active credential.

It never falls back to active authentication. Candidates live in a separate in-memory map keyed by credential ID. `hostIndex`, `getAgentByHost`, routing and `listAgents` never read it. Candidate disconnect or expiry never calls `closeHost`. Re-registration replaces only the same credential's earlier candidate. `closeHost` (every revocation path) also removes the host's candidates.

Readiness is an authenticated candidate upgrade followed by the welcome frame. At readiness the hold rule is evaluated; the 5-second enabled-only sweep re-evaluates held candidates and drops expired or revoked ones:
- Absence is measured from the active agent's last detach (or its replacement by a re-registration), never earlier than edge start, and reattachment resets it.
- When the candidate is not promoted, its durable status becomes `held`.

`promoteCandidate`, in one auth transaction:
1. Rechecks every candidate condition.
2. Revokes every other credential for the claim with the same timestamp it records as `promoted_at`.
3. Sets the candidate `active` and points the claim's `credential_id` at it.

After commit the registry moves the candidate into `agents`/`hostIndex` and terminates the old socket. A crash before commit loses only in-memory candidates, which re-register until their unchanged deadline. A crash after commit cannot resurrect the old credential. Owner confirmation goes through the internal endpoint. It requires a held, connected candidate and its exact fingerprint, and promotes even while the old agent is connected: that displacement is the owner's explicit choice. Automatic promotion never displaces a connected agent.

Origins use a port of the portal validator, with parity tests; issuance canonicalizes and exchange requires the canonical spelling. The service does not fetch the origin. Exchange limits key on the socket peer IP, or on the last X-Forwarded-For hop only when the socket peer is loopback; non-loopback peers cannot supply forwarded client identities. The edge proxy (Caddy) must set X-Forwarded-For on every proxied exchange request. A loopback peer without X-Forwarded-For is unattributed: all such requests share one 10/minute `unattributed` bucket, never the proxy address's per-IP bucket. Per-IP (or unattributed) admission is checked before the 300/minute global bucket is charged, so a rejected client never consumes global capacity. Limiter maps are swept from the oldest insertion with a bounded per-request budget. The exchange middleware is mounted only when enabled, on the exact canonical path and configured HTTPS audience authority. Known-code and claim attempt counters survive restarts; IP and global counters are process-local. The combined live limiter entry cap is 20,000, with admission failure rather than live-entry eviction.

## Review and operational limits

A successful exchange alone cannot connect a new agent: the credential must also prove key possession as a candidate and pass the promotion hold. Recovery expires exactly 120 seconds after redemption, even if the original issuance TTL has elapsed. Issuance status never returns the code again. A lost issuance response requires explicit cancellation and fresh issuance.

Transactions prune old UTC budget days and expired attempt counters, retire expired/cancelled/completed recovery records into non-authorizing digest tombstones, and delete tombstones after 24 hours. Issuance refuses at 10,000 live/recovery records without evicting authority. Issuance status requires current hostname ownership and returns the same 404 as issue and cancel otherwise. The writer lock records a pid, random nonce and creation time. Recovery reaps it only when the holder pid is dead or the lock is older than 30 seconds, and only if the claimed lock still carries the nonce that was read. Releasing a lock removes it only while it still holds the releaser's own nonce. Unknown codes return the uniform 401 before field validation or RSA parsing; matched codes retain malformed-request 400 responses. Migration/repair tooling remains required before enablement. No credentials, codes, request bodies, headers or ciphertext are logged by the new handlers; deployment must still validate actual proxy logging with sentinels.

Known milestone-2 limits:
- Candidate and active validation still take the writer lock and reread the snapshot (the review-3 LOW on lock-free cached validation remains open).
- A client controlling many source addresses can fill the anonymous exchange limiter table, which then fails closed; the global bucket protects the rest.
- The XFF trust assumption still needs the deployed-Caddy sentinel test.

## Milestone 2 validation

`test/bootstrap-candidates.test.js` covers:
- legacy credentials with the flag off and on, with junk proof headers ignored;
- missing, wrong-key, duplicated, non-canonical, tampered-body, replayed (same path and across register/upgrade) and ±61 s skewed proofs, with ±60 s accepted;
- pending credentials refused on the active path without registry changes;
- hold timing with a fake clock: 299.999 s held, 300 s promoted, reattachment resets the clock, and absence counted from edge start;
- no displacement through `hold_until`, plus `activate_by` expiry;
- the replaced credential revoked in the same transaction, and the promoted key-bound credential then requiring proofs on the active path;
- owner confirmation, with 409 on mismatch and identical 404s for other tenants and hostnames;
- reissue and cancel, which revoke candidates while preserving `bootstrap_used`;
- revocation removing candidates;
- nonce-cache bounds, absent_for parsing, public-key immutability and log redaction.

`test/bootstrap-edge.test.js` runs the real edge with the flag on over loopback HTTP/WS. Two lock regressions are in `test/bootstrap-protocol.test.js`.

## Milestone 1 review validation

The review regression file covers trusted proxy buckets, flag-off upgrade/routing parity, authority matching, retention/cap refusal, stale startup/writer locks, idle ciphertext removal and uniform unknown-code errors. Its 27 tests pass offline with no skips. The root, portal and Verdict suites were attempted with the offline preload; this sandbox denies loopback listeners and some child processes (`EPERM`), preventing a clean full-suite run. The unchanged tracked-repository name scanner passes using a Git inventory captured outside the blocked Node child process; scanner fixtures requiring Git subprocesses remain sandbox-blocked. No allowlist baseline was relaxed.
