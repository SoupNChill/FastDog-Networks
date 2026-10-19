# Agent bootstrap implementation

Milestone 1 implements edge issuance and exchange. Milestone 2 adds key-bound register/tunnel proofs, candidate registration, the promotion hold and owner confirmation on the edge. Milestone 3 implements the agent client and its state volume. Milestone 4 adds portal issuance and revocation and the authenticated issuer check (see "Portal and issuer check (milestone 4)"). No deployment, image build or publication, image pin change or default connect command/snippet change is included. Keep both flags disabled until the remaining milestones and operational acceptance gates pass.

## Flags and configuration

`AGENT_BOOTSTRAP_ENABLED=1` enables the internal bootstrap operations and the canonical public exchange route. Unset, `0` and other values disable them. `AGENT_BOOTSTRAP_AUDIENCE` must specify the configured edge HTTPS audience; it is part of the signed transcript and issuance binding. Factory tests inject `bootstrapEnabled`, `bootstrapAudience`, `now` and `issuerCheck`. In production the issuer checker is built from `AGENT_BOOTSTRAP_ISSUER_CHECK_URL` (the portal's loopback `http://127.0.0.1:<port>/internal/v1/issuer-check`) and `AGENT_BOOTSTRAP_ISSUER_CHECK_KEY` (the per-environment service secret; 32+ characters, never `PORTAL_KEY` or `AGENT_TOKEN`). Both unset means no checker: exchange, candidate auth and promotion fail closed with 503. A partial or invalid pair fails enabled startup; messages never contain values. A checker must return the boolean `true`; false means unauthorized (401); missing, nonboolean, throwing or timed-out checks mean unavailable (503).

`PORTAL_AGENT_BOOTSTRAP_ENABLED=1` enables the portal side (below); anything else leaves the portal byte-for-byte unchanged. `PORTAL_ISSUER_CHECK_KEY` (same secret as the edge's `AGENT_BOOTSTRAP_ISSUER_CHECK_KEY`, provisioned by the portal operator in the protected runtime env file, never committed) starts the issuer-check listener on `127.0.0.1:PORTAL_ISSUER_CHECK_PORT` (default 8792). It must differ from `PORTAL_KEY` and the portal port. Caddy must not proxy that port.

`AGENT_BOOTSTRAP_ABSENT_FOR_SECONDS` sets the promotion-hold absence (default 300; an integer from 60 to 3600, otherwise enabled startup fails). It is read only when bootstrap is enabled. Disabled, the edge gives no proof context or candidate mode. It keeps the existing JSON parser and the existing register/upgrade calls, so behaviour matches master. Consequently, once a key-bound credential has been promoted, disabling the flag makes that agent fail closed with 401 until the flag is re-enabled or the owner reissues a legacy credential. Factor this into rollback.

TLS ask, recheck, pricing, the agent image pin and portal commands are unchanged.

## Status against the plan

- Section 3: issuance, 15-minute TTL, signed RSA-3072 exchange, pending key-bound credentials, two-minute encrypted recovery, binding-first errors, bounded attempt budgets and durable known-code/claim counters are implemented. Issuance charges the shared five-per-UTC-day hostname budget and eight-per-day absolute ceiling. The latter becomes independently reachable when refund accounting exists.
- Section 4: portal-key internal issuance/status/cancel/confirm and (milestone 4) `POST /bootstraps/agent/revoke` endpoints are implemented on the existing internal listener with its limits. The authenticated issuer check (portal listener, HMAC transport and reply authentication) is implemented in milestone 4. Issuer expiry caps a code effectively: an expired connect token is an invalid issuer at every later check.
- Section 5 is implemented on the edge:
  - Downgrade protection: pending and held credentials never use active registration or tunnel authentication.
  - Proofs: key-bound credentials authenticate only with a valid `X-Fastdog-Agent-Proof` (below). This is enforced inside `validCredential` and the separate `validCandidateCredential`.
  - Rechecks: upgrade authentication rechecks current credential state only when bootstrap is enabled or combined state is authoritative. Legacy flag-off upgrades retain master behaviour.
  - Versions: shared version validation preserves heartbeat's existing accepted set.

  Milestone 3 implements the agent side (see "Agent (milestone 3)").
- Section 6 is implemented on the edge:
  - Exchange leaves the selected owner credential and existing tunnel intact.
  - Candidate registration, WS readiness, the default promotion hold, owner confirmation (internal endpoint) and atomic promotion are in place.
  - Cancellation, reissue, rotation, detach, suspension and release revoke candidates and remove them from the registry.

  Since milestone 4, issuer eligibility is rechecked at exchange and matching recovery, candidate registration and upgrade, owner confirmation and promotion, and the portal enforces the cancel-by-reissue limits.
- Sections 7–9: portal issuance and revocation are implemented (milestone 4). Capability metadata, deployment allocation and templates, Docker image/volume integration, owner-visible redemption diagnostics and refund accounting remain future work.
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
- Candidate and active validation still take the writer lock and reread the snapshot (the review-3 LOW on lock-free cached validation remains open). Since milestone 3, an unknown candidate token is rejected after a lock-free read of the committed snapshot, before the writer lock or any deadline-expiry write. Expiry of that path's records is left to the sweeps and authenticated operations.
- The proof nonce cache is process memory only. An edge restart clears it, so for up to 60 seconds after a restart a proof captured in the 60 seconds before it is no longer known as used. Such a replay could succeed once and still needs the bearer token as well as the captured header (both are deleted from access logs). The plan accepts this window rather than persisting nonces.
- Any active re-registration in candidate mode restarts the host's absence clock, including when the active socket is already down. A candidate therefore cannot promote in the gap between the active agent's register and its WS attach (M2 review LOW).
- A client controlling many source addresses can fill the anonymous exchange limiter table, which then fails closed; the global bucket protects the rest.
- The XFF trust assumption still needs the deployed-Caddy sentinel test.

## Agent (milestone 3)

Modules under `agent/` (all built-in `node:` APIs plus the existing `ws` dependency): `config.js` (env schema and pins), `state.js` (volume persistence and lock), `protocol.js` (wire formats and strict transport), `bootstrap.js` (exchange state machine) and `index.js` (`startAgent`, register/WS and the reconnect loop).

### Configuration

- Accepted `AGENT_*` names: `AGENT_BOOTSTRAP`, `AGENT_TOKEN`, `AGENT_HOSTNAME`, `AGENT_NAME`, `AGENT_LOCAL_UPSTREAM`, `AGENT_DEPLOYMENT_ID` and `AGENT_ENV_FORMAT`. `AGENT_ENV_FORMAT` is optional; only `1` is supported. `EDGE_HTTP_URL` and `EDGE_WS_URL` are also read. Any other `AGENT_*` name fails startup in bootstrap and persisted-credential modes, and the error names the setting but never its value. Token-only legacy mode (`AGENT_TOKEN` without `AGENT_BOOTSTRAP` and no saved state) skips that check and treats an unreadable state directory (EACCES/EPERM, for example `--user` against the image's 0700 directory) as no state, as 0.1.2 did (M3 review LOW). Unrelated environment such as `HOME` or `NODE_VERSION` is allowed.
- Key-bound modes (bootstrap and persisted credential) require `EDGE_HTTP_URL` to be exactly one audience in the image file `agent/edge-pins.json`. `EDGE_WS_URL` is optional; if set, it must equal `wss://<same authority>/_fastdog/tunnel`. The environment can only select a pinned entry: it cannot add a host, downgrade to HTTP or change trust roots.
- The repository ships an empty pin list, because the production edge name may not appear in the repository under the name-scan rule. Until a reviewed release adds the production audience, bootstrap mode fails closed with `edge_not_pinned`.
- Legacy `AGENT_TOKEN` mode keeps the 0.1.2 defaults and transport unchanged, and pins do not apply to it.

### State volume

- `/var/lib/fastdog-agent/credential.json` uses schema version 1 with strict fields, so unknown fields fail.
- Common fields: `hostname`, `origin`, `audience`, `deployment_id`, `private_key` (PKCS#8 PEM, RSA-3072) and `key_fingerprint` (SHA-256 of the SPKI DER, checked against the key on every read).
- `pending` adds the signed exchange request, the SHA-256 code digest (never the code), `created_at`, `deadline_at` (17 minutes, the most a code plus recovery can last), `next_attempt_at`, `attempt` and an optional terminal `failure`.
- `active` adds `credential_id`, `token` and `promoted`. Retry metadata is dropped and the private key is retained.
- Reads require a plain directory owned by the agent UID with no group or other access, and a regular, non-symlink, 0600, agent-owned file opened with `O_NOFOLLOW` (inode rechecked after open).
- Writes create an exclusive `O_EXCL|O_NOFOLLOW` 0600 temp in the same directory, write it completely, fsync it, rename it over the destination and fsync the directory. The process umask is 077. Any failure raises `state_write_failed`, and the agent never registers after one.
- Only the agent's own temp names (`.credential.json.<32 hex>.tmp`, `.write-probe.<32 hex>.tmp`) and a leftover `write-probe` file are removed at startup, while holding the lock.
- Nothing is written outside the volume and `/tmp` is not used, so a read-only root filesystem works.
- `agent/Dockerfile` creates the directory as `node:node` 0700 with an empty 0600 `.fastdog-agent-volume` seed, so Docker's empty-volume copy preserves the ownership. It declares no `VOLUME` (old run templates get no anonymous volume) and uses no root entrypoint or runtime ownership change.

### Lock

`.agent.lock` is created exclusively. The holder refreshes its mtime every 10 seconds. Another starting agent waits up to 35 seconds:
- A lock not refreshed for 30 seconds is a crashed holder's and is reaped. PIDs are not compared, because containers restart as PID 1 and two containers on one volume have separate PID namespaces. Reaping goes through an exclusive `.agent.lock.reap` claim and removes only the inode that was judged stale.
- A lock that stays fresh means `volume_busy` and exit 1.
- A holder that finds its lock replaced exits with `volume_lock_lost`.

Graceful shutdown removes the lock, including a SIGTERM/SIGINT that arrives while startup is still redeeming. A lock file that was created but could not be written or synced is removed at once. So only a crash restart waits for the stale ceiling.

### Startup order

1. Env schema.
2. Existing state file. Acquire the lock, read the state and check its binding against hostname, origin, deployment and pinned audience. Any corruption, unsafe file or mismatch fails closed without redeeming over it. A persisted credential ignores `AGENT_BOOTSTRAP`.
3. `AGENT_BOOTSTRAP` without state. Both secrets set means `ambiguous_config`. Otherwise:
   - acquire the lock;
   - run the full write probe;
   - generate the key and request, sign them once and persist them as `pending`;
   - only then call the exchange.

   A pending state is resumed only with the same code digest; retries send its stored request bytes. A pending key is never regenerated.
4. `AGENT_TOKEN`: legacy mode with a nonsecret deprecation notice. No lock or volume is needed.
5. Neither: `missing_credential`. The message keeps the existing `AGENT_TOKEN is required` wording.

### Exchange outcomes

| Response | Agent action |
| --- | --- |
| 200 | Validate exact fields and binding, OAEP-decrypt (SHA-256, label `fastdog-agent-bootstrap-v1`) and require a 64-hex token. Then persist `active`. |
| 400, 401, 409, 410 | Persist the failure, then exit 1 with a fixed diagnostic. Restarts exit again without a network call. `bootstrap_used` reports possible copying and advises revoke plus a fresh command. |
| 404, 405, 413, other 4xx | Exit 1. `next_attempt_at` is pushed 30 seconds out. |
| 200 that fails validation or decryption | Exit 1 with `bootstrap_response_invalid`; not terminal (a matching retry returns the stored response), but `next_attempt_at` is pushed 30 seconds out. |
| 429 | Wait for `Retry-After`. |
| 503, 5xx, network errors | Back off with `computeBackoffMs` (1 s base, 30 s cap, full jitter). |

Before each retry the next eligible attempt is persisted, so restarts neither reset the deadline nor retry early. Reaching `deadline_at` persists `bootstrap_expired`.

### Register and tunnel

- `register(credential, settings)` and `connectWs(credential, agentId, onWelcome, settings)` take the in-memory credential; nothing is written to `process.env`.
- Key-bound requests carry one fresh `X-Fastdog-Agent-Proof` over the exact target and body bytes (see the wire encoding above).
- Before the agent knows it is promoted, it registers with `?candidate=1`. On a 401 it tries the active path once. That succeeds only if the credential was already promoted, for example after a crash before the promotion was persisted.
- The edge's `candidate_status` frame drives the rest:
  - `held`: the agent stays connected, keeps heartbeats running and logs once per registration: "awaiting owner confirmation or old-agent absence; this agent's key fingerprint is <hex>".
  - `promoted`: the agent persists `promoted: true`, and later reconnects use the active path.
- Three consecutive registration rounds rejected with 401 end in exit 1 with a reconnect-required (`credential_rejected`) diagnostic. The old bootstrap is not retried.
- TLS uses `rejectUnauthorized: true` with `tls.rootCertificates`, so `NODE_TLS_REJECT_UNAUTHORIZED` and `NODE_EXTRA_CA_CERTS` cannot relax it. The origin probe's local exception is not inherited.
- HTTP requests use no redirects, a bounded response size, the pinned `Host`, a 15-second idle timeout and a 30-second overall deadline. WS sets `followRedirects: false`.
- `AGENT_LOCAL_UPSTREAM` longer than 200 characters (the saved-state limit) fails as `origin_invalid` naming the setting.
- Loopback HTTP/WS is reachable only through the code-level `fixture` option that tests inject, and must target 127.0.0.1, ::1 or localhost. No environment setting can select it.
- Heartbeats add `credential_mode` (`legacy` or `key_bound`) and `bootstrap_status` (`none`, `candidate`, `held` or `promoted`), and never any state contents. Welcome-based backoff reset and origin reporting are unchanged.

### Versions

`agent/package.json`, its lockfile, the Dockerfile `org.opencontainers.image.version` label and the heartbeat/exchange `agent_version` must agree; a test enforces this. They stay at 0.1.2 in this milestone, because the label and the published pins are out of scope. A release must bump all of them together (for example to 0.2.0) before an image is built, since the publish workflow refuses an existing tag.

### Milestone 3 validation

- `test/agent-bootstrap.test.js` uses the real edge `createBootstrap` service in-process, with no sockets except one loopback 401 fixture. It covers:
  - byte-identical transcripts and edge-verified proofs;
  - durable pending state observed before the first exchange call;
  - persisted-first restarts with zero calls;
  - corrupt, unknown-field, unsupported-schema, wrong-fingerprint, loose-mode, symlinked, directory and wrong-binding state failing closed;
  - legacy mode with and without the seeded directory;
  - both-secret and no-secret rejection;
  - unknown env names and formats;
  - disallowed or downgraded edges, with fixture-only loopback;
  - a symlinked, loose-mode, wrongly owned or missing directory, and EACCES, ENOSPC, fsync and rename failures, each with zero exchange calls and no state file;
  - pending-key recovery after a committed exchange whose response was lost;
  - leftover env with a fresh volume getting a persisted `bootstrap_used` exit;
  - backoff and Retry-After, with persisted next attempts;
  - restart waiting and the horizon;
  - lock busy, stale and lost cases, and temp cleanup;
  - no symlink following on a planted temp;
  - candidate-then-active registration with fresh proofs, ending in `credential_rejected`;
  - version agreement;
  - no secrets in logs or `process.env`.
- `test/agent-bootstrap-e2e.test.js` runs `startAgent` against the real `server.js` with the flag on. The exchange is served by `bootstrapHandler` with a test issuer check; since milestone 4, `server.js` rechecks candidates and promotion through the real portal issuer-check listener (`test/helpers/issuer-check.js`). The steps:
  1. exchange;
  2. candidate register and WS;
  3. `held` while a legacy agent is connected, with the fingerprint notice;
  4. owner confirmation using that fingerprint;
  5. promotion, which closes the old socket and persists `promoted`;
  6. tenant traffic through the new tunnel;
  7. a restart on the active path with no second exchange.

Open after milestone 3 (portal issuance and the issuer checker are milestone 4):
- A reviewed production pin entry.
- The version bump and image build.
- Docker integration tests (UID 1000, both architectures, read-only root, empty-volume population).
- Portal deployment metadata and templates.
- Caddy sentinel tests.

## Portal and issuer check (milestone 4)

### Portal issuance (`PORTAL_AGENT_BOOTSTRAP_ENABLED=1` only)

`portal/src/agent-bootstrap.js`. With the flag off, none of the routes, the `/agent` page or `/js/agent-bootstrap.js` exist, and every existing response is unchanged (snapshot below).

| Route | Who | Notes |
| --- | --- | --- |
| `POST /api/hostnames/:h/bootstraps` `{origin}` | Session, verified email, CSRF token, exact Origin | Issuer `session`: ID `sha256("fastdog-session-issuer:" + session hash)[0:32]`, generation = user `auth_version`. Charges the shared 5/day rotate budget. |
| `POST /api/v1/hostnames/:h/bootstraps` `{origin}` | API key with `connect` scope | Issuer `api_key`: key ID, generation = key `auth_version`. Charges `api-rotate` 3/day + shared 5/day. Trial tenants never pass (no keys). |
| `POST /api/connect/v1/bootstrap` `{origin}` | `fdct_` token, verified issuer | Issuer `connect_token`. One command per token: issuance marks it used; only a definitive refusal unmarks it. Charges `connect-token-rotate` 3/day + shared 5/day. |
| `GET` / `DELETE /api/hostnames/:h/bootstraps` | Session (DELETE: CSRF, Origin) | Nonsecret list (IDs, issuer kind, state, edge status of the newest); cancel pending codes, recovery and candidates. |
| `POST /api/hostnames/:h/bootstraps/candidates/:id/confirm` `{key_fingerprint}` | Session, CSRF, Origin | Owner confirmation of a held candidate (edge 409 on mismatch, 404 out of scope). |
| `POST /api/hostnames/:h/revoke-agent` `{confirm:true}` | Session, CSRF, Origin, browser confirmation dialog | Edge `POST /bootstraps/agent/revoke`: revokes every credential of the claim, cancels codes, recovery and candidates, closes the tunnel, mints nothing. |

Issuance responses (201, `Cache-Control: no-store`) contain `{issuance_id, code, hostname, origin, deployment_id, expires_at, note}`. The portal persists only nonsecret records in `agent_bootstraps.json`: no code, digest or credential. The deployment ID is a fresh random UUID per issuance until deployment allocation and templates exist. Before the edge call, a new issuance that would cancel a still-pending code (status checked at the edge; uncertain counts as pending) is limited to 3/hour and 6/24 h per user across hostnames. It returns 429 before any edge mutation. Like the existing portal budgets, these are rolling windows, not UTC days. An edge failure that may have committed (transport/timeout) is reconciled: look the issuance up, cancel an orphan, never retry. A connect token stays used. Bootstrap edge errors map onto portal-only codes (`agent_bootstrap_unavailable` 503, `agent_bootstrap_not_found`, `candidate_not_found` 404, `candidate_mismatch` 409), so existing routes keep their error mapping.

Revocation:
- Connect-token `DELETE` also cancels the claim's bootstraps when the newest live issuance came from a connect token. The edge honours only the newest issuance, so this cancels exactly that token's pending code, recovery and candidate. The response adds `bootstraps_cancelled`, flag on only. Active credentials and a connected agent are untouched. If the edge call fails, the revoked token is refused by the issuer check anyway.
- API-key deletion, password reset, logout and suspension invalidate pending issuance through the issuer check.

### Issuer-check protocol

Portal listener in `portal/src/issuer-check.js`; edge client in `src/onboard/issuer-check.js` (a parity test checks the two byte for byte).
- Keys: `HKDF-SHA256(ikm = service secret, salt = "fastdog-issuer-check-v1", info = "fastdog-issuer-check-request-v1" | "fastdog-issuer-check-reply-v1", 32 bytes)`.
- Request: `POST /internal/v1/issuer-check` with JSON exactly `{issuer_kind, issuer_id, authorization_generation, nonce}`. The nonce is 32 random bytes, base64url. Header `X-Fastdog-Issuer-Mac` = base64url HMAC-SHA256(request key, length-prefixed `["fastdog-issuer-check-v1", "request", kind, id, JSON(generation), nonce]`).
- Reply: 200 with JSON exactly `{issuer_kind, issuer_id, authorization_generation, nonce, valid, checked_at}` (ms). The same header carries HMAC(reply key, length-prefixed `[label, "reply", kind, id, JSON(generation), nonce, "true"|"false", String(checked_at)]`). JSON encoding of the generation keeps `1` and `"1"` distinct.
- Listener:
  - Loopback peers only; any forwarding header is 404, as is any path but the one route. Malformed requests get 400, a bad MAC 401.
  - Limits are 60/min per key, then 300/min global (fixed windows, two counters). Validator errors get 503.
  - Unknown kinds are `valid: false`. Validity requires an active, unsuspended tenant not suspended since the issuer was created, a verified user with an unchanged `auth_version`, and a live issuer: the session unexpired; the key unrevoked, unexpired, connect-scoped and on a paid plan; the token unrevoked and unexpired (used is fine).
  - Logs carry the status only.
- Edge client:
  - The edge verifies the MAC in constant time. The nonce must be its own, outstanding and unused: single-use, at most 1,024 entries, discarded 5 s after issue, with used/expired markers kept one more window. Every echoed field must be strictly equal, and `checked_at` within ±5 s.
  - Anything else throws 503 and increments one fixed reason in `issuerReplyRejected()`: capacity, transport, status, rate_limited, malformed, missing_mac, invalid_mac, unknown_nonce, reused_nonce, expired_nonce, different_request, mismatch or stale. These counters are deliberately not added to `/_fastdog/metrics`, which keeps flag-off metrics output unchanged.
  - Only an authenticated `valid: true` authorizes.

### Wiring on the edge

- Exchange and matching recovery: the existing check point, now the real client.
- Candidate registration and upgrade:
  - After token and proof validation, the candidate record's issuer is checked. The exchange copies kind, ID and generation from the code onto the pending credential as `issuer`, because the code's own issuer is dropped at its tombstone.
  - Invalid gives 401, unavailable 503. After the asynchronous check, durable liveness is rechecked before the registry changes.
- Promotion and owner confirmation:
  - `promoteCandidate` first runs a dry run. Holding never costs a check.
  - A promotable candidate is checked, then the real transaction rechecks everything with the registry state of that moment.
  - Unavailable leaves the candidate unchanged until its deadline; invalid drops it. Only one evaluation per candidate is in flight (`busy`).
  - Confirmation maps unavailable or busy to 503.
- Registry functions stay synchronous when the injected checker answers synchronously (unit tests). With the production asynchronous checker they return promises, which `server.js` awaits. Legacy register/upgrade paths are unchanged and synchronous.

### Milestone 4 validation

- `test/issuer-check.test.js`:
  - encoding/key parity, and a real listener with valid and invalid issuers;
  - a wrong-environment key;
  - forged replies, each a 503 that never counts as valid: missing or invalid MAC, request-direction MAC (both the sent header and a reply MACed with the request key), mismatched ID or generation (including `3` vs `"3"`), unknown, reused or expired nonce, stale `checked_at` either way, a valid reply to a different outstanding request, malformed bodies, 500 and 429;
  - bounded nonce table;
  - exchange 503 for each rejection and 401 only for an authenticated false;
  - unconfigured, partial or reused configuration.
- `test/bootstrap-candidates.test.js` (M4 tests): ineligible or unavailable issuers at candidate register and upgrade, held through unavailable promotion and confirmation, dropped on ineligible, asynchronous awaiting before any registry change.
- `portal/test/agent-bootstrap.test.js`, against the real internal API and listener:
  - issuance with CSRF, Origin, session and verification checks;
  - the code never stored;
  - list, cancel and cancel-by-reissue limits (also 6/day across hostnames);
  - API-key scope;
  - key deletion and password reset;
  - trial tenants;
  - connect-token single use and DELETE cancelling the pending code and candidate while the active credential and connection stay;
  - Revoke agent (confirmation, CSRF, Origin, other tenant 404, no replacement credential);
  - confirmation input checks;
  - the issuer validity matrix;
  - flag-off twins of every new path.
- `portal/test/issuer-check.test.js`: reply shape and direction keys, non-loopback and forwarded peers, wrong-environment key, rate limits, and the service credential unauthenticated on every other portal route, including internal-looking paths.
- `portal/test/flag-off-snapshot.test.js`: `flag-off-recorder.js` walks pages, scripts and session/key/token routes, including the new paths. The fixture was recorded from HEAD `d9d780c`'s portal and verified identical to the milestone-4 tree before being committed.
- `test/agent-bootstrap-portal-e2e.test.js`, both flags on in test only: portal session issuance, then edge internal `POST /bootstraps`, then real agent exchange at `server.js`. It asserts three authenticated session issuer checks (exchange, register, upgrade), the held notice, portal owner confirmation with a fourth check, promotion, traffic through the tunnel, and portal Revoke agent closing it. No secrets appear in logs or portal state.

Known milestone-4 limits:
- Owner-visible redemption diagnostics (redeem time, source IP, version, fingerprint) are not shown in the portal yet. The `/agent` page asks the owner to compare the agent's logged fingerprint.
- Refund accounting (plan section 4) is not implemented. Failed or orphaned issuances keep their budget charge (M5).
- The issuer check is a live call per check. A held candidate costs no checks until it becomes promotable.

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
