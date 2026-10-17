# Agent bootstrap plan

Status: proposed design; documentation only. No implementation, image publication, pin change or deployment is authorized by this document.

## 1. Summary and goals / non-goals

Replace the long-lived Docker env credential with a 15-minute, single-use bootstrap code. A new agent exchanges it over HTTPS, writes its real credential into a named volume, and uses today's registration and tunnel protocol. This limits docker inspect exposure to the code's 15-minute lifetime / until redemption. A used or expired env file alone cannot recover the credential.

Preserve one env-fetch curl and ONE single `docker run` approval after the existing header-file setup and curl authorization. Volume creation is implicit in `docker run`; no preparatory Docker, shell, file-writing or permission commands. Name-conflict recovery retains the existing separately approved `docker rm -f` exception.

Non-goals: host-root isolation, Docker administrator isolation, unrelated service changes, automatic agent upgrades or changes to tunnel data frames. The Linux installation path stays unchanged. Authentication and ownership fail closed.

## 2. Current state and exact residual risk

| Source | Current behavior |
| --- | --- |
| `agent/index.js`: `register`, `connectWs`, `reconnectLoop` | Reads `AGENT_TOKEN` at module startup; registers with Bearer auth, then sends the same Bearer on the WebSocket upgrade. Missing token exits; reconnect retries indefinitely. |
| `agent/backoff.js`: `computeBackoffMs` | Full jitter exponential delay, base 1 second, cap 30 seconds. |
| `agent/heartbeat.js`: `startHeartbeat` | Ping every 20 seconds; terminates after two unanswered pings. |
| `agent/index.js`: `refreshOrigin`, `probeOrigin`, `AGENT_VERSION` | Reports origin reachability and package version in heartbeat status. Probe-specific TLS relaxation is local-origin-only. |
| `agent/Dockerfile` | Version label 0.1.2, Node 20 base, `USER node`, no credential persistence directory or volume setup. |
| `portal/src/connect-command.js`: `commandEnv`, `serializeDockerEnv` | Requires `AGENT_TOKEN`; emits six unquoted lines, rejects newline/NUL. `validOrigin` restricts origins to supported local/private addresses. |
| Same file: `dockerRun`, `dockerDetails`, `agentSuffix` | Secret-free run template, stable hostname-derived container name, host networking, env-file, restart policy and hardening; no volume. Pin is read from `portal/public/js/agent-view.js`. |
| Same file: `buildCommand` | Separate human JSON command: Docker pull, file creation, container replacement and run; Linux uses the installer. This chained command is not the strict one-approval path. |
| `portal/src/app.js`: `/api/v1/hostnames/:hostname/connect` | Scoped API key, active claim, validated origin/platform/format; `edge.rotateCredential`, then `markCommand`, then JSON or env response. |
| Same file: `/api/connect/v1/command` | Bearer connect token; rechecks issuer/auth version, active claim and claim creation time. `connectTokens.markCommand` precedes rotation; pre-success failures unmark it, budgets remain spent after edge call. |
| `portal/src/connect-tokens.js`: `createConnectTokens`, `assistantPrompt` | `fdct_` tokens are distinct: one hour, SHA-256 at rest, hostname/tenant/issuer binding, at most three live per host; one command per token. |
| `portal/src/edge-client.js`: `createEdgeClient().rotateCredential` | Calls internal `POST /internal/v1/tenants/:tid/hostnames/:hostname/credentials/rotate` with the portal key. |
| `src/internal/claims.js`: `rotate`, `revoke` | Revokes old credentials and calls `registry.closeHost` immediately, then issues and selects a replacement credential. |
| `src/onboard/credentials.js`: `issueCredential`, `validCredential`, `tenantOwner` | Random 32-byte hex credential; SHA-256 in `agent-credentials.json` (0600). Validation checks revocation, hostname and current owner's credential ID. |
| `src/edge/server.js`: `agentToken`, registration handler, WebSocket handler | Bearer precedence; registration at `/_fastdog/agents/register`, upgrade at `/_fastdog/tunnel`. Compatibility fallbacks remain. |
| `src/control/tunnels.js`: `registerAgent`, `attachWs` | Registration validates ownership/credential and replaces any agent for the host. WS auth compares the token hash with the registered record; it is not a fresh credential-store lookup. |

Current rate limits in `portal/src/app.js`: API keys 300 requests/10 minutes/IP and 60/minute/key; connect tokens 120/10 minutes/IP and 30/minute/token. Command budgets are separately 3/day/hostname for each bearer type, plus the shared portal 5/day rotation budget. Edge `claims.rotate` also enforces 5/day/hostname. JSON and env share budgets. Connect-token creation is 5/hour/tenant.

`site/llms.txt`, “Connect command”, and `docs/TENANT_API.md`, “Docker connect command”, specify curl `--create-file-mode 0600`, a fresh private file, `format:"env"`, `Cache-Control: no-store`, and user-run cleanup. Creation mode does not repair permissions of an existing file.

The remaining risk is durable bearer authority: the file survives until explicit deletion, and Docker stores `AGENT_TOKEN` in container configuration visible through inspect, including across restarts. A copied file or inspect output authenticates until rotation/revocation. Mode 0600 limits ordinary local readers but does not expire backups, accidental copies or disclosures. Deleting the file does not remove Docker's stored token.

`docs/DAY2_BACKLOG.md` records this one-approval tradeoff as shipped; bootstrap is not implemented. `docs/TENANT_API.md` is binding: the changes below require an explicit contract amendment in the implementation review. `docs/INTERNAL_API_OPS.md` supplies loopback/internal-key and test-tenant constraints; historical architecture notes do not override current code.

## 3. Design decisions and exchange protocol

### Code, binding and ownership

- Format: `fdab_` plus 32 random bytes encoded base64url (43 characters). `fdab_EXAMPLE` is documentation only. No embedded identity, credential or reversible payload.
- TTL: exactly 15 minutes from edge issuance; edge time is authoritative. No extension on attempts. One successful redemption; one outstanding code per claim, newer issuance invalidates earlier unused codes.
- Store only SHA-256(code), compared in constant time, on the edge. The portal transports the raw code once to the client and never persists it. Portal `fdct_` and API keys are not agent bootstrap credentials.
- Bind to tenant ID, normalized hostname, claim creation generation, current credential ID, issuer kind and key/connect-token ID, issuer authorization generation, canonical origin, deployment ID, and configured edge audience. Recheck the active owner and current credential generation at redemption. Any intervening rotation invalidates the code.
- Issuer metadata is supplied by the authenticated portal, never trusted from agent input. At exchange the edge asks a new authenticated loopback portal authorization-check endpoint whether that issuer/generation remains valid; unavailable portal means retryable 503, never permissive fallback. For `fdct_`, command-used is expected, but revoked/reset/expired authority is rejected. Bootstrap expiry is capped by issuer expiry.
- An origin binding prevents changing the approved upstream in the exchange. It cannot prove which physical machine redeems a bearer code or stop a malicious credential holder from lying later.

### Endpoint

Proposed public control endpoint: `POST /_fastdog/agents/bootstrap/exchange`, canonical path only, on the configured edge HTTPS authority. No redirects, cookies, API key, operator token or portal key. Authentication is `Authorization: Bearer fdab_EXAMPLE`; never query/body credentials.

Request JSON (maximum 16 KiB, 5-second handler deadline):

```json
{
  "hostname": "app.example.test",
  "origin": "http://127.0.0.1:8080",
  "deployment_id": "<public deployment UUID>",
  "request_id": "<random UUID persisted by agent>",
  "recipient_public_key": "<RSA-3072 public SPKI PEM>"
}
```

Tenant/issuer are derived from the code record. Validate exact canonical origin, audience and deployment binding; accept only RSA-3072 keys with exponent 65537 and bounded encoding. The agent generates this keypair inside its volume before exchange. Add `agent_version` and `proof` fields: RSA-PSS/SHA-256 (32-byte salt) signature over a versioned, length-prefixed canonical encoding of method, path, pinned audience, code digest and every request field except proof. Verify possession before consuming the code; bind the credential to the public-key fingerprint. This proves possession of the submitted key, not the identity of the intended machine.

Success: `200 application/json`, `Cache-Control: no-store`, `{credential_id, hostname, origin, deployment_id, algorithm:"RSA-OAEP-256", encrypted_token, recovery_expires_at}`. `encrypted_token` is base64url RSA-OAEP/SHA-256 encryption of the new 64-hex-character token to that public key. No raw credential is returned to the portal. Use Node crypto built-ins and a fixed protocol-version OAEP label.

The edge generates the credential using the same 32-byte randomness and SHA-256 storage semantics as `issueCredential`; refactor generation from persistence so exchange can commit it transactionally. The agent decrypts locally, validates shape and binding, then persists it. Encryption is a deliberate addition to support retries without storing recoverable plaintext on the edge.

| Status / error | Agent action |
| --- | --- |
| 400 `invalid_request` | Stop; malformed fields/key/origin, no echoed inputs. |
| 401 `unauthorized` | Stop; uniform status/body for unknown code, wrong tenant, wrong binding or invalid proof; no reflected inputs. |
| 409 `bootstrap_used` | Different request ID or recipient key already redeemed; stop and alert. |
| 410 `bootstrap_expired` | Stop; no automatic issuance. |
| 429 `rate_limited` | Respect `Retry-After` and remaining retry deadline. |
| 503 `bootstrap_unavailable` | Retry boundedly; authorization/storage uncertainty fails closed. |
| 404 / 405 / 413 | Disabled or wrong route / wrong method / oversized request; stop with safe diagnostic. |

Check request binding against the stored issuance before classifying used/expired codes; wrong bindings always receive the uniform 401. For a consumed code, its own successful promotion does not erase the used-code diagnostic: retain the tombstone and different-key reuse alert, but never return credentials after revocation.

Proposed limits: 30 attempts/minute/source IP before lookup, 10/minute/known code including successful retries, 30/minute/claim, global 300/minute. Use trusted proxy replacement or direct peer IP, never arbitrary forwarded headers. Bound limiter entries to 20,000; admission fails with 429 at capacity. Persist known-code/claim budgets across restarts; anonymous budgets may be in memory. No shared-PoP load testing.

### Lost-response retries and atomic consumption

Before any exchange the agent generates the RSA keypair and request ID and atomically persists them in its volume. Retries send exactly the same request. Fingerprint canonical request fields excluding the randomized PSS signature; retries may reuse their stored signed request. A successful transaction stores the request fingerprint, public key fingerprint, credential hash/ID and encrypted response alongside the consumed marker.

The first exchange consumes the code and issues one pending, key-bound credential; it does not revoke the active credential. Matching retries return the identical encrypted response until the 120-second activation deadline, even if the original issuance TTL has elapsed. This is response retrieval, not another redemption; only the persisted private key can decrypt it. A code-only thief may copy the public request but cannot recover the token. Different-key retries always fail. Revocation/ownership changes disable even matching recovery; do not return a now-revoked result.

If the agent loses its pending private key or misses the recovery deadline, request a fresh command and volume. Never regenerate a private key and retry a consumed code. After successful credential persistence, retain the private key with the credential for subsequent proof of possession; remove only exchange retry metadata. The consumed env code remains useless by itself.

Use one authoritative combined state file, `agent-auth-state.json`, for claims/ownership generations, credential hashes and key bindings, bootstrap consumption/recovery, pending activation deadlines, revocations and edge budget/refund ledgers. Replace the separate credential/claim/bootstrap stores; no multi-file redo journal or dual authoritative writes. Under one writer lock, validate a complete next snapshot, write an exclusive 0600 temp, fsync it, atomically rename on the same filesystem and fsync the parent directory before publishing memory or acknowledging success. On uncertain persistence, gate affected authentication and recover from the authoritative snapshot before serving. Migrate with writers stopped and a validated backup; never fall back to stale legacy files.

Serialize registration, activation, issuance and every revoke/rotate/detach/suspend mutation with this store. Existing `src/control/tunnels.js` `attachWs` compares only the hash cached at registration: require a fresh `validCredential` check against current ownership, status, generation and key binding on every upgrade, under the same transition lock. Every revocation path must close/remove affected records and sockets; stale registrations cannot bypass revocation. Crash tests must prove that no durably revoked credential validates after any simulated crash point (including rename, fsync, memory publication and socket closure); unacknowledged pre-commit mutations may recover the old complete snapshot, never a partial transition.

## 4. API and edge changes

New internal operations under `/internal/v1/tenants/:tid/hostnames/:hostname`:

| Operation | Contract |
| --- | --- |
| POST `/bootstraps` | Portal-key auth; `{origin, deployment_id, issuer:{kind,id,authorization_generation}, issuance_id}`. Active owner only. Returns code once, expiry and nonsecret metadata. No credential rotation yet. |
| GET `/bootstraps/:issuance_id` | Portal-key auth; status/IDs only, never code. Resolves an ambiguous issuance outcome. |
| DELETE `/bootstraps` | Portal-key auth; revoke pending codes and recovery responses for this claim. |

Keep loopback-only internal binding, separate portal key, scoped IDs and existing size/time limits from `src/internal/server.js` and `docs/TENANT_API.md`. Wrong tenant remains 404. New portal-internal issuer validation accepts only the edge's authenticated service call on loopback, with a separate service credential per environment, owned/rotated by the portal operator and provisioned outside the repo; never reuse the operator token. Request accepts only issuer ID + authorization generation and returns only a boolean (unknown/revoked/expired all false), never identity, scopes or account data. Rate-limit to 60/minute/service key and 300/minute globally with bounded counters; enforce loopback/internal-only ingress, no public proxy route. Unavailable/limited checks fail closed with retryable 503 at exchange. Test denial for external callers and wrong-environment keys.

Issuance IDs deduplicate edge mutations and budget consumption. If issuance response is lost, raw code is unrecoverable: query status, revoke the orphan, and require an explicit new command; do not automatically rotate or pretend the curl succeeded. A connect token stays command-used after committed issuance; do not revive its authority. After reconciliation, refund one unit to each budget charged by that issuance only when the orphaned code is confirmed never redeemed and expires or is revoked. Persist idempotent refund IDs, capped at one refund per issuance and three refunded issuances per hostname per UTC day across bearer types; never exceed the original charge or carry credit to a later budget window. Portal and edge reconcile their own ledgers by issuance ID, retrying safely after crashes; no refund on uncertain status or redeemed codes. The owner explicitly creates a fresh command/token. Only definitive non-commit failures may `unmarkCommand`; pending/uncertain calls retain reservations to prevent oversubscription.

For both portal connect endpoints, when bootstrap mode is eligible, replace `rotateCredential` with issuance and call host `markCommand` only on confirmed issuance. Preserve all authentication, scope, claim-generation checks and command budgets. Charge the edge's shared 5/day budget at issuance, not again at redemption; legacy rotations share it. Keep JSON/env budgets identical.

`commandEnv` and `serializeDockerEnv` select exactly one secret field: `AGENT_BOOTSTRAP` for the new pinned image, `AGENT_TOKEN` for the old one. Preserve the five existing nonsecret settings and add `AGENT_DEPLOYMENT_ID` for bootstrap mode (seven lines total). Continue Docker-only env output, newline/NUL rejection, no-store and JSON errors. Never emit both secrets. Linux retains legacy output. Update `buildCommand` and its browser twin to use the same mode and volume when generating new-image Docker commands.

Drop the template ticket. Keep `docker.run` secret-free and static for a selected deployment: authenticated metadata allocates a nonsecret deployment UUID with a short-lived server-side record (15 minutes) bound to tenant, hostname, principal, claim generation and exact image digest/mode. Use an authenticated, CSRF-protected POST for allocation, not a mutating GET; existing GET may read it. The already-authorized metadata flow precedes env fetch and adds no shell/Docker approval. The connect POST supplies that opaque ID; it conveys no authority, and existing authentication/ownership checks plus the server record decide eligibility. Wrong-tenant/principal IDs return 404. Snapshot the template/pin at allocation, reject expired or changed generations before charging issuance, and preserve the template for retries. Fresh explicit commands get fresh volumes; old clients receive legacy output only with a legacy template, otherwise upgrade-required. No signing key or transferable ticket is introduced.

Proposed template, with all placeholders resolved by `dockerDetails` except `ENV_FILE`:

```text
docker run -d --name fastdog-agent-<hostname-suffix> --network host --cap-drop ALL --security-opt no-new-privileges --restart unless-stopped --env-file ENV_FILE -v fastdog-agent-<hostname-suffix>-<deployment-id>:/var/lib/fastdog-agent IMAGE
```

`agentSuffix` retains its collision-resistant hostname suffix. Volume deployment IDs keep fresh commands separate from persisted old credentials. No additional Docker volume-create command. Server-side deployment/version validation prevents an early old template being paired with a later new env format; refresh metadata before issuance on mismatch.

Edge state lives only in the combined 0600 file in private runtime storage. Delete recovery ciphertext after its deadline; retain digest tombstones and redemption diagnostics for 24 hours, then purge. Cap live/recovery records at 10,000; refuse issuance at capacity, never evict live authority. Keep revocations until credential records can be safely removed without fallback validation. Bounded cleanup runs with nice and CPU/memory caps.

Private owner-visible redemption diagnostics contain redeem time, trusted source IP, claimed agent version and public-key fingerprint; version is untrusted, bounded display text. Restrict these to the owning tenant/session and retain 24 hours. General audit records contain only opaque IDs, event/reason/status/duration; never code, digest, key, body, origin, token, headers or ciphertext. Metrics have bounded reason labels, no hostname/tenant/code labels.

Require an explicit Caddy access-log filter removing `request>headers>Authorization` for `/_fastdog/agents/bootstrap/exchange` in every applicable logger (including error paths); also retain query/cookie redaction. Never log request/response bodies or enable credential logging. Before enabling bootstrap, validate the actual deployment Caddy config and run it locally with isolated loopback fixtures: send synthetic sentinel codes through success and failure routes and assert they appear in none of its access/error logs. A snippet-only test is insufficient; absence of Caddy/prepared artifacts blocks enablement, not this documentation change.

## 5. Agent startup and persistence

Proposed state file `/var/lib/fastdog-agent/credential.json`: schema version, credential ID/token, persistent private key and fingerprint, hostname, canonical origin, edge audience and deployment ID. Directory mode 0700; files 0600; UID/GID 1000:1000 (`node`, verify in built image). Create the owned directory and a harmless seed file in the image so Docker's default empty-volume population preserves ownership; test both architectures. Do not use `volume-nocopy` or require a root entrypoint/chown command. Existing wrongly owned volumes fail clearly.

Startup state machine:

1. Validate a known env schema (reject unknown `AGENT_*` names, unsupported format versions and unknown edge selections; allow ordinary unrelated process env). Check edge host/audience against immutable image pins. Acquire exclusive volume ownership (lock with crash recovery); never run two writers against one volume.
2. If a valid persisted credential exists, check binding against configured hostname/origin/audience/deployment, then use it. Ignore bootstrap on normal restart. Corrupt/mismatched state fails closed; do not silently redeem over it.
3. Else if bootstrap exists, test volume writability using the full write/fsync/rename/directory-fsync sequence, then restore or generate and durably persist pending request/key before any network exchange. Failure aborts before redemption. Exchange, decrypt, atomically persist credential and retained private key, then register. Post-exchange disk failure cannot revoke the old credential; pending key permits recovery until the activation deadline.
4. Else if legacy `AGENT_TOKEN` exists, use compatibility mode; emit only a nonsecret deprecation notice. It may operate without a volume as old deployments do. Do not claim inspect protection for this mode.
5. Else fail clearly: missing credential and bootstrap. Never print supplied values. If both bootstrap and legacy token exist without state, reject ambiguous configuration.

Atomic persistence: exclusive temp creation within the same directory, no symlink following, umask 077, explicit 0600, write complete JSON, fsync temp, rename over destination, fsync directory. Validate regular-file type/ownership/mode on reads. A write failure must never proceed to register; pending key enables safe retry. Remove abandoned temps only within the owned state directory. State is writable even with `--read-only` root filesystem; all agent writes stay in the volume, no reliance on `/tmp`.

Refactor `register` and `connectWs` to receive the loaded in-memory credential rather than the module-level env constant. Do not write it to `process.env`. Continue `POST /_fastdog/agents/register` Bearer, then `/_fastdog/tunnel?agentId=...` Bearer; no credential in URL/body. For new key-bound credentials both requests additionally sign a versioned method/path/body-hash/audience/credential-ID transcript with a fresh nonce and timestamp. Edge enforces a 60-second clock window and bounded, single-use nonce cache (fail closed at capacity); retries use fresh proofs. Legacy credentials retain the existing path. Losing the private key requires reissue; possession of the token alone cannot authenticate new-mode agents. Preserve `startHeartbeat`, origin reporting and welcome-based reconnect backoff reset.

Exchange uses `computeBackoffMs`, 1-second base/30-second cap with jitter, bounded by issuance/recovery deadline; honor 429. Network/503 failures retry the persisted request. Terminal failures log a safe code and remediation, exit nonzero; restart policy may restart the process but must not reset deadlines or hammer the endpoint (persist next eligible attempt). Revoked persisted credentials stop with a reconnect-required diagnostic instead of trying an old bootstrap.

Package version, image label and heartbeat `agent_version` must agree. Add nonsecret credential-mode/bootstrap-status reporting for portal diagnostics; never expose state contents. TLS verification is mandatory for exchange/register/tunnel; do not inherit `probeOrigin`'s local probe exception. Pin allowed edge HTTPS host/audience pairs in the image; env may select only among these values and cannot add a host, override trust roots or disable TLS. HTTPS/WSS same-authority URLs only in bootstrap mode, with loopback HTTP permitted solely in injected test fixtures.

## 6. Rotation and reconnect behavior

Decision: two-phase cutover. Exchange durably creates a pending credential with `activate_by = redeemed_at + 120 seconds`; keep the previous credential, selected owner ID and live tunnel valid. The pending credential may only register/establish its own candidate tunnel, not replace the active registry entry. A successful registration alone is insufficient: after validated registration plus authenticated WebSocket attachment and welcome readiness, atomically select the new credential and revoke the old one, then route to the new tunnel and close the old socket. Recheck active ownership and issuer authorization at promotion; unavailable issuer checks leave the candidate pending until its unchanged deadline. Serialize this promotion against revocation and generation changes. A crash after promotion may require reconnect, but cannot resurrect the old credential.

At the 120-second deadline, expire/revoke a never-ready pending credential and recovery response, remove candidate registrations and leave the healthy old site untouched. Check deadlines on every auth/recovery path and startup, not just cleanup timers. Matching exchange retries never extend the deadline; recovery lasts at most 120 seconds after redemption, even past the code's original expiry. A new issuance cancels any earlier pending code/credential but preserves the active one. Explicit revoke/detach/suspend/legacy rotate cancel candidates too; these intentional revocations do not wait for replacement. A thief who completes a tunnel can still trigger cutover: see detection/recovery below.

| Situation | Required behavior |
| --- | --- |
| New connect command | New code and deployment volume; invalidate earlier pending codes, leave current connection until replacement tunnel readiness. |
| Docker name conflict | User approves `docker rm -f` for exact returned container name once; rerun the same run template/env file. No reissuance merely for this conflict. |
| Restart / recreate same deployment | Reuse exact volume and settings; persisted credential wins even after bootstrap expiry. Container deletion without `-v` preserves named volume. |
| New command with old volume | Binding mismatch fails; never silently ignore requested replacement. Use the returned new volume. |
| Old container keeps running elsewhere | Continues until replacement tunnel promotion commits, then disconnected and unable to register with revoked credential. Stop it to avoid retry noise. |
| Lost/removed volume | Consumed code cannot provision fresh state; explicitly obtain a fresh command/new volume. Previous credential revoked only when replacement tunnel is ready. |
| Fresh volume + leftover used env | New recipient key/request is refused with `bootstrap_used`; no tunnel and no credential file. |

Portal revocation must distinguish pending bootstrap cancellation from revoking a running agent. Existing connect-token DELETE only revokes `fdct_` records today; it must also invalidate their pending bootstraps/recovery, without silently killing an already connected agent. API-key deletion/password reset likewise invalidates pending issuance through issuer checks. Add an explicit authenticated-session POST “Revoke agent” action with a confirmation dialog, reusing the existing portal CSRF token and exact-Origin checks. It revokes current credentials, cancels pending codes and closes/removes registry records; do not mint a replacement. Existing rotate/detach/suspension must cancel bootstrap generations too. Do not assume the backlog's unresolved tenant-suspension propagation is fixed; make that integration a rollout gate.

## 7. Threat model

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Read leftover env before use | 0600, private parent, 15-minute TTL, narrow binding, one redemption | Bearer thief can win first redemption; binding is not machine attestation. |
| Read env after use/expiry | Consumed/expired code refuses new recipient; recovery ciphertext bound to volume private key | Nonsecret origin/hostname metadata remains; live pending private key plus code enables recovery. |
| Docker inspect / Docker group | New-mode config contains only short-lived code; real token stays out of env | Docker group is root-equivalent: volume read, exec, memory and daemon access still expose live credentials. |
| Stale backups, history, accidental sharing | Old env/inspect copies cease to confer authority; commands contain no token | Volume backups contain live credentials; raw bootstrap leaks before use remain dangerous. |
| Race to redeem first | Persisted key, signed exchange, key-bound credential, single-use 15-minute code and two-phase cutover | Issuance precedes agent startup, so a thief can submit their own key first and win. A legitimate agent receiving `bootstrap_used` exits with a clear possible-theft/revoke-and-reissue diagnostic. Portal shows “redeemed by a different agent” on different-key reuse, with redeem time, source IP, claimed agent version and fingerprint; these indicate a mismatch, not proof of theft. Owner can explicitly revoke that credential and reissue. |
| Replay / concurrent redemption | Serialized transaction, request fingerprint, identical encrypted retries only | Same legitimate volume can reconnect by design; that is credential reuse, not bootstrap replay. |
| Brute force / resource exhaustion | 256-bit randomness, bounded keys/bodies/stores, layered rate limits | IP/global limits can cause availability loss; tune from canary data. |
| MITM / malicious redirect | Verified TLS to configured edge, reject redirects and cross-authority WS URLs | Without image pins, whoever edits the env can point the agent at a rogue edge and steal the code. Pins reject that redirect, but malicious env edits can still break startup or choose another allowed environment; code audience binding prevents cross-environment redemption. Image/host-root/trust-store compromise remains outside protection. |
| Origin tampering / SSRF | Reuse `validOrigin`/`originError` validation on edge, exact canonical binding; exchange performs no origin fetch | Approved private upstream access is intentional. Local DNS rebinding and a malicious credential holder need separate forwarding controls; bootstrap does not solve them. |
| Logs / error leaks | Redact headers/bodies, fixed error codes, no crypto/state dumps | Debug tooling and host administrators can still disclose secrets; test failure paths too. |
| Edge/portal state theft | Bootstrap hashes only; edge credentials hashes plus recipient-encrypted recovery | Portal service authority or active host compromise can issue credentials; not addressed by stale-file protection. |

## 8. Tradeoffs and alternatives

| Alternative | Decision |
| --- | --- |
| `-e AGENT_TOKEN=...` | Reject: command arguments/history and inspect retain the live bearer. |
| Docker secrets / Swarm | Reject for default path: extra orchestration/secret creation, not one standalone run. |
| stdin / shell pipelines | Reject: complicates daemonized startup/restarts and approval allowlists; still needs durable credential storage. |
| Mount env file and let agent delete it | Reject: env-file is read client-side, not mounted; adding writable host mount/deletion creates ownership hazards and cannot erase copies/backups/inspect. |
| Agent pulls credential using API key | Reject: puts broader, reusable portal authority on origin; larger compromise scope. |
| Bind only to expected origin/hostname | Insufficient: a thief can copy both; these are routing constraints, not machine identity. |
| Pre-register agent key before code issuance | Stronger race prevention, but needs an extra provisioning step before the one-run flow; not the default. |
| Portal fingerprint confirmation | Optional future hardened mode could hold promotion until owner compares the local fingerprint over an independent trusted channel. Defer from this default flow; merely displaying a fingerprint or clicking blindly does not prevent theft. |
| Revoke at issuance | Reject for bootstrap: unused or failed commands would disconnect healthy agents. |
| Return plaintext again on retry | Reject: consumed code alone would remain a credential retrieval token. |
| No retry after consumption | Simpler, but lost responses force avoidable rotation/outage. Choose encrypted response recovery with durable recipient key. |
| Stable volume across all new commands | Reject: persisted-state-first startup would ignore fresh bootstrap. Separate deployment volumes preserve deterministic precedence. |

Costs: extra state, transaction recovery and cryptographic protocol review; stale named volumes require explicit owner cleanup. No automatic pruning of credential volumes. Prefer built-in crypto over dependencies; review OAEP parameters and test vectors before implementation approval.

## 9. Migration from 0.1.2

| Image / input | Outcome |
| --- | --- |
| 0.1.2 + old `AGENT_TOKEN` env | Works unchanged; existing agents untouched. |
| 0.1.2 + bootstrap env | Unsupported; portal must never produce this pairing. |
| New image + old token env | Legacy fallback works; same inspect exposure, no bootstrap promise. |
| New image + bootstrap + fresh named volume | Redeem and persist, then ordinary tunnel auth. |
| New image + matching persisted volume | Reconnect without redeeming, even if env code expired. |

Portal uses an explicit capability allowlist keyed by the exact pinned image digest, not a loose version comparison or client-supplied version. Bootstrap requires compatible pin, flags, server-side deployment metadata and healthy edge capability. Old pin always emits old env. Flags off retain legacy behavior; do not silently fall back to plaintext after an attempted bootstrap issuance. Snapshot template mode/pin for the whole command transaction.

Implementation must update `site/llms.txt`, `docs/TENANT_API.md`, `docs/INTERNAL_API_OPS.md`, portal prompt/browser copy and agent attach runbook together. Explain volume retention, seven-line env format, delayed rotation, used-code refusal, recovery, deployment metadata handling and continued optional user cleanup. Keep the one-curl/one-run procedure; no secret printing. Those files and the image pin remain unchanged by this documentation task.

Proposed timeline relative to approved rollout: day 0 opt-in canary; after at least 7 healthy days bootstrap becomes default for compatible Docker templates; at day 30 announce env-token deprecation; no earlier than day 90 disable legacy Docker issuance only after the count of active legacy-token agents is zero across all claims/environments and owner approval; inventory uses registered credential mode plus persisted unrevoked legacy assignments so temporarily offline agents are not mistaken for migrated agents. Keep new-agent `AGENT_TOKEN` fallback for at least two releases and until the separately planned Linux migration. Existing agents are never revoked merely for version age. Record implementation work DONE in the backlog only when actually implemented and validated, not for this plan.

## 10. Tests and acceptance gates

- Unit exchange tests: exact TTL boundary, invalid/unknown formats, single-use, every binding dimension, issuer expiry/revocation, other-tenant isolation, rate limits/Retry-After and bounded storage, concurrent different/same recipient redemption.
- Lost-response tests: drop response after commit, retry same persisted key/request, decrypt same credential; different key fails; copied public request yields only undecryptable ciphertext. Recovery expiry and revocation forbid retrieval. Issuance timeout reconciliation refunds only confirmed never-redeemed orphan expiry/revocation; test duplicate reconciliation, caps, window rollover, concurrent issuance and redeemed refusal, without leaking stored code.
- Transaction crash tests at each fsync/rename/commit step; restart and prove one selected active credential plus at most one pending candidate, correct owner ID and no revoked credential validates at any simulated crash point. Cover revoke/detach/suspend/rotate between registration and attachWs, including cached registrations and reconnects.
- Two-phase tests: redemption and lost response leave the old tunnel healthy; deadline (including restart) expires only the pending credential; successful register without WS cannot cut over; ready tunnel promotes exactly once; racing revoke prevents promotion.
- Portal tests: 0.1.2 is never paired with bootstrap env; stale metadata/pin mismatch fails before issuance; other-tenant/principal deployment IDs return 404; Revoke agent requires session, existing CSRF and confirmation; different-agent status displays safe diagnostics and revoke/reissue actions.
- Agent state tests: persisted-first, absent/corrupt/wrong-binding state, legacy fallback, both-secret rejection, permission/symlink/disk-full failures proving zero exchange calls before durable pending state, unknown env rejection and disallowed edge host/audience rejection, pending-key crash recovery, deadlines, backoff, no credential in process env, version reporting.
- Docker integration using prepared local images: automatic volume ownership with UID 1000 and cap-drop, read-only root fs, restart, same-volume recreate, new-volume replacement, name conflict, old container behavior, volume loss, invalid preexisting ownership. No image pulls in offline suites.
- Redaction tests scan stdout/stderr, HTTP errors, proxy/audit logs, Docker config and metrics using injected sentinel secrets; include 400/401/409/410/429/503 and transport exceptions. Real tokens never enter fixtures.
- Strict one-prompt E2E: pre-authorized curl and header setup, metadata supplies full volume template, ONE curl writes fresh 0600 env, ONE standalone Docker run approval, status via curl. Fail if flow requires shell, chmod/chown, file inspection, volume create, pull or extra approval. Separate reconnect E2E allows only the documented name-conflict removal.
- Leftover-file E2E: after successful first use, rerun identical env with an empty fresh volume and nonconflicting test container name; expect `bootstrap_used`, no new credential/tunnel. Same-volume restart is a separate positive case, not an expected refusal.
- Name-scan `test/no-hardcoded-names.test.js` must pass unchanged; explicitly scan the new document too because tracked-file scans may omit an untracked plan. No baseline exemptions.
- Run both mandatory suites from repository root with prepared dependencies and external access blocked; require zero failures and zero new skips:

```sh
NODE_OPTIONS="--require=$PWD/test/helpers/offline.cjs" npm test
NODE_OPTIONS="--require=$PWD/test/helpers/offline.cjs" npm run test:portal
```

## 11. Rollout and rollback

1. Review contract changes, transaction/retry protocol and permission model. Build/test locally for linux/amd64 and linux/arm64 using approved artifacts. Produce immutable multi-arch manifest digest, matching package/OCI versions and provenance. Do NOT publish until the owner approves; this plan does not authorize builds, registry access or operational actions.
2. Add `AGENT_BOOTSTRAP_ENABLED` on edge and `PORTAL_AGENT_BOOTSTRAP_ENABLED` on portal, both default off. Allow canary selection only for operator-designated test tenants. Keep `TLS_ASK_ENABLED`, `RECHECK_ENABLED` and Verdict settings unchanged.
3. Prepare an edge deploy kit under `docs/runbooks/deploy.md` and rollback runbook procedures: release/unit inventory, migration/recovery tool, offline checks, narrowly scoped Caddy allowance for the exchange on the edge host, rejection on tenant hosts, log redaction and acceptance commands. Internal APIs remain private.
4. During separately authorized staging: stop writers, back up code/config/state under `/root/backups/<tag>-<timestamp>`, stage without overwriting runtime data, validate Caddy, restart only affected units, verify health/auth isolation and recovery. Preserve portal previous code at `/opt/fastdog-portal.old`.
5. Exercise an operator test tenant using `docs/INTERNAL_API_OPS.md` marking and normal ownership/routing proof; no guardrail exceptions or load tests. Test both architectures, response-loss recovery, revoke, and rollback before canary expansion.
6. After owner approval publish the image; flip portal pin and matching capability metadata together, enable only the canary, then expand after at least seven healthy days. Existing running agents remain untouched.
7. Monitor redemption latency, 4xx/5xx by bounded reason, expired-unused ratio, retry recovery, reused codes, storage health and registration failures. Alert immediately on transaction corruption or any different-key reuse for a known code; investigate if exchange 5xx exceed 1% for five minutes with at least 20 requests. Low-volume canary uses individual failure review. Portal surfaces safe deployment status so an old still-connected agent cannot masquerade as successful replacement.
8. Rollback starts by disabling new issuance and restoring the prior portal pin/template; keep exchange/recovery available for already-issued codes through their maximum 17-minute issuance-plus-activation horizon, unless security requires immediate cancellation. Retain support for key-bound credentials and proof verification; an old edge lacking it is not a safe rollback target for these agents.
9. Quiesce writers and validate the combined snapshot before rolling edge code back. Use a compatibility release that reads this state and enforces key bindings; never export key-bound tokens into a bearer-only validator or restore stale credential state that resurrects old tokens. If recovery cannot be proved, stop issuance/auth for affected claims and require explicit reissue after repair. Untar recorded `code.tgz` at its recorded root, restart the unit, validate Caddy and acceptance checks. Retain new state/volumes for forward recovery; never delete them to hide a rollback error.

## 12. Implementation ownership and review log

Confirm image version/publication owner, multi-arch capacity, canary ownership, issuer-check key owner, diagnostic retention, suspension integration and operational alert handling before implementation. The 15-minute code TTL, 120-second activation/recovery deadline, combined state and two-phase cutover are design decisions, not unresolved options. No implementation or deployment is marked DONE by this plan.

### Review log

- HIGH — First-bearer race: durable agent key, signed exchange and key-bound credentials; honest pre-start theft residual, different-agent diagnostics and owner revoke/reissue. Origin-only binding rejected; fingerprint confirmation considered and deferred.
- HIGH — Revocation timing: old tunnel retained through candidate registration/WS readiness; pending credentials expire after 120 seconds without disrupting it.
- MEDIUM — Cached attachWs auth: fresh `validCredential` checks and serialization for revoke, detach, suspend and rotate, with regression tests.
- MEDIUM — Journal complexity: one atomic combined snapshot; crash invariant forbids revoked credential resurrection.
- MEDIUM — Volume writes: writability and durable key/pending-state persistence before any exchange; failure aborts redemption.
- MEDIUM — Lost issuance response: idempotent, capped one-unit refunds for confirmed never-redeemed orphans on expiry/revocation.
- MEDIUM — Template ticket: removed; static secret-free run template with authenticated server-side deployment allocation and cross-tenant 404 test.
- MEDIUM — Issuer-check oracle: boolean ID/generation check only, internal ingress, bounded rates and per-environment service keys.
- MEDIUM — Access logs: explicit Authorization removal and no body logging; sentinel test against actual Caddy config gates enablement.
- MEDIUM — Env trust root: immutable image host/audience pins; env editor, image and host compromise residuals stated.
- LOW — Error isolation: uniform public 401 for unknown, wrong-binding and wrong-tenant requests.
- LOW — Revoke agent: existing portal CSRF and Origin checks, authenticated POST and confirmation.
- LOW — Inspect wording: exposure limited to 15-minute lifetime / until redemption, not eliminated before use.
- LOW — Migration pairing: portal test excludes 0.1.2/bootstrap pairing; new agent rejects unknown agent env/schema.
- LOW — Legacy disable: zero active legacy-token agents required, including offline unrevoked assignments.
- LOW — Placeholders: hostname examples use `app.example.test`; no real tokens.
