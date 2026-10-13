# Attach a hostname and connect an agent

The [tenant API](../TENANT_API.md) is binding. The portal tenant flow differs from the legacy operator `attach-host` CLI. Default onboarding keeps the existing registrar/DNS provider; no NS cut is required. All example names are synthetic; substitute an authorized public test domain for live verification because `.test` is reserved and not publicly resolvable.

1. Use the portal’s own login (the Caddy basic-auth gate is removed), completing an email-bound invite and email verification. Add `app.example.test` through the portal. Tenant identity comes from the session; do not supply a tenant ID from the browser or use the operator credential for tenant hosts.
2. Publish the returned routing record (normally CNAME to the configured attach target, or supported apex A/alias path) and the exact returned TXT value at `_fastdog-challenge.app.example.test`. Standard apex CNAMEs are invalid; follow the API's apex note. Do not invent a TXT token or use `/etc/hosts` as ownership proof.
3. Choose Verify. Both routing and TXT must pass. Pending claims expire after 24 hours and do not reserve ownership; another tenant may win first. `hostname_unavailable` requires operator review, not forcing the mapping. A successful first activation returns a hostname-scoped credential once. Re-verifying an active claim does not return it again; rotate if it was lost.
4. Provision the agent's credential privately on the authorized origin. Configure `AGENT_HOSTNAME=app.example.test`, `AGENT_NAME`, `AGENT_LOCAL_UPSTREAM` (for example `http://127.0.0.1:8080`), `EDGE_HTTP_URL=https://edge.example.test` and `EDGE_WS_URL=wss://edge.example.test/_fastdog/tunnel`. `AGENT_TOKEN` here is the issued host credential, not the edge operator key. Keep it in the protected runtime environment, not shell history or tickets. Both HTTP and WS URLs must target the same edge; setting only WS leaves registration at its loopback default.
5. Run the installed `agent/index.js` using its confirmed manager (`npm run agent` for a foreground lab). Confirm successful registration, tunnel welcome and portal connected/last-seen status. Reconnect uses jitter/backoff; heartbeat detects dead connections. Check the local upstream independently if requests return 502. Token rejection after rotation requires installing the new credential, not repeatedly restarting with the old one.
6. The operator adds the explicit verified-host Caddy block using [cert-caddy.md](cert-caddy.md). Verify real HTTPS and application behavior, including a body-bearing request to a synthetic test endpoint. Agent connected, active claim and valid certificate are separate acceptance checks.

Rotate via portal when needed: the old token becomes invalid and the live tunnel closes; install the newly returned token. The current limit is five rotations/day/hostname, including recovery from a lost activation response. Detach through the owner portal/API to revoke claim credentials, remove dynamic mapping and close the tunnel, then remove the Caddy block with validation/reload. Coordinate DNS removal with the hostname owner; do not restore stale credential files.

If re-checks are eventually enabled, three authoritative routing mismatches suspend and revoke access; inconclusive routing results accumulate a persisted streak. From the eighth consecutive inconclusive check, each advances the failure counter (default suspension on the tenth, about 60 hours). With at least ten claims checked, a strict majority of inconclusive tenant votes freezes inconclusive counters for that run. Conclusive results reset the streak; the remaining intermittent-result concern is tracked in the Day 3 backlog. Scheduled runs never restore claims. Restore routing plus the original TXT and explicitly verify before the 24-hour suspended expiry; afterward create a new claim/challenge. Install the fresh credential after recovery.

Legacy operator attachments use `scripts/onboard.js` commands `attach-host`, `verify-host`, `list-attached-hosts`, `detach-host` under operator authorization. They occupy `attached_hosts.json` and cannot be taken over by a tenant. That flow's routing-only verification does not satisfy the tenant TXT contract. Do not use legacy map/issue commands to bypass tenant ownership. prod1 packaging in `deploy/` is reference only; this handover authorizes no prod1 changes.

## Install on Linux

The agent connects your web service to its verified hostname. Run it on the Linux machine that hosts your web service. Docker must be installed and running, and the machine must use systemd (the Linux service manager). This release's published image targets Linux amd64.

After verifying your hostname, keep the connection token shown by the portal. You also need the edge URL supplied by your operator. Replace the example URLs below with those values. `--hostname` is required. `--origin` is your local web service address; it defaults to `http://127.0.0.1:8080`. `--name` identifies this installation and defaults to `default`; use lowercase letters, numbers and hyphens only.

```sh
curl -fsSL https://portal.example.test/install/agent.sh -o /tmp/fastdog-agent-install.sh
sudo FASTDOG_AGENT_TOKEN='TOKEN' bash /tmp/fastdog-agent-install.sh --edge https://edge.example.test \
  --hostname app.example.test --origin http://127.0.0.1:8080 --name web
```

Use your actual portal address in place of `portal.example.test`. Do not save a real token in shell history or tickets. You can first download the script, review it, and use a hidden prompt in Bash:

```sh
curl -fsSL https://portal.example.test/install/agent.sh -o agent.sh
read -r -s -p 'Connection token: ' agent_token; printf '\n'
sudo FASTDOG_AGENT_TOKEN="$agent_token" bash agent.sh --edge https://edge.example.test \
  --hostname app.example.test --name web
unset agent_token
```

The token is passed in the environment (FASTDOG_AGENT_TOKEN), never in process arguments; `--token` is rejected. Run this on a trusted machine. The installer never prints it. It saves the token and connection settings in `/etc/fastdog-agent/web.env`, owned by root with mode 600, under a private directory. The service file is `/etc/systemd/system/fastdog-agent-web.service`. The container runs as the non-root `node` user. Host networking lets the container reach your web service on `127.0.0.1`.

The installer accepts an HTTPS edge address or its WSS equivalent, with an optional `/_fastdog/tunnel` suffix. It sets both `EDGE_HTTP_URL` and `EDGE_WS_URL` for the same server, plus `AGENT_TOKEN`, `AGENT_NAME`, `AGENT_HOSTNAME` and `AGENT_LOCAL_UPSTREAM`. It downloads `ghcr.io/soupnchill/fastdog-agent:0.1.0` and enables automatic restarts and startup after reboot.

Check the service with `sudo systemctl status fastdog-agent-web.service`, then confirm the portal shows the hostname as connected. If requests fail, check that your local web service is running at the origin address. A connected agent does not itself provision the hostname's certificate; complete the operator certificate step above.

To remove this installation and its saved token:

```sh
sudo bash agent.sh --uninstall --name web
```

Removal stops and disables the service and deletes its configuration. It retains the downloaded Docker image and does not detach the hostname or revoke its credential. Use the portal to detach the hostname when needed. To replace a token, uninstall this named installation and reinstall it with the newly issued token. This briefly interrupts the connection. Existing installations are never silently overwritten.

## Publish the container (operator)

DONE (lane G): container packaging, installer, public download route and offline regression coverage. Publication and live installation remain operator steps.

The workflow `.github/workflows/agent-image.yml` builds only the `agent/` context. The image uses `node:20-bookworm-slim`, copies three runtime modules, and installs only the locked production `ws` dependency. No token or runtime configuration is included. The OCI image version is `0.1.0`.

From a reviewed, committed release, publish with:

```sh
git tag agent-v0.1.0 && git push origin agent-v0.1.0
```

The workflow uses only `GITHUB_TOKEN`, pushes `ghcr.io/soupnchill/fastdog-agent:0.1.0`, and prints its digest. It does not publish a `latest` tag. **Make the package public once in the GitHub package settings**, so customer machines can pull it without GitHub credentials. A manual workflow run publishes the version in `agent/package.json`; a tag run requires the tag version to match. For a future release, update the package version, lockfile, image label, installer image reference and identical portal copy together before tagging.

The repository work is offline: building, publishing, pulling and live acceptance checks run only in the separately authorized workflow or operator procedure. `TLS_ASK_ENABLED` and `RECHECK_ENABLED` remain off; this installer does not change either flag or any ownership checks.
