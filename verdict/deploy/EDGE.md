# PoP deployment (operator instructions; files only)

This checkout is the public build, not the live LAN installation. Do not deploy over `~/projects/verdict`. Review changes and back up the current edge release, Caddy config, `/etc/fastdog/verdict.env`, and `/opt/verdict/data` first. Use an already provisioned PoP; no paid resources are required by this guide.

1. Copy the reviewed release to `/opt/verdict` with Node 18+ and dependencies (`npm ci --omit=dev`). Create `/opt/verdict/data` with mode 0700. Keep existing data on upgrades. Verify transfer fingerprints with `sha256sum package-lock.json src/server.js src/engine/heuristic.js` on source and destination.
2. Create root-owned mode-0600 `/etc/fastdog/verdict.env` from `.env.example`, with `PORT=8089`, `VERDICT_BIND=127.0.0.1`, `VERDICT_ALLOW_BOOTSTRAP=0`, `VERDICT_DEMO_FORCE=0`. Generate a private clearance secret with `openssl rand -hex 32` redirected into the env file, not the terminal. Leave `TYPESAFE_API_KEY` absent. For example: `printf 'VERDICT_CLEARANCE_SECRET=%s\n' "$(openssl rand -hex 32)" >> /etc/fastdog/verdict.env`.
3. Review/copy `deploy/verdict-edge.service` to `/etc/systemd/system/`. The unit runs as root with a read-only filesystem except `/opt/verdict/data` and private temporary space. A dedicated user may be substituted with ownership of data and read access to the environment file. Ensure `/usr/bin/node` exists. `EnvironmentFile` values override `Environment`, so keep bind/port correct in the file. Operator-only activation: `systemctl daemon-reload` then `systemctl start verdict-edge`. Enabling at boot is a separate operator choice.
4. Before publishing Caddy, bootstrap via socket loopback. The script below stores the key in the env file without printing it; it requires Python 3. Do not use verbose curl, shell tracing, or paste the response into tickets.

```sh
sudo python3 - <<'PY'
import hashlib, json, os, urllib.request
request = urllib.request.Request('http://127.0.0.1:8089/v1/keys',
    data=b'{"name":"edge"}', headers={'Content-Type': 'application/json'})
with urllib.request.urlopen(request) as response:
    result = json.load(response)
path = '/etc/fastdog/verdict.env'
fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
with os.fdopen(fd, 'a') as env:
    env.write('\nVERDICT_API_KEY=' + result['key'] + '\n')
os.chmod(path, 0o600)
print('key_id:', result['id'])
print('sha256 fingerprint:', hashlib.sha256(result['key'].encode()).hexdigest())
PY
```

`VERDICT_API_KEY` is an operator/client credential, not needed by the server. The store contains only its hash. First-key creation through a loopback proxy would look local to Verdict: seed before publication and reject key creation at the public proxy as below. Bootstrap opt-in never bypasses authentication once keys exist, even when all are revoked.

## Caddy

Review with `caddy adapt --config /path/to/Caddyfile --validate` before the operator reloads Caddy. This repository does not install or restart services. Both hostnames need DNS/TLS configured by the operator.

```caddyfile
verdict.fastdognetworks.com {
    # Manage keys through loopback only, including bootstrap.
    @keyCreation {
        method POST
        path /v1/keys
    }
    respond @keyCreation "Key creation is loopback-only" 403
    reverse_proxy 127.0.0.1:8089 {
        header_up X-Forwarded-Host {hostport}
        header_up X-Forwarded-For {remote_host}
        header_up -X-Real-IP
    }
}

verdict-demo.fastdognetworks.com {
    @challenge path /demo /branding /branding/* /challenge*
    handle @challenge {
        reverse_proxy 127.0.0.1:8089 {
            header_up X-Forwarded-Host {hostport}
            header_up X-Forwarded-For {remote_host}
            header_up -X-Real-IP
        }
    }
    handle {
        route {
            vars verdict_auth_pending yes
            forward_auth 127.0.0.1:8089 {
                uri /v1/edge-auth
                header_up X-Forwarded-Host {hostport}
                header_up X-Forwarded-For {remote_host}
                header_up -X-Real-IP
                # Remove this line ONLY when intentionally demonstrating force mode.
                header_up -X-Verdict-Force
                transport http {
                    dial_timeout 50ms
                    response_header_timeout 200ms
                }
                @challenge status 401
                handle_response @challenge {
                    redir {rp.header.Location} 303
                }
                @blocked status 403
                handle_response @blocked {
                    respond "Blocked by Verdict" 403
                }
                @unavailable status 5xx
                handle_response @unavailable {
                    # Writing no response continues to the demo handler.
                    header X-Verdict-Fail-Open true
                }
            }
            vars verdict_auth_pending no
            rewrite * /demo
            reverse_proxy 127.0.0.1:8089
        }
    }
    # Dial failures/timeouts raise handler errors instead of upstream responses.
    handle_errors {
        @authUnavailable expression `{http.vars.verdict_auth_pending} == "yes" && {http.error.status_code} >= 500`
        handle @authUnavailable {
            header X-Verdict-Fail-Open true
            # Verdict itself may be down, so do not proxy this fallback to it.
            respond "Verdict demo: auth unavailable, request allowed" 200
        }
        handle {
            respond "Service unavailable" 503
        }
    }
}
```

This demo fails open on auth 5xx, dial failure and timeout. Challenge-route failures return an error. For a real application, replace the demo rewrite/reverse_proxy handler and the auth-error `respond` fallback with the same independently available application handler; preserve method/body and restrict error fallback to the auth stage. Do not fail open indiscriminately on application errors. `forward_auth` clones the request as GET and supplies original method/URI headers. See official [forward_auth](https://caddyserver.com/docs/caddyfile/directives/forward_auth) and [reverse_proxy response handling](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#intercepting-responses) documentation.

The API IP limiter counts socket peers, so requests through Caddy share its 120/window bucket; size `VERDICT_IP_RATE_LIMIT_MAX` appropriately. Edge velocity and clearance use overwritten forwarding headers. If another proxy sits in front of Caddy, configure its trust boundary before using its client IP assertions.

## Checks and rollback

- Check loopback `/health` reports 0.2.2. Use placeholder `KEY` in examples; use a private client config for actual bearer credentials. Verify normal GET `/login` allows, sqlmap blocks, and headless challenges.
- Through HTTPS, check a solved proof submitted to `/challenge/verify` issues the Secure cookie (an empty POST must fail), browser challenge returns to the original local path, and JSON edge debug retains 200/401/403 status codes. To demonstrate force, enable `VERDICT_DEMO_FORCE=1` and remove the proxy stripping line deliberately, then restore both settings.
- In staging, test auth HTTP 503 and an unreachable auth port; confirm `X-Verdict-Fail-Open: true`. Check original POST bodies reach an application if replacing the demo. The Caddy snippets require operator validation against the installed Caddy build.
- Roll back by restoring the previous Caddy configuration (or removing forward auth to leave the application reachable), validate it, and have the operator reload. Restore the previous `/opt/verdict` release and env file, then have the operator restart only `verdict-edge` if needed. Never restart the live LAN `verdict` unit. Preserve keys/usage/logs; avoid restoring stale key stores that resurrect revoked keys. Rotating `VERDICT_CLEARANCE_SECRET` invalidates all cookies.

## Phone demo and latency (0.2.2)

On the isolated verdict-demo instance only, set `VERDICT_DEMO_FORCE=1`.
Open https://verdict-demo.fastdognetworks.com/demo for the branded tap links:

- https://verdict-demo.fastdognetworks.com/?verdict=allow
- https://verdict-demo.fastdognetworks.com/?verdict=challenge
- https://verdict-demo.fastdognetworks.com/?verdict=block

`/demo`, `/branding` assets, and `/challenge*` bypass forward_auth. `/` passes through
forward_auth before being rewritten to `/demo`. Caddy supplies the original query
in `X-Forwarded-Uri`; header force still works if its stripping line is removed.
An explicit force overrides clearance in demo mode. Challenge return URLs remove
only the force query parameter so successful verification does not loop.
Keep force disabled on production instances; use a separate process for the demo
if the production API needs force disabled. No running Caddy configuration is changed here.

`dial_timeout 50ms` limits TCP connection setup only; `response_header_timeout 200ms`
limits waiting for auth response headers. Auth dial errors, 5xx and timeouts fail open.
`VERDICT_EDGE_GOODBOT_DNS=0` is the default: edge-auth never does DNS and claimed
Googlebot/Bingbot requests get `good_bot_pending` risk (at least challenge).
Opting into `VERDICT_EDGE_GOODBOT_DNS=1` permits reverse/forward DNS with a 200ms
DNS deadline. HTTP overhead means this can exceed Caddy's 200ms response header
timeout and fail open. `/v1/decide` still verifies claimed bots asynchronously.
Normal non-bot requests never use DNS. Decision writes are queued without awaiting
disk; usage snapshots are batched at one-second intervals and drained on graceful shutdown.

## 0.3.0 — Shadow, ASN, demo-force lock, per-host config

### Demo force (verdict-demo only)
Caddy for `verdict-demo.fastdognetworks.com` MUST set:

```
header_up X-Verdict-Demo 1
header_up -X-Verdict-Force   # strip client force on non-demo; demo may pass query
```

On all other sites, strip both:

```
header_up -X-Verdict-Demo
header_up -X-Verdict-Force
```

Force (`?verdict=` / `X-Verdict-Force`) is ignored unless `VERDICT_DEMO_FORCE=1` **and** `X-Verdict-Demo: 1`.

### Apex/www JSON access logs (log-only — never forward_auth)

```
fastdognetworks.com, www.fastdognetworks.com {
  log {
    output file /var/log/caddy/access-apex.json {
      roll_size 5MiB
      roll_keep 3
    }
    format json
  }
  # ... existing handlers unchanged ...
}
```

Same pattern for verdict-demo → `/var/log/caddy/access-verdict-demo.json`.

### Background jobs
Install `verdict-shadow.service`, `verdict-shadow-summary.timer`, `verdict-asn-refresh.timer`.
All set Nice≥10, CPUQuota=10%, MemoryMax≤200M.

### Per-host enforce
`node scripts/verdict-hosts.js set app.customer.com enable=1 mode=enforce fail=open`
then `node scripts/caddy-apply-hosts.js` (dry-run) / `--apply` (validate+reload+rollback).
Denylist hosts can never be enforce.
