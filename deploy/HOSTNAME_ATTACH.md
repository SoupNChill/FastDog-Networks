# Hostname attach deployment runbook

This runbook covers the deployment and operation of the CNAME/hostname-attach onboarding path. **This is the default first-seat onboarding path.** NS cut remains an advanced/optional path.

## Overview

Hostname attach allows customers to keep their registrar DNS (including Cloudflare Free). They CNAME their hostname to FastDog's edge target. FastDog terminates TLS and proxies via WebSocket tunnel to their origin agent.

```
Customer DNS:  app.customer.com  CNAME  attach.fastdognetworks.com
                                           │
                                           ▼
FastDog edge:  attach.fastdognetworks.com  A  157.230.57.32
               (Caddy terminates TLS via HTTP-01)
                                           │
                                           ▼
               fastdog-edge proxy → WS tunnel → customer agent → origin
```

## Prerequisites

Before deploying, ensure:

1. **DNS record for attach target** exists in the FastDog zone:
   ```
   attach.fastdognetworks.com.  300  IN  A  157.230.57.32
   ```

2. **Edge server** is running and reachable

3. **Caddy** is configured to handle dynamic TLS (HTTP-01)

## Customer steps (quick start)

### 1. Attach hostname

```sh
# Via CLI
npm run onboard -- attach-host app.customer.com

# Via API
curl -sS -X POST http://127.0.0.1:8787/_fastdog/onboard/attach-host \
  -H "x-fastdog-token: $AGENT_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"hostname":"app.customer.com"}'
```

Response includes CNAME instructions:
```json
{
  "hostname": "app.customer.com",
  "status": "pending",
  "cname_target": "attach.fastdognetworks.com",
  "cname_instructions": "Add this CNAME record at your registrar:\n\napp.customer.com.  300  IN  CNAME  attach.fastdognetworks.com.\n\nThen run: npm run onboard -- verify-host app.customer.com"
}
```

### 2. Add CNAME at registrar

Customer adds the CNAME record at their registrar (Cloudflare, Namecheap, GoDaddy, etc.):

| Type | Name | Target | TTL |
| --- | --- | --- | --- |
| CNAME | app | attach.fastdognetworks.com | 300 |

Wait 5-10 minutes for DNS propagation.

### 3. Verify DNS

```sh
# Via CLI
npm run onboard -- verify-host app.customer.com

# Via API
curl -sS -X POST http://127.0.0.1:8787/_fastdog/onboard/verify-host \
  -H "x-fastdog-token: $AGENT_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"hostname":"app.customer.com"}'
```

On success, response includes:
- `status: "active"`
- `credential`: agent token (save immediately, shown once)
- `caddy_block`: Caddy configuration snippet

### 4. Run agent

```sh
export AGENT_TOKEN='<issued-token>'
export AGENT_HOSTNAME=app.customer.com
export AGENT_LOCAL_UPSTREAM=http://127.0.0.1:8080
export EDGE_WS_URL=ws://edge.fastdognetworks.com/_fastdog/tunnel
npm run agent
```

### 5. HTTPS works

After operator completes Caddy setup (see below), `https://app.customer.com` serves via FastDog.

## Operator steps

### Edge route reload

After hostname verification, routes are automatically reloaded. For manual reload:

```sh
curl -sS -X POST http://127.0.0.1:8787/_fastdog/routes/reload
```

### Caddy TLS setup

Phase 1 uses operator-assisted Caddy configuration.

1. **Get Caddy block** from verify-host response or generate manually:

   ```caddy
   app.customer.com {
       reverse_proxy localhost:8787
       log {
           output file /var/log/caddy/app.customer.com.log
       }
   }
   ```

2. **Add to Caddyfile** on edge server:

   ```sh
   # SSH to edge server
   ssh root@157.230.57.32
   
   # Edit Caddyfile
   nano /etc/caddy/Caddyfile
   
   # Add the block at the end
   ```

3. **Reload Caddy**:

   ```sh
   systemctl reload caddy
   # Or: caddy reload --config /etc/caddy/Caddyfile
   ```

4. **Verify TLS**:

   ```sh
   curl -sS https://app.customer.com/health
   ```

Caddy uses HTTP-01 challenge to automatically obtain Let's Encrypt certificate.

### Verification checks

```sh
# Check DNS resolution
dig app.customer.com CNAME
dig app.customer.com A

# Check edge routes
curl -sS http://127.0.0.1:8787/_fastdog/routes

# Check attached hosts
curl -sS -H "x-fastdog-token: $AGENT_TOKEN" http://127.0.0.1:8787/_fastdog/onboard/attached-hosts

# Check tunnel agents
curl -sS http://127.0.0.1:8787/_fastdog/agents

# Test via Host header (before Caddy TLS)
curl -sS -H 'Host: app.customer.com' http://127.0.0.1:8787/
```

## Rollback

### Detach hostname

```sh
# Via CLI
npm run onboard -- detach-host app.customer.com

# Via API
curl -sS -X DELETE http://127.0.0.1:8787/_fastdog/onboard/attached-hosts/app.customer.com \
  -H "x-fastdog-token: $AGENT_TOKEN"
```

This removes:
- Attachment record from `attached_hosts.json`
- Hostname from `tunnel_hosts.json`

### Remove Caddy block

1. **Edit Caddyfile** on edge server and remove the hostname block
2. **Reload Caddy**: `systemctl reload caddy`

### Customer removes CNAME

Customer removes the CNAME record at their registrar.

## Fail-closed behavior

If verification fails, the hostname stays in `pending` status:
- No tunnel binding (hostname not in `tunnel_hosts`)
- No credential issued
- Edge returns 404/503 for the hostname
- Caddy should not be configured for unverified hostnames

## LAN demo (without production DNS)

To demo attach on LAN without touching real DNS:

### Option 1: /etc/hosts

```sh
# On client machine
echo '192.168.200.42 app.demo-customer.test' >> /etc/hosts

# Skip DNS verification (already verified by hosts file)
# Directly issue credential and map tunnel host
npm run onboard -- issue-credential --hostname app.demo-customer.test
npm run onboard -- map-host demo.zone app.demo-customer.test

# Run agent
AGENT_TOKEN='<issued-token>' AGENT_HOSTNAME=app.demo-customer.test AGENT_LOCAL_UPSTREAM=http://127.0.0.1:9999 npm run agent

# Test
curl -sS -H 'Host: app.demo-customer.test' http://192.168.200.42:8787/
```

### Option 2: Mock DNS verification

For testing the full attach flow with mock DNS:

```sh
# Set environment to use local resolver
export ATTACH_TARGET=app.demo-customer.test

# The verification will check for CNAME to app.demo-customer.test
# Use a local DNS server or dnsmasq for testing
```

### Option 3: Operator UI

1. Open operator dashboard: `http://127.0.0.1:8788/`
2. Enter agent token
3. Use "Quick attach" panel
4. For LAN demo, use Host header testing after manual tunnel mapping

## Existing FastDog zone dogfood

`lease.fastdognetworks.com` uses the NS-cut path (A record + tunnel_hosts in FastDog authoritative zone). This is separate from hostname-attach. **Do not modify `lease.fastdognetworks.com` or any Summit Lease resources.**

## Do NOT

- Do NOT change anything touching `trysummitlease.com` or cloudflared
- Do NOT SSH to production from automated scripts in this agent
- Do NOT configure Caddy for unverified hostnames
- Do NOT issue credentials before DNS verification passes
- Do NOT serve public traffic for pending attachments

## Related docs

- [Hostname attach design](../docs/HOSTNAME_ATTACH.md)
- [Onboarding (updated)](../docs/ONBOARDING.md)
- [NS cut runbook](NS_CUT.md)
