# Hostname attach (CNAME onboarding)

This is the **default first-seat onboarding path** for FastDog Networks. Customers keep their registrar DNS (including Cloudflare Free) and CNAME their hostname to FastDog's edge. FastDog terminates TLS and proxies via WebSocket tunnel to their origin agent.

## When to use each path

| Path | Use case | DNS action | Zone authority |
| --- | --- | --- | --- |
| **Hostname attach (CNAME)** | First seat, quick onboard, keep registrar DNS | Customer adds CNAME → FastDog edge | Customer registrar keeps zone |
| NS cut (authoritative) | Full zone control, advanced features, custom records | Customer changes registrar NS to FastDog | FastDog becomes authoritative |

**Default = hostname attach.** NS cut is an advanced/optional path documented in [NS_CUT.md](../deploy/NS_CUT.md).

## How it works

### Customer DNS setup

The customer creates a CNAME (or ALIAS/ANAME at apex-supporting registrars) pointing their hostname to FastDog's edge target:

```
app.customer.com.  300  IN  CNAME  attach.fastdognetworks.com.
```

**Edge target:** `attach.fastdognetworks.com` — a dedicated hostname for attached customers. This target resolves to FastDog's edge IP (`157.230.57.32` in production).

> **Apex note:** CNAME at the zone apex (`@`) is not supported by standard DNS. Customers with apex-only needs should:
> 1. Use a subdomain (`www`, `app`) with CNAME (recommended)
> 2. Use ALIAS/ANAME if their registrar supports it (Cloudflare, DNS Made Easy, Route 53)
> 3. Consider NS cut for full apex control
>
> Attach-host verification fails if the CNAME is unreachable or misconfigured. The attach stays pending; public traffic is not served.

### Control-plane lifecycle

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  attach-host    │────▶│   show CNAME    │────▶│   verify-host   │────▶│  bind tunnel    │
│  (pending)      │     │   instructions  │     │   (DNS lookup)  │     │  + issue cred   │
└─────────────────┘     └─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                              ┌─────────────────┐
                                              │  TLS ready      │
                                              │  (Caddy HTTP-01)│
                                              └─────────────────┘
```

1. **attach-host**: Create attachment record with status `pending`. Returns CNAME instructions.
2. **Customer action**: Add CNAME record at their registrar.
3. **verify-host**: DNS lookup confirms hostname CNAMEs (or A) to FastDog edge target. Status → `verified`.
4. **On verify**: 
   - Add hostname to `tunnel_hosts` for edge Host routing
   - Issue hostname-bound agent credential
   - Status → `active`
5. **TLS**: Caddy uses HTTP-01 challenge to issue Let's Encrypt certificate for the attached hostname.

### Status states

| Status | Meaning | Public traffic |
| --- | --- | --- |
| `pending` | Attached, awaiting DNS verification | **Blocked** (fail-closed) |
| `verified` | DNS verified, awaiting Caddy TLS setup | **Blocked** until Caddy configured |
| `active` | TLS ready, tunnel host bound | **Served** via tunnel |

## Fail-closed behavior

If the CNAME is not pointed to FastDog (or points elsewhere), the attachment stays `pending`:

- **No tunnel binding**: Hostname is not added to `tunnel_hosts`
- **No credential issued**: Agent cannot register for that hostname
- **No TLS certificate**: Caddy does not attempt HTTP-01 challenge
- **Public traffic rejected**: Edge returns 404/503 for unverified hostnames

This prevents accidentally serving wrong content or issuing certificates for uncontrolled domains.

## DNS verification

Verification uses DNS lookup to confirm ownership:

```javascript
// Acceptable verification patterns:
// 1. CNAME to attach.fastdognetworks.com
// 2. CNAME chain ending at attach.fastdognetworks.com or edge.fastdognetworks.com
// 3. A record matching FastDog edge IP (for ALIAS/ANAME)

verifyHost({ hostname: 'app.customer.com' })
// → { verified: true, method: 'cname', target: 'attach.fastdognetworks.com' }
// → { verified: false, error: 'cname_not_found', found: 'other.cdn.com' }
```

### Verification requirements

- CNAME must resolve to `attach.fastdognetworks.com` or `edge.fastdognetworks.com`
- Or A record must resolve to FastDog edge IP
- TTL propagation: recommend waiting 5-10 minutes after DNS change
- Re-verification allowed (idempotent)

## TLS via Caddy HTTP-01

Attached hostnames use the same Caddy HTTP-01 pattern as existing FastDog hosts (`lease.fastdognetworks.com`, `whoami.fastdognetworks.com`).

### Phase 1: Operator-assisted Caddy config

Full Caddy auto-provision is risky in Phase 1 (requires Caddy API access, reload privileges). Instead:

1. **API/CLI returns Caddy block snippet** for the attached hostname
2. **Operator adds block to Caddyfile** on the edge server
3. **Operator reloads Caddy** (`systemctl reload caddy`)
4. Caddy performs HTTP-01 challenge and obtains certificate

Example Caddy block returned by `attach-host --verified`:

```caddy
app.customer.com {
    reverse_proxy localhost:8787
    log {
        output file /var/log/caddy/app.customer.com.log
    }
}
```

### Future: Caddy API auto-provision

When safe to implement:
- Use Caddy admin API to add routes dynamically
- Trigger on verification success
- Require `CADDY_ADMIN_URL` environment variable

## Security model

### Hostname ownership

- **DNS verification** proves customer controls the hostname (can set CNAME)
- Verification must pass before any credential or tunnel binding
- Re-verification recommended if DNS changes

### Token scoping

- Agent credentials are scoped to the attached hostname
- Token only works for `registerAgent({ hostname: 'app.customer.com', ... })`
- Different hostnames require different credentials

### Fail-closed

- Unverified attachments cannot serve traffic
- Expired/removed CNAME: attachment returns to `pending` (future: periodic re-check)

## API reference

All routes require `x-fastdog-token` header.

### POST /_fastdog/onboard/attach-host

Create or update a hostname attachment.

```json
// Request
{
  "hostname": "app.customer.com"
}

// Response (201)
{
  "hostname": "app.customer.com",
  "status": "pending",
  "created_at": "2026-10-06T12:00:00.000Z",
  "cname_target": "attach.fastdognetworks.com",
  "cname_instructions": "Add this CNAME record at your registrar:\n\napp.customer.com.  300  IN  CNAME  attach.fastdognetworks.com.\n\nThen run: npm run onboard -- verify-host app.customer.com"
}
```

### POST /_fastdog/onboard/verify-host

Verify DNS for an attached hostname.

```json
// Request
{
  "hostname": "app.customer.com"
}

// Response (200) — success
{
  "hostname": "app.customer.com",
  "status": "active",
  "verified": true,
  "method": "cname",
  "target": "attach.fastdognetworks.com",
  "credential": {
    "id": "...",
    "token": "...",
    "agent_env": { "AGENT_TOKEN": "...", "AGENT_HOSTNAME": "app.customer.com" }
  },
  "caddy_block": "app.customer.com {\n    reverse_proxy localhost:8787\n}"
}

// Response (200) — failed verification
{
  "hostname": "app.customer.com",
  "status": "pending",
  "verified": false,
  "error": "cname_not_found",
  "found": "other.cdn.com",
  "cname_target": "attach.fastdognetworks.com",
  "cname_instructions": "..."
}
```

### GET /_fastdog/onboard/attached-hosts

List all attached hostnames.

```json
// Response
{
  "hosts": [
    {
      "hostname": "app.customer.com",
      "status": "active",
      "created_at": "2026-10-06T12:00:00.000Z",
      "verified_at": "2026-10-06T12:05:00.000Z"
    }
  ]
}
```

### DELETE /_fastdog/onboard/attached-hosts/:hostname

Detach a hostname.

```json
// Response (200)
{
  "hostname": "app.customer.com",
  "detached": true
}
```

## CLI reference

```sh
# Attach a hostname (pending, returns CNAME instructions)
npm run onboard -- attach-host app.customer.com

# Verify DNS and activate (issues credential, returns Caddy block)
npm run onboard -- verify-host app.customer.com

# List attached hostnames
npm run onboard -- list-attached-hosts

# Detach a hostname
npm run onboard -- detach-host app.customer.com
```

## Operator UI flow

The operator dashboard includes a "Quick attach" panel as the **default first action**:

1. **Enter hostname** (e.g., `app.customer.com`)
2. **Click Attach** → shows CNAME instructions with copy button
3. **Wait for customer** to add CNAME at their registrar
4. **Click Verify** → runs DNS verification
5. **On success**: shows credential (copy once), Caddy block (copy), status updates to Active
6. **Caddy setup**: operator copies block to Caddyfile, reloads Caddy

## Comparison to NS cut

| Feature | Hostname attach | NS cut |
| --- | --- | --- |
| Setup time | Minutes | Hours to days |
| DNS control | Customer keeps | FastDog authoritative |
| DNSSEC | Customer's choice | FastDog must configure |
| MX/TXT/CAA records | Customer manages | FastDog manages |
| Multiple hostnames | Attach each one | Zone covers all |
| TLS | HTTP-01 per hostname | HTTP-01 per hostname |
| Best for | Quick start, single service | Full domain control |

## Existing FastDog zone dogfood

`lease.fastdognetworks.com` remains as FastDog-zone dogfood (A record + tunnel_hosts already live). It uses the NS-cut path because the zone is authoritative at FastDog nameservers. This is separate from the hostname-attach flow.

## Related docs

- [Onboarding (updated)](ONBOARDING.md) — CNAME/attach is now the default stranger path
- [NS cut runbook](../deploy/NS_CUT.md) — advanced authoritative zone path
- [Hostname attach runbook](../deploy/HOSTNAME_ATTACH.md) — operator deployment steps
