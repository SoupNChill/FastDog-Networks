# Domain search

A separate, read-only domain availability and one-year USD pricing service for
`/domains`. Requires Node >= 20, with no npm dependencies. Credentials stay in
this process, separate from the edge. Only domain LOOKUP and GET_PRICE operations
are allowed; this service cannot register, renew, transfer, or modify domains.

From this directory:

```sh
node src/server.js
node --test test/
```

`npm start` and `npm test` are equivalent. Tests use injected mocks and local HTTP
only; they never contact the upstream. Starting the service alone makes no
upstream calls. Searches need credentials; unavailable upstreams return a generic
degraded result. Do not use live searches for verification.

Environment variable names (never put credentials into source or logs):

- `REGISTRAR_USERNAME`, `REGISTRAR_API_KEY`
- `OPENSRS_USERNAME`, `OPENSRS_API_KEY` (legacy fallbacks)
- `REGISTRAR_HOST` (optional upstream host override)
- `DOMAIN_SEARCH_PORT`, `DOMAIN_SEARCH_BIND`
- `TRUST_PROXY`

The default listener is `127.0.0.1:8791`. Trust of the first forwarded IP is disabled
by default; enable `TRUST_PROXY` only behind the local proxy, with direct access
blocked and the proxy replacing untrusted forwarded headers.

`GET /api/domains/search?q=example.com` returns the normalized query and at most
five names, with status, premium flag, registration/renewal prices, and currency.
A bare label uses `.com`; the supported endings are `.com`, `.net`, `.org`, `.dev`,
`.app`, `.io`, and `.co`. Invalid input is 400; rate limiting is 429 with
`Retry-After`. `GET /api/domains/health` returns `{ "ok": true }` without contacting
the upstream. Other methods are 405 and unknown paths are 404.

Results cache per domain for three hours. `cached` is true only when every result
came from the cache. Limits are ten search requests per IP per ten minutes and
300 upstream calls per UTC day (each lookup and each price request counts,
including failures). The budget is reserved before each call. Concurrent searches
share pending per-domain work. A cap reached midway through pricing preserves the
known availability and prices, leaving missing prices null and remaining uncached
names unknown. Errors become unknown results; incomplete/error results are not
cached. Cached entries remain usable when the cap is exhausted. State is in
memory and resets on restart: deploy one service instance for these limits.

Responses contain only public fields and generic errors. Every response uses
`no-store` and `nosniff`. Logs include only a known route (or `unknown`), HTTP
status, elapsed milliseconds, and the client network truncated to /24 or /48.

## Deployment sketch (not deployed by this PR)

Install the code at `/opt/fastdog/domain-search` or adjust the working directory in
`deploy/domain-search.service`. Create the `fastdog` service user. Store the
service environment at `/etc/fastdog/domain-search.env`, owned by `root:root` with
mode `0600`; systemd reads it before dropping privileges. Never copy credentials
into the unit. The supplied unit is a sketch and is not installed or enabled.
Its main settings are:

```ini
[Service]
User=fastdog
WorkingDirectory=/opt/fastdog/domain-search
EnvironmentFile=/etc/fastdog/domain-search.env
ExecStart=/usr/bin/node src/server.js
NoNewPrivileges=true
MemoryMax=64M
Nice=10
```

At deployment, add this route inside the apex Caddy site, before its existing
fallback handler. Keep the `/api/domains` prefix (do not use `handle_path`):

```caddyfile
handle /api/domains/* {
    reverse_proxy 127.0.0.1:8791 {
        header_up X-Forwarded-For {remote_host}
    }
}
```

This assumes Caddy receives clients directly; if another proxy precedes Caddy,
configure its trusted proxies and client IP policy before enabling forwarded-IP
trust here. No Caddy configuration or running service is changed by this PR.
