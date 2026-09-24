# Fastdog public PoP status

`GET /status` serves a self-contained HTML page for edge HTTPS, ns1 DNS, and ns2 DNS. `GET /status.json` serves the same result as JSON. This is a lightweight view of the public PoPs; it is not a full incident history.

## How checks work

- Edge: HTTP GET to `STATUS_EDGE_URL` (default `https://edge.fastdognetworks.com/health`). A 404 or 405 from `/health` triggers a GET to `/` and shows yellow if that succeeds.
- DNS: `dig` asks each configured nameserver IP for the zone SOA. A NOERROR answer with the authoritative (`aa`) flag is green.
- All three checks run concurrently with short timeouts. Results are written to `$DATA_DIR/status.json`. Concurrent page requests share one probe run.
- Page requests use the saved result until it is as old as `STATUS_INTERVAL_MS`; then they refresh before responding. `?refresh=1` forces a fresh check. A periodic check runs at the same interval while the server is running, unless the interval is zero.
- An optional webhook receives JSON when a check changes from green or yellow to red. It is best effort; failures are logged. The first observation has no prior status and does not alert.

## Colors

| Color | Meaning |
| --- | --- |
| Green | Edge responds 2xx within 1.5 seconds; DNS returns an authoritative SOA. |
| Yellow | Edge responds slowly, returns a non-2xx status, or only `/` works; DNS answers without `aa`. |
| Red | Edge cannot be reached or times out; DNS fails, times out, or has no SOA answer. |

Overall status is red if any check is red, yellow if none are red and any is yellow, and green otherwise. The page shows the UTC ISO time of the last completed check, latency, and result detail.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `STATUS_EDGE_URL` | `https://edge.fastdognetworks.com/health` | Edge probe URL |
| `STATUS_ZONE` | `fastdognetworks.com` | Zone for SOA queries |
| `NS1_IP` / `NS2_IP` | `157.230.57.32` / `2.29.58.90` | DNS probe targets |
| `STATUS_PROBE_TIMEOUT_MS` | `3000` | Timeout per HTTP or DNS probe |
| `STATUS_INTERVAL_MS` | `60000` | Cache and periodic check interval; `0` disables periodic checks and probes on every request |
| `STATUS_ALERT_WEBHOOK_URL` | unset | Optional POST target for red transitions |
| `DATA_DIR` | `data` | Directory for `status.json` |

The server needs `dig` installed for DNS checks. No external monitoring service is required.

## Try on a LAN

Run `npm start`, then open `http://<edge-lan-ip>:8787/status`. For an immediate new check, open `/status?refresh=1`; use `/status.json` for the saved JSON. To test against a local edge while keeping public DNS targets, set `STATUS_EDGE_URL=http://127.0.0.1:8787/health` before starting the server. The status page can still show red DNS rows if the PoPs are unreachable from that LAN.
