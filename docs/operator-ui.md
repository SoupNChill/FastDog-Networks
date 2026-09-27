# Operator dashboard and NS-cut checklist

The edge process also starts an operator dashboard on `127.0.0.1:8788` by default. `OPERATOR_BIND` accepts only `127.0.0.1` or `::1`; startup fails for a non-loopback value. Keep `EDGE_PORT` on the intended LAN interface and do not expose the operator port on WAN.

From a laptop, create a tunnel to server3:

```sh
ssh -L 8788:127.0.0.1:8788 -L 8787:127.0.0.1:8787 server3
```

Open <http://127.0.0.1:8788/>. Enter `AGENT_TOKEN` to load the dashboard and mint invites. The token stays in the browser tab and is sent in the `x-fastdog-token` header. Invite codes are shown only on creation; the operator invite list omits codes. The dashboard shows zones, invite capacity, connected tunnels, the latest `paid_test` timestamp, local edge health, and the public status summary. Status and Stripe **TEST MODE** Checkout links use edge port 8787, which is why the example forwards both ports.

The operator JSON endpoint is `GET /_fastdog/operator/metrics` on port 8788; it requires the same token. The `lastPaidTest` value comes from the latest `paid_test` account update. It is a paid test signal, not a complete webhook audit trail. Both the operator UI and its API are loopback-only.

Before a future registrar NS cut, run on server3:

```sh
npm run ns-cut-checklist
# or: bash scripts/ns-cut-checklist.sh fastdognetworks.com
```

The script queries `157.230.57.32` and `2.29.58.90` directly for MX, SPF, DMARC, DKIM, and SOA serial. It prints `SAFE_TO_FLIP=yes` only if both PoPs agree and the required mail records are present. DNS failures or missing `dig` produce `SAFE_TO_FLIP=no`. This is a checklist only; it does not change registrar nameservers. Keep the registrar NS flip on hold.
