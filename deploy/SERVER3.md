# Server3 operator runbook (LAN, engineering owned)

Repository: `~/projects/fastdog-edge`. Keep `.env` and `data/` local. Do not touch prod1 or any registrar NS settings. Keep `COREDNS_SYNC_ENABLED=false` (the default).

```sh
cd ~/projects/fastdog-edge
./deploy/start-edge.sh
./deploy/stop-edge.sh
./deploy/restart-edge.sh
```

Start a local agent with `node agent/index.js` (or review `deploy/fastdog-agent.service` if managing it separately). The edge unit is `deploy/fastdog-edge.service`; do **not** enable either systemd unit for WAN access.

Confirm the operator listener is loopback only:

```sh
ss -tlnp | rg ':8788|:8787'
curl -sS http://127.0.0.1:8787/health
```

`:8788` must show `127.0.0.1` or `[::1]` only. `OPERATOR_BIND` rejects other addresses at startup. Forward both ports from a LAN client with `ssh -L 8788:127.0.0.1:8788 -L 8787:127.0.0.1:8787 server3`. See [operator-ui.md](../docs/operator-ui.md) for the dashboard and checklist. Keep registrar NS on HOLD.
