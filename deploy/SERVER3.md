# Server3 operator runbook (LAN, engineering owned)

Repository: `~/projects/fastdog-edge`. Keep `.env` and `data/` local. This runbook is for the LAN branch demo. Leave the running master edge/agent alone; no restart is needed for `npm test`. Do not touch prod1, PoP CoreDNS, or registrar NS settings. Keep `COREDNS_SYNC_ENABLED=false` (the default).

## Process paths

For an isolated local demo, use a separate checkout/config and free ports. The scripts below manage a script-started edge in the current checkout; inspect the listener and PID before using them on server3. Do not run `stop-edge.sh` or `restart-edge.sh` against the live master process for a branch review.

```sh
cd ~/projects/fastdog-edge
./deploy/start-edge.sh
# later, only for an edge started by this checkout:
./deploy/stop-edge.sh
# restart only that checkout's script-managed edge, when needed:
./deploy/restart-edge.sh
```

Start a local agent with `npm run agent` in its own terminal after issuing its credential. If a separate systemd-managed deployment is intentionally in use, inspect `systemctl status fastdog-edge fastdog-agent` first. Use `sudo systemctl start fastdog-edge`, `sudo systemctl stop fastdog-edge`, or `sudo systemctl restart fastdog-edge` only for that deployment; substitute `fastdog-agent` for agent operations. The scripts above are for script-managed processes. The unit files do not set a WAN operator bind; `OPERATOR_BIND` must be `127.0.0.1` or `::1`. **Do not `systemctl enable` edge or agent for WAN.**

Confirm the operator listener is loopback only:

```sh
ss -tlnp | rg ':8788|:8787'
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8788/
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8788/_fastdog/operator/metrics
curl -sS http://127.0.0.1:8787/health
```

`:8788` must show `127.0.0.1` or `[::1]` only; the operator homepage should return `200` and unauthenticated metrics `401`. Stop the demo if the operator listener is on a non-loopback address. `OPERATOR_BIND` rejects other addresses at startup. Port `8787` is the edge and may listen on the configured LAN address.

From a LAN client, forward both ports:

```sh
ssh -L 8788:127.0.0.1:8788 -L 8787:127.0.0.1:8787 server3
```

Open <http://127.0.0.1:8788/> for the [operator dashboard](../docs/operator-ui.md) and <http://127.0.0.1:8787/status> for edge status. Follow the [LAN onboarding flow](../docs/ONBOARDING.md#lan-try-server3). Direct `dig @NS1_IP` and `@NS2_IP` with `+norecurse` is DNS verification only; a failed check blocks a DNS-ready claim. **Do not flip registrar NS.**
