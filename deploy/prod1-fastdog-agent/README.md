# prod1 Fastdog agent (template)

Copy this directory to `/home/barbra/fastdog-agent` on prod1.

```sh
# from server3 or Mamasota:
scp -r deploy/prod1-fastdog-agent/* barbra@192.168.200.7:/home/barbra/fastdog-agent/
# then copy agent source:
scp ../../agent/index.js barbra@192.168.200.7:/home/barbra/fastdog-agent/app/index.js
ssh barbra@prod1 'cd /home/barbra/fastdog-agent && docker compose up -d'
```

Uses `external: true` network `summitlease-prod_default`. Never edit summitlease-prod compose.
`AGENT_TOKEN` must match edge `.env` (local-dev token only; rotate before shared use).