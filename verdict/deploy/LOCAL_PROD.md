# Deploy Verdict to local prod (LAN)

Use your on-network prod machine. Do **not** open port 8080 to the public internet until HTTPS and auth are reviewed.

## Prerequisites

- Ubuntu (or similar) with Node 18+
- SSH access from Mamasota (or your admin desktop)
- Same LAN as `server3` / your Cloudflare alternative customers

## Steps

1. Copy the app (exclude secrets and junk):

```sh
rsync -a --exclude node_modules --exclude data --exclude .env --exclude '*.log' \
  mranderson@server3:~/projects/verdict/ ~/projects/verdict/
```

Or `git clone` / `git pull` once this tree has a remote.

2. On prod:

```sh
cd ~/projects/verdict
npm ci
cp .env.example .env   # edit PORT / rate limits / TypeSafe key if any
mkdir -p data
chmod 700 data
npm test
```

3. Bootstrap one owner key (save plaintext once):

```sh
node src/server.js &   # temporary, or use systemd below
curl -sS http://127.0.0.1:8080/v1/keys -H 'Content-Type: application/json' -d '{"name":"prod"}'
```

4. Install systemd (edit `User=` and paths in `deploy/verdict.service` first):

```sh
sudo cp deploy/verdict.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now verdict
curl -sS http://127.0.0.1:8080/health
```

5. Front with Caddy or Nginx + TLS on a private hostname (or Tailscale) when ready. Keep `8080` LAN-only or localhost-only behind the proxy.

## Do not

- Publish `:8080` on a WAN interface or cloud security group
- Commit `.env`, `data/keys.json`, or plaintext API keys
- Point Stripe/webhooks here until branding and payment work is done

## Smoke

```sh
curl -sS http://127.0.0.1:8080/health
curl -sS http://127.0.0.1:8080/openapi.json | head
curl -sS http://127.0.0.1:8080/v1/decide \
  -H "Authorization: Bearer $VERDICT_API_KEY" -H 'Content-Type: application/json' \
  -d '{"path":"/login","signals":["headless"]}'
```
