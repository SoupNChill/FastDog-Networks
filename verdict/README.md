# Verdict

Gray-zone threat decision API: `allow`, `challenge`, or `block` with confidence and reason. Node 18+.

## Setup

```sh
npm install
npm test
npm start
```

Server listens on port 8080 by default. `npm run dev` runs with Node's watch mode. Visit `/` for a quick start or `/openapi.json` for the API schema.

## API keys and decisions

When `data/keys.json` has no keys, bootstrap the first key without a bearer token:

```sh
curl -sS http://localhost:8080/v1/keys -H 'Content-Type: application/json' -d '{"name":"main"}'
```

Save the returned `key` securely; it is shown once. Later calls to `/v1/keys` require an existing key. All other `/v1/*` calls require `Authorization: Bearer <key>`.

```sh
export VERDICT_API_KEY='paste-key-here'
curl -sS http://localhost:8080/v1/decide \
  -H "Authorization: Bearer $VERDICT_API_KEY" -H 'Content-Type: application/json' \
  -d '{"ip":"203.0.113.8","asn":64500,"ja3":"sample","path":"/login","method":"POST","ua":"sample browser","headers":{"accept":"*/*"},"account_age_hours":0.5,"prior_score":0.2,"signals":["headless"],"notes":"new session"}'
curl -sS http://localhost:8080/v1/usage -H "Authorization: Bearer $VERDICT_API_KEY"
```

`/v1/decide` also accepts the older `{ "state": {...} }` or `{ "state": "..." }` shape. Decisions contain `action`, `confidence`, `reason`, `engine`, and `request_id`. Invalid bodies return `400` with Zod details. Decide is rate-limited per API key (default 60 requests / 60s; see env below). Usage counters persist under `data/usage.json` across restarts. Key records persist under `data/` as SHA-256 hashes; protect the file and use HTTPS outside localhost.

## Configuration

- `PORT`: listen port, default `8080`.
- `VERDICT_KEY_FILE`: key store path, default `data/keys.json`.
- `VERDICT_USAGE_FILE`: usage store path, default `data/usage.json`.
- `VERDICT_RATE_LIMIT_WINDOW_MS`: decide window, default `60000`.
- `VERDICT_RATE_LIMIT_MAX`: max decide calls per key per window, default `60`.
- `TYPESAFE_API_KEY`: optional Jev key. Leave unset to use the local heuristic and avoid external calls.
- `TYPESAFE_BASE_URL`: default `https://api.typesafe.ai`.

With a TypeSafe key, Verdict calls System One Choice at `/v1/systemone`. If the request fails or returns an unexpected response, it uses the local heuristic. The Jev integration is a stub pending validation against a real account and response. Billing coming soon.

## systemd

The unit assumes this checkout path and user `mranderson`; edit it if needed. Store environment variables in `.env` and keep the file private. To enable after reviewing the unit:

```sh
sudo cp deploy/verdict.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now verdict
```

## Local prod

See [deploy/LOCAL_PROD.md](deploy/LOCAL_PROD.md) for copying this build onto another LAN machine behind TLS.
