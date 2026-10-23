// Short-lived "connect tokens" for the 'Copy prompt for your AI assistant' block.
// Scope: one tenant, one hostname, connect-only (read that hostname's connection status and get
// its connect command once). Expires after an hour, revocable, stored only as a SHA-256 digest.
import { randomBytes, randomUUID } from 'node:crypto';
import { dockerRun } from './connect-command.js';
import { digest } from './tokens.js';

export const CONNECT_TOKEN_TTL_MS = 3600000;
const PREFIX = 'fdct_';
const MAX_LIVE_PER_HOST = 3;

export function createConnectTokens(store, now) {
  const all = () => store.read('connect_tokens', []).filter((t) => Date.parse(t.expires_at) > now() - 86400000);
  const live = (t) => !t.revoked_at && Date.parse(t.expires_at) > now();
  return {
    issue(tenantId, hostname, issuer = {}) {
      const records = all();
      const mine = records.filter((t) => t.tenant_id === tenantId && t.hostname === hostname && live(t))
        .sort((a, b) => Date.parse(a.created_at) - Date.parse(b.created_at));
      for (const old of mine.slice(0, Math.max(0, mine.length - MAX_LIVE_PER_HOST + 1))) old.revoked_at = new Date(now()).toISOString();
      const secret = `${PREFIX}${randomBytes(32).toString('base64url')}`;
      const record = { id: randomUUID(), digest: digest(secret), tenant_id: tenantId, hostname,
        scope: 'connect', user_id: issuer.user_id ?? null, auth_version: issuer.auth_version ?? null,
        claim_created_at: typeof issuer.claim_created_at === 'string' ? issuer.claim_created_at : null, created_at: new Date(now()).toISOString(),
        expires_at: new Date(now() + CONNECT_TOKEN_TTL_MS).toISOString(), revoked_at: null, command_issued_at: null };
      records.push(record);
      store.write('connect_tokens', records);
      return { token: secret, id: record.id, expires_at: record.expires_at };
    },
    // Returns the live record for a bearer secret, or null. Never throws on malformed input.
    find(secret) {
      if (typeof secret !== 'string' || !secret.startsWith(PREFIX) || secret.length > 100) return null;
      const hash = digest(secret);
      return all().find((t) => t.digest === hash && live(t)) ?? null;
    },
    markCommand(id) {
      const records = all();
      const record = records.find((t) => t.id === id);
      if (!record || record.command_issued_at) return false;
      record.command_issued_at = new Date(now()).toISOString();
      store.write('connect_tokens', records);
      return true;
    },
    unmarkCommand(id) {
      const records = all();
      const record = records.find((t) => t.id === id);
      if (record) { record.command_issued_at = null; store.write('connect_tokens', records); }
    },
    list(tenantId, hostname) {
      return all().filter((t) => t.tenant_id === tenantId && t.hostname === hostname && live(t))
        .map((t) => ({ id: t.id, created_at: t.created_at, expires_at: t.expires_at, command_issued: Boolean(t.command_issued_at) }));
    },
    revokeAll(tenantId, hostname) {
      const records = all();
      let count = 0;
      for (const t of records) if (t.tenant_id === tenantId && t.hostname === hostname && live(t)) { t.revoked_at = new Date(now()).toISOString(); count++; }
      store.write('connect_tokens', records);
      return count;
    },
    // Every live token of a tenant (suspension).
    revokeTenant(tenantId) {
      const records = all();
      let count = 0;
      for (const t of records) if (t.tenant_id === tenantId && live(t)) { t.revoked_at = new Date(now()).toISOString(); count++; }
      if (count) store.write('connect_tokens', records);
      return count;
    },
    countLive: (tenantId) => all().filter((t) => t.tenant_id === tenantId && live(t)).length,
  };
}

export function assistantPrompt({ hostname, token, expiresAt, portalOrigin, docsUrl }) {
  return [
    `I'm connecting my website ${hostname} to FastDog Networks. Please help me finish the setup on my server.`,
    docsUrl ? `Read the setup guide first: ${docsUrl.replace(/\/$/, '')}/llms.txt` : null,
    `EARLY, before any DNS work, list in one message (a) curl calls to ${portalOrigin} and (b) the exact docker run line with the chosen absolute ENV_FILE path. I do the one-time header-file setup at the start. Every API call, including the env-file fetch and status polling, is plain curl of the same shape, so if I allow curl I approve those calls once/up front. After DNS, the ONLY new command needing approval is the single docker run (plus one docker rm -f only on a reconnect name conflict), nothing chained. Template: ${dockerRun(hostname)}. GET hostname supplies docker {container_name, image, run}. I must ALREADY have docker access without sudo; docker group access is root-equivalent, never add anyone to it. If I lack access, use platform "linux", the systemd installer I run myself.`,
    '',
    `Connect token (works only for ${hostname}, only for connecting, expires ${expiresAt}):`,
    token,
    '',
    'Send it as the header "Authorization: Bearer <token>". Do not put it in a URL, a log, a commit or a chat with anyone else. Never use curl -v or --trace with it (they print the Authorization header). Shell rules often refuse commands that expand a secret, so do not write the header file yourself. At the start, ask me to run this one-time command (or to approve it once), and do not retry variations. It starts with a space so most shells keep it out of history (HISTCONTROL=ignorespace); otherwise I can delete it from my history: \' mkdir -p ~/.config/fastdog && (umask 077; printf \'Authorization: Bearer %s\\n\' \'' + token + `' > ~/.config/fastdog/${hostname}.token.header)`,
    `Then use curl -H @/absolute/path/${hostname}.token.header, with the absolute path of my home directory (your HOME may differ from mine). Never echo or cat it. The token expires in an hour, so right after connecting, tell me I can delete ~/.config/fastdog/${hostname}.token.header.`,
    `1. GET ${portalOrigin}/api/connect/v1/hostname shows whether the server is connected.`,
    `3. Use the port I already gave you; only ask which port if missing. After DNS verification, fetch the env file with ONE curl run under umask 077 so the new file is private (curl's --create-file-mode does not apply to a local -o file), using a new unused absolute path in my private config directory: (umask 077; curl -sS -w '%{http_code}\\n' -X POST -H @/absolute/path/${hostname}.token.header -H 'Content-Type: application/json' -d '{"origin":"http://127.0.0.1:PORT","platform":"docker","format":"env"}' -o /absolute/path/${hostname}.agent.env ${portalOrigin}/api/connect/v1/command). If your allowlist accepts only a plain curl, run it without the umask and ask me to approve chmod 600 on the file before docker run. If you are not on the server, run these on the server; never move the env file through chat or logs. PORT is the app port I gave. Prefer ${hostname}.agent.env in ~/.config/fastdog; if it already exists, pick a different new name such as ${hostname}.agent-2.env rather than overwrite it. umask only applies to a new file. If the printed code is not 200, the file holds a JSON error without secrets and may be read; stop on transport failure. If 200 never read, print, cat or copy the file. Issuance rotates the key (3 a day at most), single use per token. Default format "json" retains the copy-paste human command.`,
    '4. Use the exact docker.run and docker.container_name from the API, never a copied example name. Replace ENV_FILE in docker.run with the absolute path you chose and run exactly that single command, nothing chained. No docker info / docker pull / docker ps / rm around it; docker run pulls the pinned image itself. If a name conflict occurs, ask me to approve docker rm -f with the exact docker.container_name once, then rerun the same docker run with the same env file; do not request a new command. If permission denied on the Docker socket, stop and offer the linux installer path. Host networking reaches 127.0.0.1; on Docker Desktop use host.docker.internal.',
    '5. Poll step 1 with plain curl every 15 seconds until agent.connected is true and agent.origin_reachable is not false, then open HTTPS; stop and tell me after about 10 minutes. This fdct endpoint has no live/certificate field; with an API key poll status until live true. Never docker inspect, ps or /proc/*/cmdline; never echo the token. Do not retry issuance for certificate_missing.',
    `6. As soon as agent.connected is true, immediately give me the exact one-line command to run myself: rm -f /home/USER/.config/fastdog/${hostname}.agent.env (substitute the absolute path you used). It holds the agent private key; the running container does not need it, and restart does not need it either because Docker stored the env at create time. Also give this cleanup command after failure, and tell me to delete the header file if no longer needed. Do not delete them yourself: that would need a second approval.`,
    'Why this design / tradeoff: the agent token never appears in any command line, shell history or process args: curl writes it straight to a 0600 file; Docker reads --env-file client-side. The cost is that the 0600 agent-key file stays on disk until I delete it. Like any Docker env var it is visible to anyone with docker access via docker inspect. Each new connect command rotates the key, making a leftover file useless after a later reconnect, and the key can be revoked. -e AGENT_TOKEN=... was rejected because it puts the key in the command line and history. A future option is a single-use bootstrap code in the env file that the agent exchanges for its key (needs a new agent image), making the leftover file harmless.',
  ].filter((line) => line !== null).join('\n');
}
