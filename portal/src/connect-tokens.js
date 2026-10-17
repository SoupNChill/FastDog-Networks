// Short-lived "connect tokens" for the 'Copy prompt for your AI assistant' block.
// Scope: one tenant, one hostname, connect-only (read that hostname's connection status and get
// its connect command once). Expires after an hour, revocable, stored only as a SHA-256 digest.
import { randomBytes, randomUUID } from 'node:crypto';
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
  };
}

export function assistantPrompt({ hostname, token, expiresAt, portalOrigin, docsUrl }) {
  return [
    `I'm connecting my website ${hostname} to FastDog Networks. Please help me finish the setup on my server.`,
    docsUrl ? `Read the setup guide first: ${docsUrl.replace(/\/$/, '')}/llms.txt` : null,
    '',
    `Connect token (works only for ${hostname}, only for connecting, expires ${expiresAt}):`,
    token,
    '',
    'Send it as the header "Authorization: Bearer <token>". Do not put it in a URL, a log, a commit or a chat with anyone else. Never use curl -v or --trace with it (they print the Authorization header). Shell rules often refuse commands that expand a secret, so do not write the header file yourself. At the start, ask me to run this one-time command (or to approve it once), and do not retry variations. It starts with a space so most shells keep it out of history (HISTCONTROL=ignorespace); otherwise I can delete it from my history: \' mkdir -p ~/.config/fastdog && (umask 077; printf \'Authorization: Bearer %s\\n\' \'' + token + `' > ~/.config/fastdog/${hostname}.token.header)`,
    `Then use curl -H @/absolute/path/${hostname}.token.header, with the absolute path of my home directory (your HOME may differ from mine). Never echo or cat it. The token expires in an hour, so right after connecting, tell me I can delete ~/.config/fastdog/${hostname}.token.header.`,
    `1. GET ${portalOrigin}/api/connect/v1/hostname shows whether the server is connected.`,
    '2. Docker group access is root-equivalent. Use Docker only if I ALREADY have docker access without sudo (docker info works without sudo); never add anyone to the docker group yourself. Otherwise tell me to use rootless Docker, or the root systemd installer (platform "linux"), which I run myself with sudo.',
    `3. Use the port I already gave you, and only ask which port my app uses if I did not. POST ${portalOrigin}/api/connect/v1/command with JSON {"origin": "http://127.0.0.1:<port>", "platform": "docker"} returns the connect command once (use "linux" only for the systemd installer); save the response with curl --create-file-mode 0600 -o /absolute/path/fastdog-connect.json (no umask or chmod; needs curl 7.75 or newer, with older curl run umask 077 first). Getting it replaces any earlier connection for this website (3 a day at most).`,
    '4. The Docker command contains the agent token. Never print the command, the response file or the env file it writes, never run docker inspect on the agent container, never use ps or read /proc/*/cmdline, and never echo the token. Write the command from the response to a 0600 file (for example /absolute/path/fastdog-run.sh) without displaying it, e.g. (umask 077; python3 -c \'import json;print(json.load(open("/absolute/path/fastdog-connect.json"))["command"])\' > /absolute/path/fastdog-run.sh), run it with sh /absolute/path/fastdog-run.sh, then delete the file, the response file and the file named by the response env_file field (never a glob, never a copied example) after docker run, whether it succeeded or failed. Verify with docker ps --filter name=fastdog-agent. It uses host networking, so 127.0.0.1 reaches my app (on Docker Desktop use host.docker.internal instead). Running it again replaces the old agent.',
    '5. Poll step 1 every 15 seconds until agent.connected is true (stop and tell me after about 10 minutes). Then open the website over HTTPS. If HTTPS is not ready (certificate_missing), tell me; do not retry the command.',
  ].filter((line) => line !== null).join('\n');
}
