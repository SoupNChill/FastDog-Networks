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
    'Send it as the header "Authorization: Bearer <token>". Do not put it in a URL, a log, a commit or a chat with anyone else. Shell rules often refuse commands that expand a secret, so do not write the header file yourself. At the start, ask me to run this one-time command (or to approve it once), and do not retry variations: mkdir -p ~/.config/fastdog && (umask 077; printf \'Authorization: Bearer %s\\n\' \'' + token + '\' > ~/.config/fastdog/auth.header). Then use curl -H @/absolute/path/auth.header, with the absolute path of my home directory (your HOME may differ from mine). Never echo or cat it.',
    `1. GET ${portalOrigin}/api/connect/v1/hostname shows whether the server is connected.`,
    `2. Use the port I already gave you, and only ask which port my app uses if I did not. POST ${portalOrigin}/api/connect/v1/command with JSON {"origin": "http://127.0.0.1:<port>", "platform": "linux"} (or "docker") returns the connect command once; save the response with curl --create-file-mode 0600 -o /absolute/path/fastdog-connect.json (no umask or chmod), then give me the one-line command to run it and delete the file. Getting it replaces any earlier connection for this website (3 a day at most).`,
    '3. Do not run the command or read the token inside it: it uses sudo and I type my own password. Tell me the one-line way to run it, then delete the file.',
    '4. Poll step 1 every 15 seconds until agent.connected is true (stop and tell me after about 10 minutes). Then open the website over HTTPS. If HTTPS is not ready (certificate_missing), tell me; do not retry the command.',
  ].filter((line) => line !== null).join('\n');
}
