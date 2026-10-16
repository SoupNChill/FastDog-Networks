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
    issue(tenantId, hostname) {
      const records = all();
      const mine = records.filter((t) => t.tenant_id === tenantId && t.hostname === hostname && live(t))
        .sort((a, b) => Date.parse(a.created_at) - Date.parse(b.created_at));
      for (const old of mine.slice(0, Math.max(0, mine.length - MAX_LIVE_PER_HOST + 1))) old.revoked_at = new Date(now()).toISOString();
      const secret = `${PREFIX}${randomBytes(32).toString('base64url')}`;
      const record = { id: randomUUID(), digest: digest(secret), tenant_id: tenantId, hostname,
        scope: 'connect', created_at: new Date(now()).toISOString(),
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
    'Send it as the header "Authorization: Bearer <token>". Do not put it in a URL, a log, a commit or a chat with anyone else.',
    `1. GET ${portalOrigin}/api/connect/v1/hostname shows whether the server is connected.`,
    `2. POST ${portalOrigin}/api/connect/v1/command with JSON {"origin": "http://127.0.0.1:<port my app listens on>", "platform": "linux"} (or "docker") returns the connect command once. Getting it replaces any earlier connection for this website.`,
    '3. Ask me which port my app uses, then run the command on the server where the app runs (it uses sudo; I type my own password).',
    '4. Poll step 1 every 10 seconds until agent.connected is true, then open the website to confirm it loads over HTTPS.',
  ].filter((line) => line !== null).join('\n');
}
