// Operator kill switch: node portal/bin/tenant.js suspend|resume|release <tenant_id|email> --reason "<text>".
// Writes only suspensions.json and admin_audit.json; the running server reads suspensions.json and ends
// sessions, API keys and connect tokens on their next use. Resume keeps the suspension's revocation
// epoch, so credentials issued before it never come back. Release (only after resume) frees the
// tenant's administratively reserved hostnames on the edge. Never prints the portal key or any token.
import { pathToFileURL } from 'node:url';
import { createStore, emptyAccounts } from '../src/store.js';
import { createSuspensions } from '../src/suspensions.js';
import { createEdgeClient } from '../src/edge-client.js';
import { normalizeEmail } from '../src/tokens.js';

const usage = 'Usage: STATE_DIRECTORY=<state directory> node portal/bin/tenant.js suspend|resume|release <tenant_id|email> --reason "<text>"\n';
const AUDIT_KEEP = 5000;
const live = (record, now) => !record.revoked_at && Date.parse(record.expires_at) > now;

function parse(argv) {
  const [action, target, ...rest] = argv;
  let reason = null;
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '--reason' && typeof rest[i + 1] === 'string') reason = rest[++i];
    else return null;
  }
  reason = typeof reason === 'string' ? reason.replace(/[\x00-\x1f\x7f]/g, ' ').trim().slice(0, 500) : '';
  if (!['suspend', 'resume', 'release'].includes(action) || typeof target !== 'string' || !target || !reason) return null;
  return { action, target, reason };
}

function resolveTenant(accounts, suspensions, target) {
  if (/^t_[a-z2-7]{20}$/.test(target)) return accounts.tenants.some((t) => t.id === target) || suspensions.known(target) ? target : null;
  const email = normalizeEmail(target);
  return accounts.users.find((u) => email && u.email === email)?.tenant_id ?? null;
}

const hostnameCount = (result) => (Array.isArray(result?.hostnames) ? result.hostnames.length
  : Number.isInteger(result?.hostnames) ? result.hostnames : Number.isInteger(result?.suspended) ? result.suspended : null);
const edgeClient = (env) => createEdgeClient({ baseUrl: env.EDGE_INTERNAL_URL || 'http://127.0.0.1:8789', portalKey: env.PORTAL_KEY });

export async function main(argv, env, out) {
  const args = parse(argv);
  if (!args || !env.STATE_DIRECTORY) { out.stderr(usage); return 1; }
  const store = createStore(env.STATE_DIRECTORY);
  const suspensions = createSuspensions(store);
  const accounts = store.read('accounts', emptyAccounts());
  const tid = resolveTenant(accounts, suspensions, args.target);
  if (!tid) { out.stderr('Tenant not found\n'); return 1; }
  // Releasing a still-suspended account would hand its hostnames back to the pool while it is blocked.
  if (args.action === 'release' && suspensions.has(tid)) { out.stderr('Tenant is still suspended; resume it first, then release\n'); return 1; }
  const at = new Date().toISOString();
  const now = Date.now();
  const users = new Set(accounts.users.filter((u) => u.tenant_id === tid).map((u) => u.id));
  const summary = { action: args.action, tenant_id: tid };
  let code = 0;
  if (args.action === 'suspend') {
    const changed = !suspensions.has(tid);
    // revoked_before: every credential issued up to now stays invalid, even after resume.
    if (changed) suspensions.set(tid, { at, reason: args.reason, revoked_before: now });
    // The server revokes these on next use; the CLI never writes their files.
    Object.assign(summary, { changed, pending_revocation: {
      sessions: store.read('sessions', []).filter((s) => users.has(s.user_id) && s.expires_at > now).length,
      api_keys: store.read('api_keys', []).filter((k) => k.tenant_id === tid && live(k, now)).length,
      connect_tokens: store.read('connect_tokens', []).filter((t) => t.tenant_id === tid && live(t, now)).length,
    } });
    // Always call the edge, so re-running suspend retries a failed edge call. The edge route is idempotent.
    try {
      const result = await edgeClient(env).suspendTenant(tid);
      Object.assign(summary, { edge: 'ok', hostnames_suspended: hostnameCount(result) });
    } catch {
      Object.assign(summary, { edge: 'failed', hostnames_suspended: null, note: 'Portal suspension is in place. Re-run suspend to retry the edge.' });
      code = 2;
    }
  } else if (args.action === 'resume') {
    Object.assign(summary, { changed: suspensions.clear(tid, at),
      note: 'Portal access restored; credentials issued before the suspension stay revoked. Hostnames stay reserved on the edge until release; the customer then re-adds and re-verifies each one.' });
  } else {
    try {
      const result = await edgeClient(env).releaseTenant(tid);
      const released = Number.isInteger(result?.released) ? result.released : null;
      Object.assign(summary, { changed: released > 0, edge: 'ok', hostnames_released: released });
    } catch {
      Object.assign(summary, { changed: false, edge: 'failed', hostnames_released: null, note: 'Hostnames stay reserved. Re-run release to retry the edge.' });
      code = 2;
    }
  }
  const audit = store.read('admin_audit', []);
  const entries = Array.isArray(audit) ? audit : [];
  entries.push({ at, action: args.action, tenant_id: tid, reason: args.reason, changed: summary.changed, ...(summary.edge ? { edge: summary.edge } : {}) });
  store.write('admin_audit', entries.slice(-AUDIT_KEEP));
  out.stdout(`${JSON.stringify(summary)}\n`);
  return code;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2), process.env, { stdout: (s) => process.stdout.write(s), stderr: (s) => process.stderr.write(s) })
    .then((code) => { process.exitCode = code; }, () => { process.stderr.write('Failed\n'); process.exitCode = 1; });
}
