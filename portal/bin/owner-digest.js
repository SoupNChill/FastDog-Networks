// Daily owner summary: node portal/bin/owner-digest.js [--dry-run] [--force] [--test-notice] [--now=<ISO time>].
// Run by deploy/fastdog-owner-digest.timer at 08:00 America/Denver; does nothing unless OWNER_DIGEST_ENABLED=1 and
// OWNER_NOTIFY_EMAIL are set. Reads portal state, the edge, the outbox and (with OWNER_DIGEST_VISITORS=1) Caddy
// access logs; writes only owner_digest.json ({ last_sent_day }) after the mailer accepts the message.
// stdout carries one JSON line with reason codes, never an address, an env value or a secret.
import { readFileSync } from 'node:fs';
import { join, resolve, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createStore } from '../src/store.js';
import { acquireLock } from '../src/mail-lock.js';
import { createEdgeClient } from '../src/edge-client.js';
import { normalizeEmail } from '../src/tokens.js';
import { ownerNotifyConfig } from '../src/owner-notify.js';
import { digestWindow, mtDay, collectAccounts, collectHostnames, collectMailHealth, countVisitors, countFunnel, logFiles,
  renderDigest } from '../src/owner-digest.js';
import { selectMailer } from '../server.js';

export const TEST_LINE = 'Test notice from the FastDog portal (owner notifications are on).';
const usage = 'Usage: node portal/bin/owner-digest.js [--dry-run] [--force] [--test-notice] [--now=<ISO time>]\n';
const LOG_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
const plain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

function parse(argv) {
  const flags = { dryRun: false, force: false, testNotice: false, now: null };
  for (const arg of argv) {
    if (arg === '--dry-run') flags.dryRun = true;
    else if (arg === '--force') flags.force = true;
    else if (arg === '--test-notice') flags.testNotice = true;
    else if (arg.startsWith('--now=') && Number.isFinite(Date.parse(arg.slice(6)))) flags.now = Date.parse(arg.slice(6));
    else return null;
  }
  return flags.dryRun && flags.testNotice ? null : flags;
}

// Validated settings, or { error: <reason code> }.
export function digestConfig(env) {
  const { to, showEmail } = ownerNotifyConfig(env);
  if (to !== null && !normalizeEmail(to)) return { error: 'invalid_address' };
  if (!env.STATE_DIRECTORY) return { error: 'no_state_directory' };
  const stateDir = resolve(env.STATE_DIRECTORY);
  const config = { to: to && normalizeEmail(to), showEmail, stateDir, outboxDir: env.OUTBOX_DIR ? resolve(env.OUTBOX_DIR) : join(stateDir, 'outbox'),
    visitors: env.OWNER_DIGEST_VISITORS === '1', logDir: '/var/log/caddy', siteLogs: [], funnelLog: null };
  if (!config.visitors) return config;
  if (env.OWNER_DIGEST_LOG_DIR) {
    if (!isAbsolute(env.OWNER_DIGEST_LOG_DIR) || env.OWNER_DIGEST_LOG_DIR.includes('\0')) return { error: 'invalid_log_dir' };
    config.logDir = resolve(env.OWNER_DIGEST_LOG_DIR);
  }
  const names = (env.OWNER_DIGEST_SITE_LOGS || '').split(',').map((name) => name.trim()).filter(Boolean);
  if (!names.every((name) => LOG_NAME.test(name))) return { error: 'invalid_site_logs' };
  config.siteLogs = [...new Set(names)];
  const funnel = (env.OWNER_DIGEST_FUNNEL_LOG || '').trim();
  if (funnel && !LOG_NAME.test(funnel)) return { error: 'invalid_funnel_log' };
  config.funnelLog = funnel || null;
  return config;
}

// Read-only view of the state directory: collecting never creates or writes a file.
const readOnlyStore = (dir) => ({
  read(name, fallback) {
    try { return JSON.parse(readFileSync(join(dir, `${name}.json`), 'utf8')); }
    catch (error) { if (error.code === 'ENOENT') return structuredClone(fallback); throw error; }
  },
});

// One run at a time per state directory, so a manual --force cannot race the timer into two sends. The mkdir lock is
// created atomically; it is treated as stale only after LOCK_STALE_MS, longer than the unit's TimeoutStartSec=180.
const LOCK_STALE_MS = 10 * 60000;
const lock = (dir) => acquireLock(join(dir, 'owner-digest.lock'), { staleMs: LOCK_STALE_MS });

export async function collect(config, env, now) {
  const window = digestWindow(now);
  const { accounts, trials, tenants } = collectAccounts({ store: readOnlyStore(config.stateDir), now, window });
  let edge = null;
  try { edge = createEdgeClient({ baseUrl: env.EDGE_INTERNAL_URL || 'http://127.0.0.1:8789', portalKey: env.PORTAL_KEY }); } catch { /* hostnames unavailable */ }
  const hostnames = await collectHostnames({ edge, tenants });
  const mail = collectMailHealth({ outboxDir: config.outboxDir, window });
  let visitors = null, funnel = null;
  if (config.visitors) {
    visitors = config.siteLogs.length ? await countVisitors({ files: logFiles({ logDir: config.logDir, names: config.siteLogs, window }), window })
      : { available: false, reason: 'not_configured' };
    if (config.funnelLog) funnel = await countFunnel({ files: logFiles({ logDir: config.logDir, names: [config.funnelLog], window }), window });
  }
  return { day: window.day, lines: renderDigest({ day: window.day, showEmail: config.showEmail, accounts, trials, hostnames, mail, visitors, funnel }) };
}

// delivered: 'smtp' means the message left; 'outbox' (file transport) keeps an audit record without the body.
async function deliver(mailer, message) {
  try {
    const result = await mailer.send(message);
    if (result?.delivered === 'smtp' || result?.delivered === 'outbox') return { ok: true, smtp: result.delivered === 'smtp' };
    return { ok: false, reason: typeof result?.reason === 'string' && /^[a-z][a-z_]{0,39}$/.test(result.reason) ? result.reason : 'send_failed' };
  } catch { return { ok: false, reason: 'send_failed' }; }
}

export async function main(argv, env, out, { clock = Date.now, mailer: injected = null } = {}) {
  const log = (result, reason) => out.stdout(`${JSON.stringify({ event: 'owner_digest', result, ...(reason ? { reason } : {}) })}\n`);
  const flags = parse(argv);
  if (!flags) { out.stderr(usage); log('invalid_config', 'usage'); return 1; }
  if (env.OWNER_DIGEST_ENABLED !== '1' && !flags.dryRun && !flags.testNotice) { out.stdout('owner digest disabled\n'); log('disabled'); return 0; }
  const config = digestConfig(env);
  if (config.error) { log('invalid_config', config.error); return 1; }
  const now = flags.now ?? clock();
  if (flags.dryRun) {
    // Terminal output never shows a full address, whatever OWNER_NOTIFY_SHOW_EMAIL says; only the mailed body may.
    const { lines } = await collect({ ...config, showEmail: false }, env, now);
    out.stdout(`${lines.join('\n')}\n`);
    log('dry_run');
    return 0;
  }
  if (!config.to) { out.stdout('owner digest disabled\n'); log('disabled', 'no_recipient'); return 0; }
  let mailer = injected;
  if (!mailer) try { mailer = selectMailer(env, { outboxDir: config.outboxDir, logger: () => {} }); } catch { log('invalid_config', 'mail_config'); return 1; }
  if (flags.testNotice) {
    const sent = await deliver(mailer, { to: config.to, kind: 'owner-event', lines: [TEST_LINE], count: 1 });
    log(sent.ok ? 'test_sent' : 'failed', sent.ok ? null : sent.reason);
    return sent.ok ? 0 : 2;
  }
  const store = createStore(config.stateDir);
  const unlock = lock(config.stateDir);
  if (!unlock) { log('skipped', 'locked'); return 0; }
  try {
    const today = mtDay(now);
    let last = null;
    try { const state = store.read('owner_digest', {}); if (plain(state) && typeof state.last_sent_day === 'string') last = state.last_sent_day; } catch { /* resend */ }
    if (last === today && !flags.force) { log('skipped', 'already_sent'); return 0; }
    const { day, lines } = await collect(config, env, now);
    const sent = await deliver(mailer, { to: config.to, kind: 'owner-digest', lines, date: day });
    if (!sent.ok) { log('failed', sent.reason); return 2; }
    // The file transport keeps no body, so only an SMTP hand-off marks the day as sent.
    if (!sent.smtp) { log('queued_file'); return 0; }
    try { store.write('owner_digest', { last_sent_day: today }); } catch { log('sent', 'state_write_failed'); return 3; }
    log('sent');
    return 0;
  } finally { unlock(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2), process.env, { stdout: (s) => process.stdout.write(s), stderr: (s) => process.stderr.write(s) })
    .then((code) => { process.exitCode = code; },
      () => { process.stdout.write(`${JSON.stringify({ event: 'owner_digest', result: 'failed', reason: 'internal' })}\n`); process.exitCode = 2; });
}
