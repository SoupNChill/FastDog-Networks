import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { ROOT, env } from '../lib/config.js';

const file = (name) => path.join(path.resolve(ROOT, env('DATA_DIR', 'data')), name);

function read(name) {
  const target = file(name);
  return fs.existsSync(target) ? JSON.parse(fs.readFileSync(target, 'utf8')) : {};
}

function write(name, value) {
  const target = file(name);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const temp = `${target}.${process.pid}.${randomUUID()}.tmp`;
  fs.writeFileSync(temp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temp, target);
  fs.chmodSync(target, 0o600);
}

export function recordSession({ id, zone, account_id, plan }) {
  const sessions = read('billing-sessions.json');
  sessions[id] = { zone: zone || null, account_id, plan, created_at: new Date().toISOString() };
  write('billing-sessions.json', sessions);
  return sessions[id];
}

export function markPaidTest(sessionId) {
  const session = read('billing-sessions.json')[sessionId];
  if (!session) return null;
  const accounts = read('billing-accounts.json');
  const key = session.zone || session.account_id;
  accounts[key] = {
    zone: session.zone, account_id: session.account_id, status: 'paid_test',
    stripe_session_id: sessionId, plan: session.plan, updated_at: new Date().toISOString(),
  };
  write('billing-accounts.json', accounts);
  return accounts[key];
}

export function getStatus(zone) {
  return read('billing-accounts.json')[zone] || null;
}

export function listAccounts() {
  return Object.values(read('billing-accounts.json'));
}
