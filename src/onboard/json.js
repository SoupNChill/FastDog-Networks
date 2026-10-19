import fs from 'node:fs';
import path from 'node:path';
import { equalHash } from '../control/auth.js';
import { randomUUID } from 'node:crypto';
import { ROOT, env } from '../lib/config.js';

export const dataDir = () => path.resolve(ROOT, env('DATA_DIR', 'data'));
export const dataFile = (name, directory) => path.join(directory, AUTH_FILES.includes(name) && combined(directory) ? STATE : name);

const revisions = new Map();
export const jsonRevision = (name, directory = dataDir()) => revisions.get(path.resolve(directory, name)) ?? 0;

export function readJson(name, fallback, directory = dataDir()) {
  if (AUTH_FILES.includes(name) && combined(directory)) return structuredClone(snapshot(directory)[name] ?? fallback);
  const file = dataFile(name, directory);
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : fallback;
}

export function writeJson(name, data, mode = 0o644, directory = dataDir()) {
  if (AUTH_FILES.includes(name) && combined(directory)) {
    return authTransaction(directory, () => {
      const current = transactions.get(path.resolve(directory));
      if (name === 'agent-credentials.json') for (const record of data) {
        const old = current[name]?.find((c) => c.id === record.id);
        if (old?.key_fingerprint !== undefined && (!equalHash(old.key_fingerprint, record.key_fingerprint) || old.public_key !== record.public_key)) throw new Error('immutable_key_binding');
      }
      current[name] = structuredClone(data);
    });
  }
  fs.mkdirSync(directory, { recursive: true });
  const file = dataFile(name, directory);
  const temp = `${file}.${process.pid}.${randomUUID()}.tmp`;
  fs.writeFileSync(temp, `${JSON.stringify(data, null, 2)}\n`, { mode });
  fs.renameSync(temp, file);
  fs.chmodSync(file, mode);
  const key = path.resolve(file);
  revisions.set(key, (revisions.get(key) ?? 0) + 1);
}

// Synchronous transactions are the single process writer lock: callbacks must never yield.
const AUTH_FILES = ['agent-credentials.json', 'tenant_hostnames.json', 'agent-bootstrap.json'];
const enabled = new Set();
const transactions = new Map();
const STATE = 'agent-auth-state.json';
export const AUTH_LOCK = '.agent-auth.lock';
export const combined = (directory) => enabled.has(path.resolve(directory)) || fs.existsSync(path.join(directory, STATE));
function snapshot(directory) {
  const state = transactions.get(path.resolve(directory)) ?? JSON.parse(fs.readFileSync(path.join(directory, STATE), 'utf8'));
  if (state?.version !== 1 || !Array.isArray(state['agent-credentials.json']) || !Array.isArray(state['tenant_hostnames.json']) || !state['agent-bootstrap.json']) throw new Error('invalid_auth_snapshot');
  return state;
}
export function atomicSnapshot(file, value, beforeRename = () => {}) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temp = `${file}.${randomUUID()}.tmp`;
  let fd;
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
    fs.writeFileSync(fd, JSON.stringify(value) + '\n');
    fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
    beforeRename();
    fs.renameSync(temp, file);
    const dir = fs.openSync(path.dirname(file), 'r');
    try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(temp); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  }
}
export function enableAuthState(directory = dataDir()) {
  const file = path.join(directory, STATE);
  if (!fs.existsSync(file)) {
    fs.mkdirSync(directory, { recursive: true });
    const lock = path.join(directory, AUTH_LOCK);
    const release = acquireLock(lock);
    try {
      if (!fs.existsSync(file)) {
        const initial = { version: 1 };
        for (const name of AUTH_FILES) initial[name] = readJson(name, [], directory);
        atomicSnapshot(file, initial);
      }
    } finally { release(); }
  }
  snapshot(directory);
  enabled.add(path.resolve(directory));
}
export function authTransaction(directory, fn) {
  if (!combined(directory)) return fn();
  const key = path.resolve(directory);
  if (transactions.has(key)) return fn();
  const lock = path.join(directory, AUTH_LOCK);
  let release;
  try { release = acquireLock(lock); } catch { throw Object.assign(new Error('bootstrap_unavailable'), { status: 503, code: 'bootstrap_unavailable' }); }
  try { transactions.set(key, snapshot(directory)); } catch (e) { release(); throw e; }
  try {
    const result = fn();
    if (result?.then) throw new Error('asynchronous_auth_transaction');
    const next = transactions.get(key);
    if (JSON.stringify(next) !== fs.readFileSync(path.join(directory, STATE), 'utf8').trim()) {
      atomicSnapshot(path.join(directory, STATE), next);
      for (const name of AUTH_FILES) { const file = path.resolve(directory, name); revisions.set(file, (revisions.get(file) ?? 0) + 1); }
    }
    return result;
  } finally { transactions.delete(key); release(); }
}

// Transactions are synchronous and short; any lock older than this is abandoned even if its pid was reused.
export const LOCK_CEILING_MS = 30000;
function createLock(lock) {
  const content = JSON.stringify({ pid: process.pid, nonce: randomUUID(), created: Date.now() });
  const fd = fs.openSync(lock, 'wx', 0o600);
  fs.writeFileSync(fd, content);
  return { fd, content };
}
function staleLock(lock, raw) {
  let holder;
  try { holder = JSON.parse(raw); } catch { /* Empty or partially written lock: age decides. */ }
  if (typeof holder === 'number') holder = { pid: holder };
  const created = Number.isFinite(holder?.created) ? holder.created : fs.statSync(lock).mtimeMs;
  if (Date.now() - created > LOCK_CEILING_MS) return true;
  if (!Number.isSafeInteger(holder?.pid) || holder.pid <= 0) return false;
  try { process.kill(holder.pid, 0); return false; } catch (err) { return err.code === 'ESRCH'; }
}
const busy = () => Object.assign(new Error('lock_busy'), { code: 'EEXIST' });
// Short bounded backoff for a competing live writer; transactions are synchronous, so this blocks for at most ~17 ms.
export const LOCK_RETRY_MS = [2, 5, 10];
const pause = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
function acquireLock(lock) {
  for (let retry = 0; ; retry++) {
    try { return tryLock(lock); } catch (e) {
      if (e.message !== 'lock_busy' || retry >= LOCK_RETRY_MS.length) throw e;
      pause(LOCK_RETRY_MS[retry]);
    }
  }
}
function tryLock(lock) {
  for (let attempt = 0; attempt < 3; attempt++) {
    let held;
    try { held = createLock(lock); } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      let raw;
      try { raw = fs.readFileSync(lock, 'utf8'); if (!staleLock(lock, raw)) throw busy(); } catch (err) { if (err.code === 'ENOENT') continue; throw err; }
      // A hard-link claim serializes recovery; reap only the exact lock (by nonce) that was judged stale.
      const claim = `${lock}.reap`;
      try { fs.linkSync(lock, claim); } catch (err) {
        if (err.code === 'ENOENT') continue;
        if (err.code !== 'EEXIST') throw err;
        // A live claim exists for microseconds. Linking updates ctime, so an old claim was left by a crashed reaper.
        try { if (Date.now() - fs.statSync(claim).ctimeMs <= LOCK_CEILING_MS) throw busy(); fs.unlinkSync(claim); } catch (stat) { if (stat.code !== 'ENOENT') throw stat; }
        continue;
      }
      try {
        if (fs.readFileSync(claim, 'utf8') !== raw) throw busy();
        fs.unlinkSync(lock);
      } finally { fs.unlinkSync(claim); }
      held = createLock(lock);
    }
    return () => {
      fs.closeSync(held.fd);
      // Never remove a lock that recovery has handed to another writer.
      try { if (fs.readFileSync(lock, 'utf8') === held.content) fs.unlinkSync(lock); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    };
  }
  throw busy();
}
