// Credential state volume: one schema-versioned credential.json written atomically, plus an exclusive writer lock.
// Every write stays inside the state directory (no /tmp), so it works with a read-only root filesystem.
import realFs from 'node:fs';
import { join } from 'node:path';
import { randomBytes, createHash, createPrivateKey, createPublicKey } from 'node:crypto';

export const STATE_DIR = '/var/lib/fastdog-agent';
export const STATE_FILE = 'credential.json';
export const LOCK_FILE = '.agent.lock';
export const SCHEMA_VERSION = 1;
const PROBE_FILE = '.write-probe';
const TEMP = /^\.(?:credential\.json|write-probe)\.[0-9a-f]{32}\.tmp$/;
const MAX_STATE_BYTES = 65536;

export class StateError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

const uidOf = (opts) => opts.uid ?? process.getuid?.();
const hex64 = (v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
const id = (v) => typeof v === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(v);
const text = (v, max = 512) => typeof v === 'string' && v.length > 0 && v.length <= max;
const int = (v) => Number.isSafeInteger(v) && v >= 0;

// The directory must be a real directory (not a symlink) owned by this user with no group/other access.
export function checkDir(dir, opts = {}) {
  const fs = opts.fs ?? realFs;
  let st;
  try { st = fs.lstatSync(dir); } catch (e) {
    if (e.code === 'ENOENT') throw new StateError('state_dir_missing', 'The credential state volume is not mounted.');
    throw new StateError('state_dir_unsafe', 'The credential state directory cannot be inspected.');
  }
  if (st.isSymbolicLink() || !st.isDirectory()) throw new StateError('state_dir_unsafe', 'The credential state path is not a plain directory.');
  if (st.uid !== uidOf(opts) || (st.mode & 0o077) !== 0) throw new StateError('state_dir_unsafe', 'The credential state directory has the wrong owner or permissions. Use a fresh volume created by this image.');
}

// True when a state file entry exists (of any type); a missing directory or file means no state.
export function stateExists(dir, opts = {}) {
  const fs = opts.fs ?? realFs;
  try { fs.lstatSync(join(dir, STATE_FILE)); return true; } catch (e) {
    if (e.code === 'ENOENT' || e.code === 'ENOTDIR') return false;
    throw new StateError('state_file_unsafe', 'The credential state file cannot be inspected.');
  }
}

export function keyFingerprint(privateKeyPem) {
  const der = createPublicKey(createPrivateKey(privateKeyPem)).export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('hex');
}

const COMMON = ['schema', 'status', 'hostname', 'origin', 'audience', 'deployment_id', 'private_key', 'key_fingerprint'];
const PENDING = [...COMMON, 'code_digest', 'request', 'created_at', 'deadline_at', 'next_attempt_at', 'attempt', 'failure'];
const ACTIVE = [...COMMON, 'credential_id', 'token', 'promoted'];
const REQUEST = ['hostname', 'origin', 'deployment_id', 'request_id', 'recipient_public_key', 'agent_version', 'proof'];
const exactKeys = (object, allowed, required = allowed) => object && typeof object === 'object' && !Array.isArray(object) &&
  Object.keys(object).every((k) => allowed.includes(k)) && required.every((k) => k in object);

// Strict schema: unknown fields, unsupported versions or a key that does not match its fingerprint are corrupt.
export function validateState(value) {
  if (value?.schema !== SCHEMA_VERSION) throw new StateError('state_unsupported', 'The credential state has an unsupported format version.');
  const pending = value.status === 'pending';
  const ok = (pending ? exactKeys(value, PENDING, PENDING.filter((k) => k !== 'failure')) : value.status === 'active' && exactKeys(value, ACTIVE)) &&
    text(value.hostname, 253) && text(value.origin, 200) && text(value.audience, 300) && id(value.deployment_id) &&
    text(value.private_key, 8192) && hex64(value.key_fingerprint) &&
    (pending
      ? hex64(value.code_digest) && exactKeys(value.request, REQUEST) && REQUEST.every((k) => text(value.request[k], 4096)) &&
        value.request.hostname === value.hostname && value.request.origin === value.origin && value.request.deployment_id === value.deployment_id &&
        int(value.created_at) && int(value.deadline_at) && int(value.next_attempt_at) && int(value.attempt) && (value.failure === undefined || id(value.failure))
      : id(value.credential_id) && hex64(value.token) && typeof value.promoted === 'boolean');
  if (!ok) throw new StateError('state_corrupt', 'The credential state is invalid.');
  let fingerprint;
  try { fingerprint = keyFingerprint(value.private_key); } catch { throw new StateError('state_corrupt', 'The credential state is invalid.'); }
  if (fingerprint !== value.key_fingerprint) throw new StateError('state_corrupt', 'The credential state is invalid.');
  return value;
}

// Reads only a regular 0600 file owned by this user, opened without following symlinks.
export function readState(dir, opts = {}) {
  const fs = opts.fs ?? realFs;
  checkDir(dir, opts);
  const file = join(dir, STATE_FILE);
  const unsafe = () => new StateError('state_file_unsafe', 'The credential state file has the wrong type, owner or permissions.');
  let st, fd, raw;
  try { st = fs.lstatSync(file); } catch { throw unsafe(); }
  if (st.isSymbolicLink() || !st.isFile() || st.uid !== uidOf(opts) || (st.mode & 0o777) !== 0o600 || st.size > MAX_STATE_BYTES) throw unsafe();
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const opened = fs.fstatSync(fd);
    if (opened.ino !== st.ino || opened.dev !== st.dev) throw unsafe();
    raw = fs.readFileSync(fd, 'utf8');
  } catch (e) { throw e instanceof StateError ? e : unsafe(); } finally { if (fd !== undefined) fs.closeSync(fd); }
  let value;
  try { value = JSON.parse(raw); } catch { throw new StateError('state_corrupt', 'The credential state is invalid.'); }
  return validateState(value);
}

// Exclusive temp in the same directory (no symlink following, 0600), full write, fsync, rename, directory fsync.
export function atomicWrite(dir, name, data, opts = {}) {
  const fs = opts.fs ?? realFs;
  const temp = join(dir, `.${name}.${randomBytes(16).toString('hex')}.tmp`);
  const { O_WRONLY, O_CREAT, O_EXCL, O_NOFOLLOW, O_RDONLY, O_DIRECTORY } = fs.constants;
  let fd, renamed = false;
  try {
    fd = fs.openSync(temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600);
    fs.fchmodSync(fd, 0o600);
    const bytes = Buffer.from(data);
    for (let offset = 0; offset < bytes.length;) offset += fs.writeSync(fd, bytes, offset, bytes.length - offset);
    fs.fsyncSync(fd);
    fs.closeSync(fd); fd = undefined;
    fs.renameSync(temp, join(dir, name)); renamed = true;
    const dirFd = fs.openSync(dir, O_RDONLY | O_DIRECTORY);
    try { fs.fsyncSync(dirFd); } finally { fs.closeSync(dirFd); }
  } catch {
    throw new StateError('state_write_failed', 'The credential state could not be written durably.');
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch { /* Already closed. */ }
    if (!renamed) try { fs.unlinkSync(temp); } catch { /* Never created or already removed. */ }
  }
}

export function writeState(dir, value, opts = {}) {
  checkDir(dir, opts);
  atomicWrite(dir, STATE_FILE, `${JSON.stringify(validateState(value))}\n`, opts);
}

// Runs the complete write/fsync/rename/directory-fsync sequence on a probe file, then removes it.
export function probeWritable(dir, opts = {}) {
  const fs = opts.fs ?? realFs;
  checkDir(dir, opts);
  atomicWrite(dir, PROBE_FILE, 'probe\n', opts);
  try { fs.unlinkSync(join(dir, PROBE_FILE)); } catch { throw new StateError('state_write_failed', 'The credential state could not be written durably.'); }
}

// Only our own abandoned temp files, only inside the owned state directory, only while holding the lock.
export function removeAbandonedTemps(dir, opts = {}) {
  const fs = opts.fs ?? realFs;
  for (const name of fs.readdirSync(dir)) {
    if (!TEMP.test(name)) continue;
    try { const st = fs.lstatSync(join(dir, name)); if (st.isFile() && st.uid === uidOf(opts)) fs.unlinkSync(join(dir, name)); } catch { /* Raced or vanished. */ }
  }
}

// Exclusive volume lock. The holder refreshes its mtime; a lock not refreshed for staleMs belongs to a crashed agent
// (PIDs are not comparable across container restarts or PID namespaces) and is reaped under an exclusive claim.
export async function acquireLock(dir, opts = {}) {
  const fs = opts.fs ?? realFs;
  const now = opts.now ?? Date.now;
  const sleep = opts.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  const staleMs = opts.staleMs ?? 30000, refreshMs = opts.refreshMs ?? 10000, waitMs = opts.waitMs ?? staleMs + 5000;
  const lock = join(dir, LOCK_FILE), claim = `${lock}.reap`;
  const nonce = randomBytes(16).toString('hex');
  const { O_WRONLY, O_CREAT, O_EXCL, O_NOFOLLOW } = fs.constants;
  const started = now();
  checkDir(dir, opts);
  for (;;) {
    try {
      const fd = fs.openSync(lock, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600);
      try { fs.writeSync(fd, JSON.stringify({ nonce, pid: process.pid })); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      break;
    } catch (e) {
      if (e.code !== 'EEXIST') throw new StateError('state_write_failed', 'The credential state volume lock could not be created.');
    }
    let st;
    try { st = fs.lstatSync(lock); } catch { continue; }
    if (!st.isFile() || st.isSymbolicLink()) throw new StateError('state_dir_unsafe', 'The credential state lock is not a regular file.');
    if (now() - st.mtimeMs > staleMs) {
      if (reap(fs, lock, claim, st, now, staleMs)) continue;
    } else if (now() - started >= waitMs) {
      throw new StateError('volume_busy', 'Another agent is using this credential state volume. Stop it or use the volume from the connect command.');
    }
    await sleep(Math.min(1000, Math.max(10, Math.floor(staleMs / 10))));
  }
  const owned = () => { try { return JSON.parse(fs.readFileSync(lock, 'utf8')).nonce === nonce; } catch { return false; } };
  const timer = setInterval(() => {
    if (!owned()) { clearInterval(timer); opts.onLost?.(); return; }
    try { const t = new Date(now()); fs.utimesSync(lock, t, t); } catch { /* Retried next interval. */ }
  }, refreshMs);
  timer.unref?.();
  return {
    owned,
    release() { clearInterval(timer); if (owned()) try { fs.unlinkSync(lock); } catch { /* Already gone. */ } },
  };
}

function reap(fs, lock, claim, stale, now, staleMs) {
  try { fs.closeSync(fs.openSync(claim, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600)); } catch {
    // A reaper that crashed while holding its claim leaves it behind; it expires with the same ceiling.
    try { if (now() - fs.lstatSync(claim).mtimeMs > staleMs) fs.unlinkSync(claim); } catch { /* Raced. */ }
    return false;
  }
  try {
    const current = fs.lstatSync(lock);
    // Only remove the exact stale lock that was inspected, never a fresh replacement.
    if (current.ino === stale.ino && current.dev === stale.dev && now() - current.mtimeMs > staleMs) fs.unlinkSync(lock);
  } catch { /* Already removed. */ } finally {
    try { fs.unlinkSync(claim); } catch { /* Already removed. */ }
  }
  return true;
}
