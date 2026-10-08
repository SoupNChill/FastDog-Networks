import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { readConfig, writeConfig } from '../config/files.js';

const hash = value => createHash('sha256').update(value).digest('hex');

export function createKeyStore(file = 'data/keys.json') {
  let keys = [];
  let pending = Promise.resolve();
  async function load() {
    try {
      const loaded = await readConfig(file);
      if (!Array.isArray(loaded) || loaded.some(key => !key || typeof key.id !== 'string' || !/^[a-f0-9]{64}$/.test(key.hash) || ![undefined, 'full', 'read'].includes(key.scope))) throw new Error('invalid_key_store');
      keys = loaded;
    }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  async function create(name = 'default', { bootstrapOnly = false, scope = 'full' } = {}) {
    const task = pending.then(async () => {
      if (bootstrapOnly && keys.length > 0) {
        const error = new Error('Bootstrap already completed');
        error.status = 401;
        throw error;
      }
      const plaintext = `vd_${randomBytes(32).toString('base64url')}`;
      const record = { id: randomBytes(12).toString('hex'), name, hash: hash(plaintext), created_at: new Date().toISOString(), scope: scope === 'read' ? 'read' : 'full' };
      const next = [...keys, record];
      await writeConfig(file, JSON.stringify(next, null, 2));
      keys = next;
      return { key: plaintext, id: record.id, name: record.name, created_at: record.created_at, scope: record.scope };
    });
    pending = task.catch(() => {});
    return task;
  }
  function verify(plaintext) {
    if (typeof plaintext !== 'string' || !plaintext) return null;
    const candidate = Buffer.from(hash(plaintext), 'hex');
    let found = null;
    for (const key of keys) {
      if (key.revoked_at) continue;
      const stored = Buffer.from(String(key.hash || ''), 'hex');
      if (stored.length !== candidate.length) continue;
      if (timingSafeEqual(candidate, stored)) found = key;
    }
    return found;
  }
  function revoke(id) {
    const task = pending.then(async () => {
      if (!keys.some(key => key.id === id)) return false;
      const next = keys.map(key => key.id === id ? { ...key, revoked_at: key.revoked_at || new Date().toISOString() } : key);
      await writeConfig(file, JSON.stringify(next, null, 2));
      keys = next;
      return true;
    });
    pending = task.catch(() => {});
    return task;
  }
  return { load, create, verify, revoke, list: () => keys.map(({ id, name, created_at, revoked_at, scope }) => ({ id, name, created_at, scope: scope || 'full', revoked_at: revoked_at || null })), hasKeys: () => keys.length > 0 };
}

export function isLoopback(address = '') {
  return address === '::1' || /^(?:::ffff:)?127\.\d+\.\d+\.\d+$/.test(address);
}

export function keyAuth(store, { allowBootstrap = process.env.VERDICT_ALLOW_BOOTSTRAP === '1' } = {}) {
  return (req, res, next) => {
    if (req.path === '/keys' && req.method === 'POST' && !store.hasKeys()) {
      if (allowBootstrap || (isLoopback(req.socket.remoteAddress) && !['x-forwarded-for', 'x-forwarded-host', 'forwarded', 'origin'].some(name => req.get(name)))) return next();
      return res.status(403).json({ error: 'bootstrap_disabled' });
    }
    const token = /^Bearer (\S+)$/i.exec(req.get('authorization') || '')?.[1];
    const key = store.verify(token);
    if (!key) return res.status(401).json({ error: 'unauthorized' });
    req.apiKey = key;
    next();
  };
}
