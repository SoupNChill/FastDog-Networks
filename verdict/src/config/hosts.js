import { readConfig, writeConfig } from './files.js';

/** Hosts that must never receive forward_auth / enforce mode. */
export const ENFORCE_DENYLIST = Object.freeze([
  'lease.fastdognetworks.com',
  'trysummitlease.com',
  'www.trysummitlease.com',
  'app.usepunchclock.com',
  'fastdognetworks.com',
  'www.fastdognetworks.com',
]);

/** Apex/www may be shadowed, never enforced. */
export const SHADOW_ALLOWED = Object.freeze([
  'fastdognetworks.com',
  'www.fastdognetworks.com',
  'verdict-demo.fastdognetworks.com',
]);

export const MODES = Object.freeze(['off', 'shadow', 'enforce']);
export const FAIL_POLICIES = Object.freeze(['open', 'closed']);

export function normalizeHost(host) {
  if (typeof host !== 'string' || /[^\x21-\x7e]/.test(host)) return '';
  const value = host.toLowerCase().replace(/:\d{1,5}$/, '').replace(/\.$/, '');
  if (value.length > 253 || !value.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return '';
  return value;
}

export function isEnforceDenied(host) {
  return ENFORCE_DENYLIST.includes(normalizeHost(host));
}

export function defaultHostConfig(host) {
  return {
    host: normalizeHost(host),
    enable: false,
    mode: 'off',
    fail: 'open',
    difficulty: 16,
  };
}

export function validateHostConfig(input, { host } = {}) {
  const h = normalizeHost(host || input?.host);
  if (!h || h.length > 253 || /[^a-z0-9.-]/.test(h)) {
    const err = new Error('invalid_host');
    err.status = 400;
    throw err;
  }
  const enable = Boolean(input?.enable);
  const mode = MODES.includes(input?.mode) ? input.mode : 'off';
  const fail = FAIL_POLICIES.includes(input?.fail) ? input.fail : 'open';
  let difficulty = Number(input?.difficulty ?? 16);
  if (!Number.isInteger(difficulty) || difficulty < 12 || difficulty > 22) {
    const err = new Error('invalid_difficulty');
    err.status = 400;
    throw err;
  }
  if (mode === 'enforce' && isEnforceDenied(h)) {
    const err = new Error('enforce_denied');
    err.status = 403;
    err.detail = `${h} is on the Verdict enforce denylist`;
    throw err;
  }
  return { host: h, enable, mode, fail, difficulty };
}

export function createHostStore(file = process.env.VERDICT_HOSTS_FILE || 'data/hosts.json') {
  let hosts = Object.create(null);
  let pending = Promise.resolve();

  async function load() {
    try {
      const raw = await readConfig(file);
      hosts = Object.create(null);
      const entries = raw?.hosts ?? raw;
      if (!entries || typeof entries !== 'object' || Array.isArray(entries)) throw new Error('invalid_hosts');
      for (const [k, v] of Object.entries(entries)) {
        hosts[normalizeHost(k)] = validateHostConfig(v, { host: k });
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      hosts = Object.create(null);
    }
  }

  async function persist(next) {
    await writeConfig(file, JSON.stringify({ hosts: next }, null, 2));
  }

  function list() {
    return Object.values(hosts).sort((a, b) => a.host.localeCompare(b.host));
  }

  function get(host) {
    return Object.hasOwn(hosts, normalizeHost(host)) ? hosts[normalizeHost(host)] : null;
  }

  function set(host, input) {
    const task = pending.then(async () => {
      const cfg = validateHostConfig({ ...input, host }, { host });
      const next = { ...hosts, [cfg.host]: cfg };
      await persist(next);
      hosts = next;
      return cfg;
    });
    pending = task.catch(() => {});
    return task;
  }

  function remove(host) {
    const task = pending.then(async () => {
      const h = normalizeHost(host);
      if (!hosts[h]) return false;
      const next = { ...hosts };
      delete next[h];
      await persist(next);
      hosts = next;
      return true;
    });
    pending = task.catch(() => {});
    return task;
  }

  return { load, list, get, set, remove, ready: () => pending };
}
