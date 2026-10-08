import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

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
  return String(host || '').trim().toLowerCase().replace(/\.$/, '');
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
  let hosts = {};
  let pending = Promise.resolve();

  async function load() {
    try {
      const raw = JSON.parse(await readFile(file, 'utf8'));
      hosts = {};
      for (const [k, v] of Object.entries(raw?.hosts || raw || {})) {
        hosts[normalizeHost(k)] = validateHostConfig(v, { host: k });
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      hosts = {};
    }
  }

  async function persist() {
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, JSON.stringify({ hosts }, null, 2), { mode: 0o600 });
  }

  function list() {
    return Object.values(hosts).sort((a, b) => a.host.localeCompare(b.host));
  }

  function get(host) {
    return hosts[normalizeHost(host)] || null;
  }

  function set(host, input) {
    const task = pending.then(async () => {
      const cfg = validateHostConfig({ ...input, host }, { host });
      hosts = { ...hosts, [cfg.host]: cfg };
      await persist();
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
      hosts = next;
      await persist();
      return true;
    });
    pending = task.catch(() => {});
    return task;
  }

  return { load, list, get, set, remove, ready: () => pending };
}
