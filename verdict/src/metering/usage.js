import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

function emptyUsage() {
  return { decisions: 0, engines: {} };
}

export function createMeter({ file = process.env.VERDICT_USAGE_FILE || 'data/usage.json' } = {}) {
  const counts = new Map();
  let pending = Promise.resolve();
  let timer;
  let dirty = false;

  async function load() {
    try {
      const raw = JSON.parse(await readFile(file, 'utf8'));
      const entries = raw && typeof raw === 'object' ? Object.entries(raw) : [];
      counts.clear();
      for (const [id, usage] of entries) {
        if (!usage || typeof usage !== 'object') continue;
        counts.set(id, {
          decisions: Number(usage.decisions) || 0,
          engines: usage.engines && typeof usage.engines === 'object' ? { ...usage.engines } : {},
        });
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }

  async function flush() {
    const payload = Object.fromEntries(counts.entries());
    await mkdir(dirname(file), { recursive: true });
    const tmp = join(dirname(file), `.usage.${process.pid}.${Date.now()}.tmp`);
    await writeFile(tmp, JSON.stringify(payload, null, 2), { mode: 0o600 });
    await rename(tmp, file);
  }

  function record(id, engine) {
    const usage = counts.get(id) || emptyUsage();
    usage.decisions += 1;
    usage.engines[engine] = (usage.engines[engine] || 0) + 1;
    counts.set(id, usage);
    dirty = true;
    if (!timer) {
      timer = setTimeout(() => { timer = undefined; persist(); }, 1000);
      timer.unref();
    }
  }

  function persist() {
    if (!dirty) return pending;
    dirty = false;
    pending = pending.then(flush).catch(error => {
      dirty = true;
      console.error('usage flush failed:', error.message);
    });
    return pending;
  }

  function get(id) {
    const usage = counts.get(id) || emptyUsage();
    return { decisions: usage.decisions, engines: { ...usage.engines } };
  }

  async function ready() {
    clearTimeout(timer);
    timer = undefined;
    await persist();
  }

  return { load, record, get, ready, file };
}
