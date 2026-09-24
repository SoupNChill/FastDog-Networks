export const SERVICES = [
  { id: 'edge', name: 'Edge HTTPS' },
  { id: 'ns1', name: 'ns1 DNS' },
  { id: 'ns2', name: 'ns2 DNS' },
];

export function aggregate(results, lastChecked = new Date().toISOString()) {
  const checks = SERVICES.map(({ id, name }) => {
    const value = results[id] || { status: 'red', detail: 'No result' };
    return { id, name, status: ['green', 'yellow', 'red'].includes(value.status) ? value.status : 'red', latencyMs: value.latencyMs ?? null, detail: value.detail || '' };
  });
  const overall = checks.some((check) => check.status === 'red') ? 'red' : checks.some((check) => check.status === 'yellow') ? 'yellow' : 'green';
  return { overall, lastChecked, checks };
}

export function createStatusService({ probes, read, write, alert = async () => {}, intervalMs = 60000, now = () => Date.now() }) {
  let current;
  let loading;
  let running;

  async function cached() {
    if (current) return current;
    if (!loading) loading = Promise.resolve().then(read).then((value) => { current = value; return value; }).finally(() => { loading = null; });
    return loading;
  }

  async function refresh() {
    if (running) return running;
    running = (async () => {
      const previous = await cached();
      const entries = await Promise.all(SERVICES.map(async ({ id }) => {
        try { return [id, await probes[id]()]; }
        catch (error) { return [id, { status: 'red', detail: error.message, latencyMs: null }]; }
      }));
      const next = aggregate(Object.fromEntries(entries), new Date(now()).toISOString());
      current = next;
      try { await write(next); } catch (error) { console.warn(`status: could not save results: ${error.message}`); }
      for (const check of next.checks) {
        const prior = previous?.checks.find((item) => item.id === check.id);
        if (check.status === 'red' && prior && prior.status !== 'red') {
          Promise.resolve().then(() => alert(check, next)).catch((error) => console.warn(`status: alert failed: ${error.message}`));
        }
      }
      return next;
    })().finally(() => { running = null; });
    return running;
  }

  async function get({ force = false } = {}) {
    const value = await cached();
    if (force || !value || intervalMs === 0 || now() - Date.parse(value.lastChecked) >= intervalMs) return refresh();
    return value;
  }

  return { get, refresh };
}
