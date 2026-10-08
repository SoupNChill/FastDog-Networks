export const latencyBounds = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500];
export function createMetrics({ capacity = 2048 } = {}) {
  if (!Number.isInteger(capacity) || capacity < 1) throw new Error('Invalid metrics capacity');
  const actions = { allow: 0, challenge: 0, block: 0 };
  const endpoints = Object.fromEntries(['/v1/decide', '/v1/edge-auth'].map(path => [path, {
    requests: 0, samples: new Float64Array(capacity), count: 0, cursor: 0,
  }]));
  let requests = 0;
  function observe(path, ms) {
    requests++;
    const entry = endpoints[path];
    if (!entry) return;
    entry.requests++;
    entry.samples[entry.cursor] = ms;
    entry.cursor = (entry.cursor + 1) % capacity;
    entry.count = Math.min(capacity, entry.count + 1);
  }
  return {
    observe,
    decision(action) { if (Object.hasOwn(actions, action)) actions[action]++; },
    middleware(req, res, next) {
      const start = performance.now();
      const path = req.path;
      res.once('finish', () => observe(path, performance.now() - start));
      next();
    },
    snapshot() {
      return { requests_total: requests, actions: { ...actions }, endpoints: Object.fromEntries(Object.entries(endpoints).map(([path, entry]) => {
        const sorted = Array.from(entry.samples.subarray(0, entry.count)).sort((a, b) => a - b);
        const percentile = p => sorted.length ? sorted[Math.ceil(sorted.length * p) - 1] : null;
        return [path, { requests_total: entry.requests, latency_ms: {
          samples: sorted.length, p50: percentile(0.5), p99: percentile(0.99),
          buckets: Object.fromEntries([...latencyBounds.map(bound => [String(bound), sorted.filter(ms => ms <= bound).length]), ['+Inf', sorted.length]]),
        } }];
      })) };
    },
  };
}
