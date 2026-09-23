const startedAt = Date.now();
const counters = {
  requestsProxied: 0,
  requestsTunnel: 0,
  requestsStatic: 0,
  registerCount: 0,
};

export function inc(name) {
  if (!Object.hasOwn(counters, name)) throw new Error(`unknown metric: ${name}`);
  counters[name] += 1;
}

export function get({ agentsRegistered = 0, agentsConnected = 0 } = {}) {
  return {
    ...counters,
    tunnelConnected: agentsConnected > 0,
    agentsConnected,
    agentsRegistered,
    uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000),
  };
}

export function resetForTests() {
  for (const name of Object.keys(counters)) counters[name] = 0;
}
