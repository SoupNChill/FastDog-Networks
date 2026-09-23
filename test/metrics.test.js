import { it } from 'node:test';
import assert from 'node:assert/strict';
import { inc, get, resetForTests } from '../src/lib/metrics.js';

it('tracks counters and connection gauges', () => {
  resetForTests();
  inc('requestsProxied');
  inc('requestsTunnel');
  const metrics = get({ agentsRegistered: 2, agentsConnected: 1 });
  assert.equal(metrics.requestsProxied, 1);
  assert.equal(metrics.requestsTunnel, 1);
  assert.equal(metrics.tunnelConnected, true);
  assert.equal(metrics.agentsConnected, 1);
  assert.equal(metrics.agentsRegistered, 2);
  assert.ok(metrics.uptimeSeconds >= 0);
  resetForTests();
  assert.equal(get().requestsProxied, 0);
});
