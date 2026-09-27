import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { summarizeOperatorMetrics } from '../src/operator/metrics.js';
import { createOperatorApp } from '../src/operator/server.js';

describe('operator metrics', () => {
  it('counts only active invite uses and selects latest paid_test', () => {
    const result = summarizeOperatorMetrics({
      zones: ['a.test', 'b.test'],
      invites: [
        { remaining_uses: 2, max_uses: 2 },
        { remaining_uses: 1, max_uses: 3 },
        { remaining_uses: 4, max_uses: 4, expires_at: '2020-01-01T00:00:00Z' },
        { remaining_uses: 0, max_uses: 1 },
      ],
      accounts: [
        { status: 'paid_test', updated_at: '2026-01-01T00:00:00Z' },
        { status: 'pending', updated_at: '2026-09-01T00:00:00Z' },
        { status: 'paid_test', updated_at: '2026-02-01T00:00:00Z' },
      ],
      agents: [{ connected: true }, { connected: false }],
      edgeHealthOk: true,
      now: Date.parse('2026-09-01T00:00:00Z'),
    });
    assert.equal(result.zoneCount, 2);
    assert.equal(result.invitesRemaining, 3);
    assert.equal(result.unusedInviteCount, 1);
    assert.equal(result.lastPaidTest, '2026-02-01T00:00:00Z');
    assert.equal(result.agentsConnected, 1);
    assert.equal(result.tunnelConnected, true);
    assert.equal(result.edgeHealthOk, true);
  });

  it('returns no paid signal when there is no paid_test account', () => {
    assert.equal(summarizeOperatorMetrics({ accounts: [{ status: 'pending' }] }).lastPaidTest, null);
  });
});

describe('operator HTTP gate', () => {
  it('requires the agent token for metrics and invite writes', async () => {
    process.env.AGENT_TOKEN = 'operator-test-token';
    const server = createOperatorApp({ edgeHealthy: () => true }).listen(0, '127.0.0.1');
    await new Promise((resolve) => server.once('listening', resolve));
    try {
      const base = `http://127.0.0.1:${server.address().port}`;
      assert.equal((await fetch(base)).status, 200);
      assert.equal((await fetch(`${base}/_fastdog/operator/metrics`)).status, 401);
      assert.equal((await fetch(`${base}/_fastdog/onboard/invites`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).status, 401);
      const response = await fetch(`${base}/_fastdog/operator/metrics`, { headers: { 'x-fastdog-token': 'operator-test-token' } });
      assert.equal(response.status, 200);
      assert.equal((await response.json()).edgeHealthOk, true);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
});
