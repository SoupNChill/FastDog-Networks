import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { summarizeOperatorMetrics } from '../src/operator/metrics.js';
import { createOperatorApp } from '../src/operator/server.js';
import { parseChecklist } from '../src/operator/checklist.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

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
      agents: [{ connected: true, lastSeen: '2026-08-01T00:00:00Z' }, { connected: true, lastSeen: '2026-08-02T00:00:00Z' }, { connected: false }],
      edgeHealthOk: true,
      now: Date.parse('2026-09-01T00:00:00Z'),
    });
    assert.equal(result.zoneCount, 2);
    assert.equal(result.invitesRemaining, 3);
    assert.equal(result.unusedInviteCount, 1);
    assert.equal(result.lastPaidTest, '2026-02-01T00:00:00Z');
    assert.equal(result.agentsConnected, 2);
    assert.equal(result.newestConnectedLastSeen, '2026-08-02T00:00:00Z');
    assert.equal(result.tunnelConnected, true);
    assert.equal(result.edgeHealthOk, true);
  });

  it('returns no paid signal when there is no paid_test account', () => {
    assert.equal(summarizeOperatorMetrics({ accounts: [{ status: 'pending' }] }).lastPaidTest, null);
  });
});

it('parses checklist output and fails closed on execution errors', () => {
  const output = 'PASS MX: ok\nFAIL SOA: mismatch\nSAFE_TO_FLIP=yes\n';
  assert.equal(parseChecklist(output).SAFE_TO_FLIP, 'no');
  assert.deepEqual(parseChecklist(output).checks, ['PASS MX: ok', 'FAIL SOA: mismatch']);
  assert.equal(parseChecklist(output, new Error('timeout')).SAFE_TO_FLIP, 'no');
  assert.match(parseChecklist('').hold, /HOLD/);
});

it('serves gated checklist and zone creation/detail with onboarding instructions', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fastdog-operator-'));
  process.env.ZONES_DIR = path.join(dir, 'zones');
  process.env.DATA_DIR = path.join(dir, 'data');
  process.env.INVITE_REQUIRED = 'false';
  process.env.AGENT_TOKEN = 'operator-test-token';
  const server = createOperatorApp({ checklist: async () => parseChecklist('PASS MX: ok\nSAFE_TO_FLIP=yes\n') }).listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const headers = { 'x-fastdog-token': 'operator-test-token' };
  try {
    assert.equal((await fetch(`${base}/_fastdog/operator/ns-cut-checklist`)).status, 401);
    const checklist = await (await fetch(`${base}/_fastdog/operator/ns-cut-checklist`, { headers })).json();
    assert.equal(checklist.SAFE_TO_FLIP, 'yes');
    assert.match(checklist.hold, /HOLD/);
    const createdResponse = await fetch(`${base}/_fastdog/onboard/zones`, { method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: JSON.stringify({ zone: 'operator.example', invite_code: 'test', edge_ip: '192.0.2.5' }) });
    assert.equal(createdResponse.status, 201);
    const created = await createdResponse.json();
    assert.equal(created.instructions.zone, 'operator.example');
    assert.equal(created.instructions.ns.length, 2);
    assert.match(created.hold, /HOLD/);
    const detail = await (await fetch(`${base}/_fastdog/dns/zones/operator.example`, { headers })).json();
    assert.deepEqual(detail.records.map((r) => r.type), ['SOA', 'NS', 'NS', 'A']);
    assert.equal((await fetch(`${base}/_fastdog/dns/zones/missing.example`, { headers })).status, 404);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    for (const key of ['ZONES_DIR', 'DATA_DIR', 'INVITE_REQUIRED', 'AGENT_TOKEN']) delete process.env[key];
    fs.rmSync(dir, { recursive: true, force: true });
  }
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
