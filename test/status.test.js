import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { aggregate, createStatusService } from '../src/status/aggregator.js';
import { readStatus, writeStatus } from '../src/status/store.js';
import { renderStatus } from '../src/status/html.js';

const green = { status: 'green', latencyMs: 22, detail: 'OK' };

describe('public status', () => {
  it('aggregates green, yellow, and red checks by severity', () => {
    assert.equal(aggregate({ edge: green, ns1: green, ns2: green }).overall, 'green');
    assert.equal(aggregate({ edge: green, ns1: { status: 'yellow', detail: 'slow' }, ns2: green }).overall, 'yellow');
    assert.equal(aggregate({ edge: { status: 'red', detail: 'down' }, ns1: { status: 'yellow' }, ns2: green }).overall, 'red');
  });

  it('runs mocked probes once for concurrent requests and persists the result', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'fastdog-status-'));
    const file = path.join(dir, 'status.json');
    let calls = 0;
    let clock = Date.parse('2026-09-24T12:00:00.000Z');
    const probes = Object.fromEntries(['edge', 'ns1', 'ns2'].map((id) => [id, async () => { calls++; return id === 'ns2' ? { status: 'red', latencyMs: 3000, detail: 'timeout' } : green; }]));
    const service = createStatusService({ probes, read: () => readStatus(file), write: (value) => writeStatus(value, file), intervalMs: 60000, now: () => clock });
    try {
      const [first, second] = await Promise.all([service.get(), service.get()]);
      assert.deepEqual(first, second);
      assert.equal(first.overall, 'red');
      assert.equal(first.lastChecked, '2026-09-24T12:00:00.000Z');
      assert.deepEqual(await readStatus(file), first);
      await service.get();
      assert.equal(calls, 3);
      clock += 60000;
      await service.get();
      assert.equal(calls, 6);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('turns thrown probe errors into red and renders safe service rows', async () => {
    const service = createStatusService({
      probes: { edge: async () => { throw new Error('<unreachable>'); }, ns1: async () => green, ns2: async () => green },
      read: async () => null,
      write: async () => {},
    });
    const result = await service.get();
    assert.equal(result.overall, 'red');
    const html = renderStatus(result);
    assert.match(html, /Fastdog public PoP status/);
    assert.match(html, /Edge HTTPS/);
    assert.match(html, /ns1 DNS/);
    assert.match(html, /ns2 DNS/);
    assert.match(html, /class="badge red"/);
    assert.match(html, /&lt;unreachable&gt;/);
    assert.doesNotMatch(html, /<unreachable>/);
  });

  it('alerts only when an existing check transitions to red', async () => {
    const alerts = [];
    let state = green;
    const service = createStatusService({
      probes: { edge: async () => state, ns1: async () => green, ns2: async () => green },
      read: async () => null,
      write: async () => {},
      alert: async (check) => { alerts.push(check.id); },
    });
    await service.refresh();
    state = { status: 'red', detail: 'down' };
    await service.refresh();
    await service.refresh();
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(alerts, ['edge']);
  });
});
