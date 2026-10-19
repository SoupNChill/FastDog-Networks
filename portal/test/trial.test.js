import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fixture, temporary, request, tids } from './helpers.js';
import { createStore, emptyAccounts } from '../src/store.js';
import { createEdgeClient } from '../src/edge-client.js';
import { trialInfo, sweepTrials, scheduleTrialSweep, tenantPlan } from '../src/trials.js';
import { main } from '../bin/tenant.js';
import { internalHarness } from '../../test/helpers/internal.js';

const DAY = 86400000;
const start = Date.parse('2026-10-01T09:30:00.000Z');
const trialTenant = (id = tids[0], extra = {}) => ({ id, name: '', plan: 'trial', hostname_limit: 1, status: 'active', source: 'open', created_at: new Date(start).toISOString(), ...extra });

// Records every call; any method other than pause/unpause is recorded too, so tests can assert nothing else ran.
function recordingEdge({ fail = () => false } = {}) {
  const calls = [];
  const edge = new Proxy({}, { get: (_, name) => async (...args) => {
    calls.push([name, ...args]);
    if (fail(name, ...args)) throw Object.assign(new Error('edge down'), { code: 'internal_error' });
    return { tenant_id: args[0], paused: name === 'pauseTenant', changed: true, hostnames: 1 };
  } });
  return { edge, calls };
}

function state(t, tenants) {
  const store = createStore(temporary(t));
  store.write('accounts', { ...emptyAccounts(), tenants });
  const logs = [];
  let clock = start;
  const sweep = (edge) => sweepTrials({ store, edge, now: () => clock, logger: (entry) => logs.push(entry) });
  return { store, logs, sweep, set: (ms) => { clock = ms; }, trials: () => store.read('trials', { tenants: {} }).tenants, audit: () => store.read('trial_audit', []) };
}

const forbidden = (calls) => calls.filter(([name]) => !['pauseTenant', 'unpauseTenant'].includes(name));

test('trialInfo: rolling 7 days from creation, ceil days left, extension and effective plan', () => {
  const tenant = trialTenant();
  const at = (ms, s = null, o = null) => trialInfo(tenant, s, o, start + ms);
  assert.deepEqual(at(0), { active: true, started_at: '2026-10-01T09:30:00.000Z', ends_at: '2026-10-08T09:30:00.000Z', days_left: 7, paused: false });
  assert.equal(at(1).days_left, 7);
  assert.equal(at(DAY).days_left, 6);
  assert.deepEqual([at(7 * DAY - 60000).active, at(7 * DAY - 60000).days_left], [true, 1]);
  assert.deepEqual([at(7 * DAY).active, at(7 * DAY).days_left], [false, 0]);
  assert.equal(at(30 * DAY).days_left, 0);
  assert.equal(at(7 * DAY, { paused_at: 'x' }).paused, true);
  assert.equal(at(0, null, { extra_days: 3 }).ends_at, '2026-10-11T09:30:00.000Z');
  assert.equal(at(0, null, { plan: 'hobby' }), null);
  assert.equal(trialInfo({ ...tenant, plan: 'hobby' }, null, null, start), null);
  // Overrides only upgrade: a paid accounts.json plan is never masked by an override to trial.
  assert.equal(trialInfo({ ...tenant, plan: 'hobby' }, null, { plan: 'trial' }, start), null);
  // Without created_at the recorded start applies.
  assert.equal(trialInfo({ ...tenant, created_at: undefined }, { started_at: '2026-10-05T00:00:00.000Z' }, null, start).ends_at, '2026-10-12T00:00:00.000Z');
});

test('sweep: day 7 is untouched, day 8 pauses once, re-runs quietly reassert the pause and nothing is ever deleted', async (t) => {
  const s = state(t, [trialTenant(), { ...trialTenant(tids[1]), plan: 'hobby' }]);
  const { edge, calls } = recordingEdge();
  s.set(start + 7 * DAY - 60000);
  await s.sweep(edge);
  assert.deepEqual(calls, []);
  assert.deepEqual(s.trials(), {});
  s.set(start + 7 * DAY);
  assert.deepEqual(await s.sweep(edge), { paused: 1, unpaused: 0, failed: 0 });
  assert.deepEqual(calls, [['pauseTenant', tids[0]]]);
  assert.deepEqual(s.trials(), { [tids[0]]: { pause_requested_at: new Date(start + 7 * DAY).toISOString(), paused_at: new Date(start + 7 * DAY).toISOString() } });
  assert.deepEqual(s.audit(), [{ at: new Date(start + 7 * DAY).toISOString(), action: 'trial_pause', tenant_id: tids[0], edge: 'ok' }]);
  const before = { trials: s.trials(), audit: s.audit(), logs: [...s.logs] };
  s.set(start + 9 * DAY);
  assert.deepEqual(await s.sweep(edge), { paused: 0, unpaused: 0, failed: 0 });
  assert.deepEqual(await s.sweep(edge), { paused: 0, unpaused: 0, failed: 0 });
  assert.deepEqual(calls, Array.from({ length: 3 }, () => ['pauseTenant', tids[0]]));
  assert.deepEqual({ trials: s.trials(), audit: s.audit(), logs: s.logs }, before);
  assert.deepEqual(forbidden(calls), []);
});

test('sweep: an edge failure is not recorded and is retried on the next run; logs carry reason codes only', async (t) => {
  const s = state(t, [trialTenant(), trialTenant(tids[1])]);
  let down = true;
  const { edge, calls } = recordingEdge({ fail: (name, tid) => down && tid === tids[0] });
  s.set(start + 8 * DAY);
  assert.deepEqual(await s.sweep(edge), { paused: 1, unpaused: 0, failed: 1 });
  assert.ok(s.trials()[tids[0]].pause_requested_at);
  assert.equal(s.trials()[tids[0]].paused_at, undefined);
  assert.ok(s.trials()[tids[1]].paused_at, 'one failure does not stop the rest');
  assert.deepEqual(s.audit().map((e) => [e.tenant_id, e.edge]), [[tids[0], 'failed'], [tids[1], 'ok']]);
  assert.ok(s.logs.some((e) => e.reason === 'edge_failed'));
  assert.ok(!JSON.stringify(s.logs).includes(tids[0]));
  down = false;
  await s.sweep(edge);
  assert.ok(s.trials()[tids[0]].paused_at);
  assert.deepEqual(calls.map(([name, tid]) => [name, tid]), [['pauseTenant', tids[0]], ['pauseTenant', tids[1]], ['pauseTenant', tids[0]], ['pauseTenant', tids[1]]]);
  const before = s.trials();
  down = true;
  assert.deepEqual(await s.sweep(edge), { paused: 0, unpaused: 0, failed: 1 });
  assert.deepEqual(s.trials(), before);
  assert.deepEqual(s.audit().at(-1), { at: new Date(start + 8 * DAY).toISOString(), action: 'trial_pause', tenant_id: tids[0], edge: 'failed' });
  assert.ok(s.logs.some((e) => e.reason === 'edge_failed'));
  assert.ok(!JSON.stringify(s.logs).includes(tids[0]));
  assert.deepEqual(forbidden(calls), []);
});

test('sweep: upgrading through accounts.json or the override file unpauses; suspended tenants are skipped', async (t) => {
  const s = state(t, [trialTenant(), trialTenant(tids[1]), trialTenant(tids[2])]);
  s.store.write('suspensions', { tenants: { [tids[2]]: { at: new Date(start).toISOString(), reason: 'test', revoked_before: start, edge_ok: true } } });
  const { edge, calls } = recordingEdge();
  s.set(start + 8 * DAY);
  await s.sweep(edge);
  assert.deepEqual(calls, [['pauseTenant', tids[0]], ['pauseTenant', tids[1]]]);
  const accounts = s.store.read('accounts');
  accounts.tenants[0].plan = 'hobby';
  s.store.write('accounts', accounts);
  s.store.write('trial_overrides', { tenants: { [tids[1]]: { plan: 'pro' } } });
  s.set(start + 9 * DAY);
  assert.deepEqual(await s.sweep(edge), { paused: 0, unpaused: 2, failed: 0 });
  assert.deepEqual(calls.slice(2), [['unpauseTenant', tids[0]], ['unpauseTenant', tids[1]]]);
  for (const tid of [tids[0], tids[1]]) assert.deepEqual(s.trials()[tid], { unpaused_at: new Date(start + 9 * DAY).toISOString() });
  assert.deepEqual(s.audit().slice(2).map((e) => [e.action, e.tenant_id, e.edge]), [['trial_unpause', tids[0], 'ok'], ['trial_unpause', tids[1], 'ok']]);
  await s.sweep(edge);
  assert.equal(calls.length, 4);
  assert.deepEqual(forbidden(calls), []);
});

test('sweep: legacy trial tenants without created_at get a full trial from first sight; an extension unpauses', async (t) => {
  const s = state(t, [trialTenant(tids[0], { created_at: undefined })]);
  const { edge, calls } = recordingEdge();
  s.set(start + 100 * DAY);
  await s.sweep(edge);
  assert.deepEqual(calls, []);
  assert.deepEqual(s.trials()[tids[0]], { started_at: new Date(start + 100 * DAY).toISOString() });
  s.set(start + 107 * DAY);
  await s.sweep(edge);
  assert.deepEqual(calls, [['pauseTenant', tids[0]]]);
  s.store.write('trial_overrides', { tenants: { [tids[0]]: { extra_days: 2 } } });
  await s.sweep(edge);
  assert.deepEqual(calls.at(-1), ['unpauseTenant', tids[0]]);
  s.set(start + 109 * DAY);
  await s.sweep(edge);
  assert.deepEqual(calls.at(-1), ['pauseTenant', tids[0]]);
  assert.equal(calls.length, 3);
});

test('sweep: an extension that expires before the next sweep re-pauses despite stale paused_at', async (t) => {
  const s = state(t, [trialTenant()]);
  const { edge, calls } = recordingEdge();
  s.set(start + 8 * DAY - 30 * 60000);
  await s.sweep(edge);
  const before = { trials: s.trials(), audit: s.audit() };
  // Simulate the CLI's override and edge unpause; only the sweep may write trials.json.
  s.store.write('trial_overrides', { tenants: { [tids[0]]: { extra_days: 1 } } });
  assert.equal(tenantPlan(s.store, trialTenant(), start + 8 * DAY - 30 * 60000).trial.active, true);
  await edge.unpauseTenant(tids[0]);
  assert.deepEqual(s.trials(), before.trials);
  s.set(start + 8 * DAY + 30 * 60000);
  assert.deepEqual(await s.sweep(edge), { paused: 0, unpaused: 0, failed: 0 });
  assert.deepEqual(calls, [['pauseTenant', tids[0]], ['unpauseTenant', tids[0]], ['pauseTenant', tids[0]]]);
  assert.deepEqual({ trials: s.trials(), audit: s.audit() }, before);
});

test('scheduled sweep never overlaps and stops cleanly', async (t) => {
  const s = state(t, [trialTenant()]);
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const calls = [];
  const edge = { async pauseTenant(tid) { calls.push(tid); await gate; return {}; } };
  const schedule = scheduleTrialSweep({ store: s.store, edge, now: () => start + 8 * DAY, delayMs: 3600000 });
  t.after(() => schedule.stop());
  const first = schedule.run();
  const second = schedule.run();
  release();
  await Promise.all([first, second]);
  assert.deepEqual(calls, [tids[0]]);
});

test('trial tenants get one hostname on session and API-key paths; /api/plan and /api/me show trial details', async (t) => {
  const f = await fixture(t);
  const a = await f.seed();
  const b = await f.seed(1);
  const accounts = f.store.read('accounts');
  accounts.tenants[0] = { ...accounts.tenants[0], plan: 'trial', hostname_limit: 3, created_at: new Date(f.now()).toISOString() };
  accounts.tenants[1] = { ...accounts.tenants[1], plan: 'hobby', hostname_limit: 3 };
  f.store.write('accounts', accounts);
  assert.equal((await a.client.call('/api/hostnames', 'POST', { hostname: 'app.example.test' })).status, 201);
  assert.deepEqual(f.calls.filter(([name]) => name === 'create').at(-1), ['create', tids[0], 'app.example.test', 1]);
  const plan = (await a.client.call('/api/plan')).data;
  assert.deepEqual(plan, { plan: 'trial', hostname_limit: 1, trial: { active: true, started_at: new Date(f.now()).toISOString(),
    ends_at: new Date(f.now() + 7 * DAY).toISOString(), days_left: 7, paused: false } });
  assert.deepEqual((await a.client.call('/api/me')).data.tenant, { id: tids[0], ...plan });
  f.store.write('trials', { tenants: { [tids[0]]: { paused_at: new Date(f.now()).toISOString() } } });
  f.advance(8 * DAY);
  assert.deepEqual({ ...(await a.client.call('/api/plan')).data.trial, started_at: undefined, ends_at: undefined },
    { active: false, started_at: undefined, ends_at: undefined, days_left: 0, paused: true });
  // Paid tenant: no trial; an override to trial cannot downgrade it, on the API-key path either.
  assert.deepEqual((await b.client.call('/api/plan')).data, { plan: 'hobby', hostname_limit: 3, trial: null });
  const key = (await b.client.call('/api/keys', 'POST', { password: b.password, scopes: ['hostnames:create'] })).data.key;
  f.store.write('trial_overrides', { tenants: { [tids[1]]: { plan: 'trial' } } });
  const created = await request(f.port, '/api/v1/hostnames', { method: 'POST', headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' }, body: { hostname: 'api.example.test' } });
  assert.equal(created.status, 201);
  assert.deepEqual(f.calls.filter(([name]) => name === 'create').at(-1), ['create', tids[1], 'api.example.test', 3]);
  assert.equal(tenantPlan(f.store, f.store.read('accounts').tenants[1], f.now()).plan, 'hobby');
});

test('corrupt or wrongly shaped trial files never break the portal: paid tenants keep full limits, trial stays at 1', async (t) => {
  const f = await fixture(t);
  const a = await f.seed();
  const b = await f.seed(1);
  const accounts = f.store.read('accounts');
  accounts.tenants[0] = { ...accounts.tenants[0], plan: 'trial', hostname_limit: 3, created_at: new Date(f.now()).toISOString() };
  accounts.tenants[1] = { ...accounts.tenants[1], plan: 'hobby', hostname_limit: 3 };
  f.store.write('accounts', accounts);
  const key = (await b.client.call('/api/keys', 'POST', { password: b.password, scopes: ['hostnames:create'] })).data.key;
  const lastCreate = () => f.calls.filter(([name]) => name === 'create').at(-1);
  let n = 0;
  for (const [overrides, trials] of [['{not json', '{not json'], ['[]', '{"tenants":[]}'], ['{"tenants":{"x":1}}', 'null']]) {
    writeFileSync(join(f.dataDir, 'trial_overrides.json'), overrides);
    writeFileSync(join(f.dataDir, 'trials.json'), trials);
    const label = `${overrides} / ${trials}`;
    assert.deepEqual((await b.client.call('/api/plan')).data, { plan: 'hobby', hostname_limit: 3, trial: null }, label);
    assert.deepEqual((await b.client.call('/api/me')).data.tenant, { id: tids[1], plan: 'hobby', hostname_limit: 3, trial: null }, label);
    assert.equal((await b.client.call('/api/hostnames', 'POST', { hostname: `paid${++n}.example.test` })).status, 201, label);
    assert.deepEqual(lastCreate(), ['create', tids[1], `paid${n}.example.test`, 3], label);
    const viaKey = await request(f.port, '/api/v1/hostnames', { method: 'POST', headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' }, body: { hostname: `key${n}.example.test` } });
    assert.equal(viaKey.status, 201, label);
    assert.deepEqual(lastCreate(), ['create', tids[1], `key${n}.example.test`, 3], label);
    const plan = (await a.client.call('/api/plan')).data;
    assert.equal(plan.hostname_limit, 1, label);
    assert.equal(plan.trial.paused, false, label);
    assert.equal((await a.client.call('/api/me')).data.tenant.hostname_limit, 1, label);
    assert.equal((await a.client.call('/api/hostnames', 'POST', { hostname: `trial${n}.example.test` })).status, 201, label);
    assert.deepEqual(lastCreate(), ['create', tids[0], `trial${n}.example.test`, 1], label);
  }
});

test('override plan trial cannot mask a paid accounts.json plan: not paused, unpaused if paused, full limit', async (t) => {
  const s = state(t, [{ ...trialTenant(), plan: 'pro', hostname_limit: 5 }, { ...trialTenant(tids[1]), plan: 'pro', hostname_limit: 5 }]);
  s.store.write('trial_overrides', { tenants: { [tids[0]]: { plan: 'trial' }, [tids[1]]: { plan: 'trial' } } });
  s.store.write('trials', { tenants: { [tids[1]]: { paused_at: new Date(start + 7 * DAY).toISOString() } } });
  const { edge, calls } = recordingEdge();
  s.set(start + 30 * DAY);
  assert.deepEqual(await s.sweep(edge), { paused: 0, unpaused: 1, failed: 0 });
  assert.deepEqual(calls, [['unpauseTenant', tids[1]]]);
  assert.equal(s.trials()[tids[0]], undefined);
  assert.equal(s.trials()[tids[1]].paused_at, undefined);
  for (const tenant of s.store.read('accounts').tenants) {
    assert.deepEqual(tenantPlan(s.store, tenant, start + 30 * DAY), { plan: 'pro', hostname_limit: 5, trial: null });
  }
});

async function cli(env, ...args) {
  let stdout = '';
  let stderr = '';
  const code = await main(args, env, { stdout: (s) => { stdout += s; }, stderr: (s) => { stderr += s; } });
  return { code, stdout, stderr, json: (() => { try { return JSON.parse(stdout); } catch { return null; } })() };
}

test('tenant CLI: extend-trial and set-plan write the override and admin audit; set-plan to paid unpauses the edge', async (t) => {
  const h = await internalHarness(t);
  const dir = temporary(t);
  const store = createStore(dir);
  store.write('accounts', { ...emptyAccounts(), tenants: [trialTenant()] });
  const env = { STATE_DIRECTORY: dir, EDGE_INTERNAL_URL: `http://127.0.0.1:${h.server.address().port}`, PORTAL_KEY: h.portalKey };
  for (const args of [['extend-trial', tids[0], '--days', '3'], ['extend-trial', tids[0], '--days', '0', '--reason', 'x'],
    ['extend-trial', tids[0], '--days', '91', '--reason', 'x'], ['set-plan', tids[0], 'enterprise', '--reason', 'x'], ['set-plan', tids[0], '--reason', 'x']]) {
    assert.equal((await cli(env, ...args)).code, 1, args.join(' '));
  }
  const extended = await cli(env, 'extend-trial', tids[0], '--days', '3', '--reason', 'support request');
  assert.equal(extended.code, 0);
  assert.equal(extended.json.extra_days, 3);
  assert.equal(extended.json.ends_at, new Date(start + 10 * DAY).toISOString());
  assert.deepEqual(store.read('trial_overrides').tenants[tids[0]], { extra_days: 3 });
  assert.equal(trialInfo(trialTenant(), null, store.read('trial_overrides').tenants[tids[0]], start).ends_at, new Date(start + 10 * DAY).toISOString());
  for (let i = 0; i < 5; i++) await cli(env, 'extend-trial', tids[0], '--days', '90', '--reason', 'cap test');
  assert.equal(store.read('trial_overrides').tenants[tids[0]].extra_days, 365);
  const edge = createEdgeClient({ baseUrl: env.EDGE_INTERNAL_URL, portalKey: h.portalKey });
  await edge.pauseTenant(tids[0]);
  const paused = () => Object.hasOwn(JSON.parse(readFileSync(join(h.dataDir, 'paused_tenants.json'), 'utf8')).tenants, tids[0]);
  assert.equal(paused(), true);
  const upgraded = await cli(env, 'set-plan', tids[0], 'hobby', '--reason', 'paid by invoice');
  assert.equal(upgraded.code, 0);
  assert.equal(upgraded.json.edge, 'ok');
  assert.equal(paused(), false);
  assert.deepEqual(store.read('trial_overrides').tenants[tids[0]], { extra_days: 365, plan: 'hobby' });
  const down = await cli({ ...env, EDGE_INTERNAL_URL: 'http://127.0.0.1:1' }, 'set-plan', tids[0], 'pro', '--reason', 'edge down');
  assert.equal(down.code, 2);
  assert.equal(down.json.edge, 'failed');
  assert.equal(store.read('trial_overrides').tenants[tids[0]].plan, 'pro', 'override kept; the sweep retries the unpause');
  assert.equal((await cli(env, 'set-plan', tids[0], 'trial', '--reason', 'back to trial')).json.edge, undefined);
  const audit = store.read('admin_audit');
  assert.deepEqual(audit.map((e) => [e.action, e.reason, e.edge]).slice(-3), [['set-plan', 'paid by invoice', 'ok'], ['set-plan', 'edge down', 'failed'], ['set-plan', 'back to trial', undefined]]);
  assert.deepEqual(audit[0], { at: audit[0].at, action: 'extend-trial', tenant_id: tids[0], reason: 'support request', changed: true, extra_days: 3 });
  for (const output of [extended, upgraded, down].map((r) => r.stdout + r.stderr)) assert.ok(!output.includes(h.portalKey));
});


test('sweep: failed paused_at write retains a request and an upgrade unpauses', async (t) => {
  const s = state(t, [trialTenant()]);
  const write = s.store.write;
  s.store.write = (name, value) => {
    if (name === 'trials' && value.tenants[tids[0]]?.paused_at) throw new Error('state write failed');
    write(name, value);
  };
  const { edge, calls } = recordingEdge();
  s.set(start + 8 * DAY);
  assert.deepEqual(await s.sweep(edge), { paused: 0, unpaused: 0, failed: 1 });
  assert.ok(s.trials()[tids[0]].pause_requested_at);
  assert.equal(s.trials()[tids[0]].paused_at, undefined);
  s.store.write('accounts', { ...emptyAccounts(), tenants: [trialTenant(tids[0], { plan: 'pro' })] });
  assert.deepEqual(await s.sweep(edge), { paused: 0, unpaused: 1, failed: 0 });
  assert.deepEqual(calls, [['pauseTenant', tids[0]], ['unpauseTenant', tids[0]]]);
  assert.deepEqual(s.trials()[tids[0]], { unpaused_at: new Date(start + 8 * DAY).toISOString() });
});

test('sweep: fresh accounts and overrides prevent pausing a tenant upgraded mid-run', async (t) => {
  for (const source of ['accounts', 'trial_overrides']) {
    const s = state(t, [trialTenant()]);
    const read = s.store.read;
    let changed = false;
    s.store.read = (name, fallback) => {
      const value = read(name, fallback);
      if (name === source && !changed) {
        changed = true;
        s.store.write(source, source === 'accounts'
          ? { ...emptyAccounts(), tenants: [trialTenant(tids[0], { plan: 'pro' })] }
          : { tenants: { [tids[0]]: { plan: 'pro' } } });
      }
      return value;
    };
    const { edge, calls } = recordingEdge();
    s.set(start + 8 * DAY);
    assert.deepEqual(await s.sweep(edge), { paused: 0, unpaused: 0, failed: 0 });
    assert.deepEqual(calls, [], source);
  }
});

test('tenantPlan: legacy trials have no countdown until a real start is recorded', (t) => {
  const s = state(t, []);
  const legacy = trialTenant(tids[0], { created_at: undefined });
  assert.equal(tenantPlan(s.store, legacy, start).trial, null);
  assert.equal(tenantPlan(s.store, legacy, start + DAY).trial, null);
  assert.equal(tenantPlan(s.store, trialTenant(), start + DAY).trial.days_left, 6);
  s.store.write('trials', { tenants: { [tids[0]]: { started_at: new Date(start).toISOString() } } });
  assert.equal(tenantPlan(s.store, legacy, start + DAY).trial.days_left, 6);
});
