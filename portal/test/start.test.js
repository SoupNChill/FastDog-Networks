import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { startState, loginDestination } from '../public/js/start-state.js';
import { fixture, tids } from './helpers.js';

const host = (status, connected = false) => ({ hostname: 'app.example.test', status, agent: { connected } });
test('first-run progress covers empty, added, connected, live and suspended claims', () => {
  for (const [records, steps, live] of [
    [[], ['current', 'next', 'next'], false],
    [[host('pending')], ['done', 'current', 'next'], false],
    [[host('active')], ['done', 'current', 'next'], false],
    [[host('pending', true)], ['done', 'done', 'current'], false],
    [[host('active', true)], ['done', 'done', 'done'], true],
    [[host('suspended')], ['done', 'current', 'next'], false],
  ]) assert.deepEqual(startState(records), { steps, live });
  assert.equal(startState([host('active'), host('pending', true)]).live, false);
  assert.equal(startState([host('pending'), host('active', true)]).live, true);
});

test('login sends tenants without live hosts to Start and preserves Website for live hosts', async () => {
  const source = await readFile(new URL('../public/js/login.js', import.meta.url), 'utf8');
  for (const records of [[], [host('pending')], [host('active')], [host('active', true)], null]) {
    let submit, destination;
    const api = async (path) => {
      if (path === '/api/login') return { ok: true };
      assert.equal(path, '/api/hostnames');
      if (!records) throw new Error('unavailable');
      return { hostnames: records };
    };
    const context = vm.createContext({ URLSearchParams, api, loginDestination, init: async () => {}, message() {},
      location: { hash: '', pathname: '/login', assign(path) { destination = path; } }, history: { replaceState() {} },
      form(id, callback) { if (id === '#login') submit = callback; } });
    await vm.runInContext(`(async () => { ${source.replace(/^import .*;\n/gm, '')} })()`, context);
    await submit({});
    assert.equal(destination, records?.some((item) => item.status === 'active' && item.agent.connected) ? '/hostname' : '/start');
  }
});

test('Start is served to signed-in tenants and status cannot be influenced by another tenant', async (t) => {
  const f = await fixture(t);
  const a = await f.seed(0), b = await f.seed(1);
  f.records.set(`${tids[1]}:app.example.test`, host('active', true));
  assert.equal((await f.client.call('/start')).status, 302);
  const page = await a.client.call('/start');
  assert.equal(page.status, 200);
  assert.match(page.text, /Put your site on FastDog in 3 steps/);
  assert.match(page.text, /TXT record/);
  const own = await a.client.call(`/api/hostnames?tenant_id=${tids[1]}`);
  assert.deepEqual(own.data.hostnames, []);
  assert.equal(await loginDestination(async () => own.data), '/start');
  assert.equal(await loginDestination(async () => (await b.client.call('/api/hostnames')).data), '/hostname');
  assert.equal((await a.client.call('/api/hostnames/app.example.test/agent')).status, 404);
});

test('Start renders textual progress and aria-current, refreshes, and stops on pagehide', async () => {
  const source = await readFile(new URL('../public/js/start.js', import.meta.url), 'utf8');
  const items = Array.from({ length: 3 }, () => ({ dataset: {}, attrs: {}, marker: null,
    removeAttribute(key) { delete this.attrs[key]; }, setAttribute(key, value) { this.attrs[key] = value; },
    querySelector() { return this.marker; }, prepend(marker) { this.marker = marker; } }));
  let refresh, stop, notice, cleared = false;
  let records = [];
  const context = vm.createContext({ startState, init: async () => {}, api: async () => ({ hostnames: records }),
    message(text) { notice = text; }, document: { querySelectorAll: () => items, createElement: () => ({}) },
    window: { addEventListener(name, fn) { assert.equal(name, 'pagehide'); stop = fn; } },
    setTimeout(fn, delay) { assert.equal(delay, 10000); refresh = fn; return 1; }, clearTimeout() { cleared = true; } });
  await vm.runInContext(`(async () => { ${source.replace(/^import .*;\n/gm, '')} })()`, context);
  assert.equal(items[0].attrs['aria-current'], 'step');
  assert.deepEqual(items.map((item) => item.marker.textContent), ['1 · Current', '2 · Next', '3 · Next']);
  records = [host('active', true)];
  await refresh();
  assert.ok(items.every((item) => !item.attrs['aria-current'] && item.dataset.state === 'done'));
  assert.match(notice, /is live/);
  stop();
  assert.ok(cleared);
});
