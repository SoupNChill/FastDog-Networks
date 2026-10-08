import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from '../src/server.js';
import { decide } from '../src/engine/jev.js';
import { createRateLimiter } from '../src/middleware/rateLimit.js';

async function withServer(fn, { rateLimit } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'verdict-test-'));
  const app = await createApp({
    keyFile: join(dir, 'keys.json'),
    usageFile: join(dir, 'usage.json'),
    rateLimit,
  });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  try {
    await fn(`http://127.0.0.1:${server.address().port}`, dir);
  } finally {
    await new Promise(resolve => server.close(resolve));
    await rm(dir, { recursive: true, force: true });
  }
}

const post = (url, body, key) => fetch(url, {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    ...(key ? { authorization: `Bearer ${key}` } : {}),
  },
  body: JSON.stringify(body),
});

test('bootstrap, auth, decision and usage', async () => withServer(async base => {
  assert.equal((await fetch(`${base}/health`)).status, 200);
  assert.equal((await post(`${base}/v1/decide`, { path: '/login' })).status, 401);
  const created = await post(`${base}/v1/keys`, { name: 'test' });
  assert.equal(created.status, 201);
  const { key } = await created.json();
  assert.equal((await post(`${base}/v1/keys`, {})).status, 401);
  const response = await post(`${base}/v1/decide`, { path: '/login', signals: ['headless'] }, key);
  assert.equal(response.status, 200);
  const decision = await response.json();
  assert.equal(decision.action, 'challenge');
  assert.ok(decision.request_id);
  const usage = await (await fetch(`${base}/v1/usage`, { headers: { authorization: `Bearer ${key}` } })).json();
  assert.equal(usage.decisions, 1);
  assert.equal(usage.period, 'persistent');
}));

test('reject invalid decide bodies', async () => withServer(async (base) => {
  const created = await post(`${base}/v1/keys`, { name: 'validation' });
  const { key } = await created.json();
  const bad = await post(`${base}/v1/decide`, ['not', 'an', 'object'], key);
  assert.equal(bad.status, 400);
  const body = await bad.json();
  assert.equal(body.error, 'invalid_body');
}));

test('rate limit decide per key', async () => withServer(async (base) => {
  const created = await post(`${base}/v1/keys`, { name: 'rl' });
  const { key } = await created.json();
  const statuses = [];
  for (let i = 0; i < 3; i += 1) {
    statuses.push((await post(`${base}/v1/decide`, { path: '/x' }, key)).status);
  }
  assert.deepEqual(statuses, [200, 200, 429]);
}, { rateLimit: createRateLimiter({ windowMs: 60_000, max: 2 }) }));

test('usage persists across app reload', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'verdict-persist-'));
  const keyFile = join(dir, 'keys.json');
  const usageFile = join(dir, 'usage.json');
  try {
    const app1 = await createApp({ keyFile, usageFile, rateLimit: createRateLimiter({ max: 1000 }) });
    const server1 = app1.listen(0, '127.0.0.1');
    await new Promise(resolve => server1.once('listening', resolve));
    const base1 = `http://127.0.0.1:${server1.address().port}`;
    const { key } = await (await post(`${base1}/v1/keys`, { name: 'persist' })).json();
    assert.equal((await post(`${base1}/v1/decide`, { path: '/login' }, key)).status, 200);
    await new Promise(resolve => server1.close(resolve));

    const raw = JSON.parse(await readFile(usageFile, 'utf8'));
    assert.equal(Object.values(raw)[0].decisions, 1);

    const app2 = await createApp({ keyFile, usageFile, rateLimit: createRateLimiter({ max: 1000 }) });
    const server2 = app2.listen(0, '127.0.0.1');
    await new Promise(resolve => server2.once('listening', resolve));
    const base2 = `http://127.0.0.1:${server2.address().port}`;
    const usage = await (await fetch(`${base2}/v1/usage`, { headers: { authorization: `Bearer ${key}` } })).json();
    assert.equal(usage.decisions, 1);
    await new Promise(resolve => server2.close(resolve));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('Jev errors fall back to heuristic', async () => {
  const result = await decide({ path: '/login' }, { apiKey: 'test', fetchImpl: async () => ({ ok: false, status: 503 }) });
  assert.equal(result.engine, 'local_heuristic_v2');
});

test('Jev Choice request and response match System One schema', async () => {
  const result = await decide({ path: '/login' }, {
    apiKey: 'test',
    fetchImpl: async (_url, options) => {
      const body = JSON.parse(options.body);
      assert.deepEqual(Object.keys(body.questions.verdict.criteria), ['allow', 'challenge', 'block']);
      return { ok: true, json: async () => ({ answers: { verdict: { type: 'choice', choice: 'challenge', confidence: 0.82 } } }) };
    },
  });
  assert.equal(result.engine, 'typesafe_jev');
  assert.equal(result.action, 'challenge');
});
