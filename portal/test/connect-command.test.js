import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createApp } from '../src/app.js';
import { fixture } from './helpers.js';

test('connect command gets the configured edge URL and tracks whether a command was issued', async (t) => {
  const f = await fixture(t, { edgeUrl: 'https://edge.example.test' });
  const a = await f.seed(0), b = await f.seed(1);
  const path = '/api/hostnames/app.example.test';
  assert.equal((await a.client.call('/api/hostnames', 'POST', { hostname: 'app.example.test' })).status, 201);
  const verified = await a.client.call(`${path}/verify`, 'POST');
  assert.equal(verified.data.credential.agent_env.EDGE_HTTP_URL, 'https://edge.example.test');
  assert.equal(verified.data.credential.agent_env.EDGE_WS_URL, 'wss://edge.example.test/_fastdog/tunnel');
  assert.equal(verified.data.credential.agent_env.AGENT_LOCAL_UPSTREAM, undefined);
  const issued = async (client) => (await client.call('/api/hostnames')).data.hostnames.map((h) => h.command_issued);
  assert.deepEqual(await issued(a.client), [false]);
  const rotated = await a.client.call(`${path}/rotate`, 'POST');
  assert.equal(rotated.data.credential.agent_env.EDGE_HTTP_URL, 'https://edge.example.test');
  assert.deepEqual(await issued(a.client), [true]);
  assert.deepEqual(await issued(b.client), []);
  assert.equal((await a.client.call(path, 'DELETE')).status, 200);
  assert.equal((await a.client.call('/api/hostnames', 'POST', { hostname: 'app.example.test' })).status, 201);
  assert.deepEqual(await issued(a.client), [false]);
});

test('without an edge URL no edge address is invented; bad edge URLs refuse to start', async (t) => {
  const f = await fixture(t);
  const a = await f.seed(0);
  await a.client.call('/api/hostnames', 'POST', { hostname: 'app.example.test' });
  const verified = await a.client.call('/api/hostnames/app.example.test/verify', 'POST');
  assert.equal(verified.data.credential.agent_env.EDGE_HTTP_URL, undefined);
  for (const edgeUrl of ['http://edge.example.test', 'https://edge.example.test/path', 'not a url', "https://edge.example.test'"]) {
    assert.throws(() => createApp({ dataDir: f.dataDir, edge: {}, config: { origin: 'https://portal.example.test', edgeUrl } }), /Invalid public edge URL/);
  }
});

test('Connect page asks where the app runs, has one primary action and an inline check result', () => {
  const html = readFileSync(new URL('../public/connect.html', import.meta.url), 'utf8');
  const view = readFileSync(new URL('../public/js/agent-view.js', import.meta.url), 'utf8');
  assert.match(html, /<label for="origin">Where does your app run on that server\?<\/label>/);
  assert.match(html, /must already be running on that server/);
  assert.doesNotMatch(html + view, /Show connection|placeholders/i);
  assert.match(html, /id="check-agent"[^]*id="connection" role="status" aria-live="polite"[^]*id="checked-at"/);
  assert.match(view, /Get my connect command/);
  assert.match(view, /warning\.hidden = !issued/);
  assert.match(view, /Checked at /);
  const css = readFileSync(new URL('../public/css/connect.css', import.meta.url), 'utf8');
  assert.match(css, /prefers-reduced-motion: reduce/);
});
