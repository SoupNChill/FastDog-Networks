import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { _resetForTests, registerAgent } from '../src/control/tunnels.js';
import { resetForTests } from '../src/lib/metrics.js';
import { canonicalPath, isNonCanonicalControlPath, isControlPath } from '../src/edge/control-path.js';

describe('control path canonicalisation', () => {
  it('collapses slashes, dots, dot-dot and decodes once', () => {
    assert.equal(canonicalPath('//_fastdog/metrics'), '/_fastdog/metrics');
    assert.equal(canonicalPath('/./_fastdog//metrics'), '/_fastdog/metrics');
    assert.equal(canonicalPath('/x/../_fastdog/metrics'), '/_fastdog/metrics');
    assert.equal(canonicalPath('/%2F_fastdog/metrics'), '/_fastdog/metrics');
    assert.equal(canonicalPath('/%252F_fastdog'), '/%2F_fastdog');
    assert.equal(canonicalPath('/_fastdog/%zz'), '/_fastdog/%zz');
  });
  it('flags only non-exact spellings as non-canonical', () => {
    for (const p of ['/_fastdog/metrics', '/_fastdog/tunnel?agentId=a', '/_fastdog/agents/register', '/_fastdog/dns/zones']) {
      assert.equal(isNonCanonicalControlPath(p), false, p);
    }
    for (const p of ['//_fastdog/metrics', '/_fastdog//metrics', '/./_fastdog/metrics', '/%2F_fastdog/metrics', '/_FASTDOG/metrics',
      '/x/../_fastdog/metrics', '/_fastdog/%6Detrics', '/_fastdog/x/../metrics', '\\_fastdog/metrics', '/_fastdog/./metrics?a=1']) {
      assert.equal(isNonCanonicalControlPath(p), true, p);
    }
    assert.equal(isNonCanonicalControlPath('/app/_fastdog/metrics'), false);
    assert.equal(isControlPath('/_fastdog'), true);
    assert.equal(isControlPath('/_fastdogs'), false);
  });
});

describe('edge refuses non-canonical /_fastdog paths on tenant hosts', () => {
  let server;
  let port;
  const HOST = 'tenant.example.test';

  before(async () => {
    _resetForTests();
    resetForTests();
    process.env.NODE_ENV = 'test';
    process.env.AGENT_TOKEN = 'test-token';
    const mod = await import('../src/edge/server.js');
    await new Promise((resolve) => mod.server.listen(0, '127.0.0.1', resolve));
    server = mod.server;
    port = server.address().port;
    registerAgent({ name: 't', hostname: HOST, localUpstream: 'http://127.0.0.1:9', token: 'test-token', expectedToken: 'test-token' });
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
    _resetForTests();
  });

  const raw = (path, headers = {}) => new Promise((resolve, reject) => {
    http.get({ hostname: '127.0.0.1', port, path, headers: { Host: HOST, ...headers } }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
    }).on('error', reject);
  });
  const metrics = async () => (await fetch(`http://127.0.0.1:${port}/_fastdog/metrics`, { headers: { 'x-fastdog-token': 'test-token' } })).json();

  it('answers 404 and never reaches the tunnel', async () => {
    const before = await metrics();
    for (const p of ['//_fastdog/metrics', '/_fastdog//metrics', '/./_fastdog/metrics', '/%2F_fastdog/metrics', '/_FASTDOG/metrics',
      '/x/../_fastdog/metrics', '/_fastdog/%6Detrics', '/_fastdog/nope', '/_fastdog']) {
      assert.equal(await raw(p), 404, p);
    }
    const after = await metrics();
    assert.equal(after.requestsProxied, before.requestsProxied);
    assert.equal(after.requestsTunnel, before.requestsTunnel);
  });

  it('exact control routes behave as before and ordinary paths still proxy', async () => {
    assert.equal(await raw('/_fastdog/metrics'), 401);
    assert.equal(await raw('/_fastdog/metrics', { 'x-fastdog-token': 'test-token' }), 200);
    const before = await metrics();
    assert.notEqual(await raw('/plain'), 404);
    assert.equal((await metrics()).requestsTunnel, before.requestsTunnel + 1);
  });
});
