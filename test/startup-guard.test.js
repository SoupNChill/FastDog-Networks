import test from 'node:test';
import assert from 'node:assert/strict';
import { assertSafeStartup, DEFAULT_AGENT_TOKEN } from '../src/lib/startup-guard.js';

test('startup refuses an unset, blank or default AGENT_TOKEN', () => {
  assert.throws(() => assertSafeStartup({}), /must be set/);
  assert.throws(() => assertSafeStartup({ AGENT_TOKEN: '   ' }), /must be set/);
  assert.throws(() => assertSafeStartup({ AGENT_TOKEN: DEFAULT_AGENT_TOKEN }), /default/);
  assert.doesNotThrow(() => assertSafeStartup({ AGENT_TOKEN: 'x'.repeat(40) }));
});

test('edge binds to loopback unless EDGE_BIND is given explicitly', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../src/edge/server.js', import.meta.url), 'utf8');
  assert.match(src, /env\('EDGE_BIND', '127\.0\.0\.1'\)/);
  assert.match(src, /assertSafeStartup\(\)/);
});

test('development token override must be exactly 1', () => {
  for (const AGENT_TOKEN of [undefined, '', '   ', DEFAULT_AGENT_TOKEN]) {
    assert.doesNotThrow(() => assertSafeStartup({ AGENT_TOKEN, FASTDOG_ALLOW_DEV_TOKEN: '1' }));
    for (const FASTDOG_ALLOW_DEV_TOKEN of [undefined, '', '0', 'true']) {
      assert.throws(() => assertSafeStartup({ AGENT_TOKEN, FASTDOG_ALLOW_DEV_TOKEN }), /AGENT_TOKEN/);
    }
  }
});

test('edge process exits 1 for unsafe tokens, including test mode', async () => {
  const { spawnSync } = await import('node:child_process');
  for (const AGENT_TOKEN of [undefined, '', '   ', DEFAULT_AGENT_TOKEN]) {
    const env = { ...process.env, NODE_ENV: 'test', FASTDOG_ALLOW_DEV_TOKEN: '0' };
    if (AGENT_TOKEN === undefined) delete env.AGENT_TOKEN;
    else env.AGENT_TOKEN = AGENT_TOKEN;
    const result = spawnSync(process.execPath, ['src/edge/server.js'], { env, encoding: 'utf8', timeout: 5000 });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /AGENT_TOKEN must/);
    assert.doesNotMatch(result.stdout, /listening/);
    env.FASTDOG_ALLOW_DEV_TOKEN = '1';
    const allowed = spawnSync(process.execPath, ['src/edge/server.js'], { env, encoding: 'utf8', timeout: 5000 });
    assert.equal(allowed.status, 0, allowed.stderr);
  }
});
