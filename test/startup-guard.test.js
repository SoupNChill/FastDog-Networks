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
