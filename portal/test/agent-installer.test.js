import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createApp } from '../src/app.js';
import { temporary, listen, request, origin } from './helpers.js';
test('installer download is public plain text with exact bytes and a narrow route', async (t) => {
  const port = await listen(t, createApp({ dataDir: temporary(t), config: { origin } }));
  const response = await request(port, '/install/agent.sh');
  assert.equal(response.status, 200);
  assert.equal(response.headers['content-type'], 'text/plain; charset=utf-8');
  assert.equal(response.text, readFileSync(new URL('../../scripts/install-agent.sh', import.meta.url), 'utf8'));
  for (const path of ['/install/other.sh', '/install/../agent.sh', '/install/%2e%2e/agent.sh']) {
    assert.equal((await request(port, path)).status, 404);
  }
  assert.equal((await request(port, '/install/agent.sh', { method: 'POST' })).status, 405);
  assert.equal((await request(port, '/connect')).status, 302);
});
