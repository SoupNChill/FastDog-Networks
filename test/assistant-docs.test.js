import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('llms.txt gives assistants a start-here flow with the key facts', () => {
  const text = read('site/llms.txt');
  assert.ok(text.split('\n').length < 170);
  assert.ok(text.indexOf('## Start here') < text.indexOf('## Concepts'));
  for (const needle of ['fdak_', 'fdct_', '-H @/', 'umask 077', 'auth.header', 'DNS only', 'every 30 seconds',
    'txt_not_found', '24 hours', '409 not_active', 'must not run it', '3 commands per hostname per day', 'certificate_missing',
    'agent.origin_reachable', 'Test it', '403 forbidden', 'contact FastDog support']) {
    assert.ok(text.includes(needle), `llms.txt mentions ${needle}`);
  }
  assert.doesNotMatch(text, /issued on the first visit/);
  assert.match(text, /^0\. One-time key setup \(the user runs this, or approves it once\)/m);
  for (const needle of ["mkdir -p ~/.config/fastdog && (umask 077; printf 'Authorization: Bearer %s\\n' '<paste key>' > ~/.config/fastdog/auth.header)",
    '--create-file-mode 0600 -o /absolute/path/fastdog-connect.json', 'do not retry variations', 'HOME may differ', 'Use the port or origin the user already gave you']) {
    assert.ok(text.includes(needle), `llms.txt mentions ${needle}`);
  }
  assert.doesNotMatch(text, /"\$KEY"/, 'no command that expands a secret variable');
  assert.doesNotMatch(text, /If the user pastes the key, write it/);
});

test('human docs have an AI assistant section with the same guidance', () => {
  const html = read('site/docs/index.html');
  const section = html.slice(html.indexOf('id="ai-assistant"'), html.indexOf('id="api-keys"'));
  for (const needle of ['curl -H @/absolute/path', 'you save the', 'approve the assistant running it once', 'umask 077', '--create-file-mode 0600 -o /absolute/path/fastdog-connect.json', '24 hours', '3 new commands a day', 'DNS only', '/llms.txt']) {
    assert.ok(section.includes(needle), `docs section mentions ${needle}`);
  }
  assert.doesNotMatch(html, /issued on the first visit/);
});
