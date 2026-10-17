import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('llms.txt gives assistants a start-here flow with the key facts', () => {
  const text = read('site/llms.txt');
  assert.ok(text.split('\n').length < 170);
  assert.ok(text.indexOf('## Start here') < text.indexOf('## Concepts'));
  for (const needle of ['fdak_', 'fdct_', '-H @/', 'umask 077', '.header', 'DNS only', 'every 30 seconds',
    'txt_not_found', '24 hours', '409 not_active', 'must not run it', '3 commands per hostname per day', 'certificate_missing',
    'agent.origin_reachable', 'Test it', '403 forbidden', 'contact FastDog support']) {
    assert.ok(text.includes(needle), `llms.txt mentions ${needle}`);
  }
  assert.doesNotMatch(text, /issued on the first visit/);
  assert.match(text, /^0\. One-time key setup \(the user runs this, or approves it once\)/m);
  assert.doesNotMatch(text, /auth\.header/, 'header file is named per hostname');
  assert.doesNotMatch(text, /\{portal\}|<portal>|https:\/\/ |off by default/, 'full API origin, no stripped placeholders');
  assert.doesNotMatch(text, /<[a-z-]+>/, 'no angle-bracket placeholders');
  for (const needle of ["mkdir -p ~/.config/fastdog && (umask 077; printf 'Authorization: Bearer %s\\n' 'PASTE_KEY' > ~/.config/fastdog/HOSTNAME.header)",
    'HOSTNAME.token.header', 'if you fetched this guide from https://DOMAIN/llms.txt, the API origin is https://portal.DOMAIN (never the bare DOMAIN', 'Write every endpoint as https://portal.DOMAIN/api/v1/... (and https://portal.DOMAIN/api/connect/v1/...)', 'POST https://portal.DOMAIN/api/v1/hostnames {',
    'accept only one plain command per call', 'issues the certificate automatically on the first HTTPS request', 'HISTCONTROL=ignorespace', 'delete the file, and to revoke the key', 'right after connecting',
    'curl 7.75+', 'run `umask 077` first', 'docker info', 'root-equivalent', 'ALREADY has docker access', 'rootless Docker', 'docker inspect', '--cap-drop ALL','--network host', 'host.docker.internal', 'docker ps --filter name=fastdog-agent', 'fastdog-agent-HOSTNAME-SLUG', '"platform":"docker"', 'Never use curl -v or --trace',
    '--create-file-mode 0600 -o /absolute/path/fastdog-connect.json', 'do not retry variations', 'HOME may differ', 'Use the port or origin the user already gave you']) {
    assert.ok(text.includes(needle), `llms.txt mentions ${needle}`);
  }
  const endpointLines = text.split('\n').filter((l) => /\/api\/(connect\/)?v1\//.test(l) && !l.startsWith('The API origin'));
  assert.ok(endpointLines.length > 8);
  for (const l of endpointLines) {
    assert.match(l, /https:\/\/portal\.DOMAIN\/api\//, `endpoint uses the portal origin: ${l.slice(0, 80)}`);
    assert.doesNotMatch(l, /https:\/\/(?![A-Za-z])|\{portal\}/, 'no empty host or {portal}');
    assert.doesNotMatch(l, /https:\/\/DOMAIN\/api/, 'never the bare DOMAIN');
  }
  const connect = text.slice(text.indexOf('## Connect command'));
  assert.ok(connect.indexOf('Docker is the default') < connect.indexOf('systemd installer command'), 'Docker before systemd');
  assert.ok(text.indexOf('-d \'{"origin":"http://127.0.0.1:3000","platform":"docker"}\'') > 0);
  assert.doesNotMatch(text, /"\$KEY"/, 'no command that expands a secret variable');
  assert.doesNotMatch(text, /If the user pastes the key, write it/);
});

test('human docs have an AI assistant section with the same guidance', () => {
  const html = read('site/docs/index.html');
  const section = html.slice(html.indexOf('id="ai-assistant"'), html.indexOf('id="api-keys"'));
  for (const needle of ['curl -H @/absolute/path/HOSTNAME.header', 'accept only one plain command per call', 'automatically on the first HTTPS request', 'per hostname', 'HISTCONTROL=ignorespace', 'revoke the key', 'right after connecting', 'curl 7.75 or newer', 'umask 077</code> first', '<code>--trace</code>', 'you save the', 'approve the assistant running it once', 'umask 077', '--create-file-mode 0600 -o /absolute/path/fastdog-connect.json', 'docker info', '--network host', 'docker ps --filter name=fastdog-agent', '24 hours', '3 new commands a day', 'DNS only', '/llms.txt']) {
    assert.ok(section.includes(needle), `docs section mentions ${needle}`);
  }
  assert.doesNotMatch(html, /issued on the first visit/);
  assert.ok(html.includes('if you fetched the guide from <code>https://DOMAIN/llms.txt</code>, the API origin is <code>https://portal.DOMAIN</code> (never the bare <code>DOMAIN</code>)'));
  assert.doesNotMatch(html, /\{portal\}|https:\/\/(?![A-Za-z])/);
});
