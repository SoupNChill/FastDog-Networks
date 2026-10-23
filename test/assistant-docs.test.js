import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('llms.txt gives assistants a start-here flow with the key facts', () => {
  const text = read('site/llms.txt');
  assert.ok(text.split('\n').length < 170);
  assert.ok(text.indexOf('## Start here') < text.indexOf('## Concepts'));
  for (const needle of ['fdak_', 'fdct_', '-H @/', 'umask 077', '.header', 'DNS only', 'every 30 seconds',
    'txt_not_found', '24 hours', '409 not_active', 'runs it themselves', '3 commands per hostname per day', 'certificate_missing',
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
    'umask 077; curl -sS -w', 'docker info', 'root-equivalent', 'ALREADY have docker access', 'docker inspect', '--cap-drop ALL','--network host', 'host.docker.internal', 'ENV_FILE', '"platform":"docker"', 'Never use curl -v or --trace',
    'chmod 600', 'reserved_hostname', 'never sees 409 hostname_limit_reached', 'not on the server where the app runs', 'checks?', 'agent_version (may be null)', 'do not retry variations', 'HOME may differ', 'Use the port or origin the user already gave you']) {
    assert.ok(text.includes(needle), `llms.txt mentions ${needle}`);
  }
  const endpointLines = text.split('\n').filter((l) => /\/api\/(connect\/)?v1\//.test(l) && !l.startsWith('The API origin') && !l.startsWith('Once the hostname'));
  assert.ok(endpointLines.length > 8);
  for (const l of endpointLines) {
    assert.match(l, /https:\/\/portal\.DOMAIN\/api\//, `endpoint uses the portal origin: ${l.slice(0, 80)}`);
    assert.doesNotMatch(l, /https:\/\/(?![A-Za-z])|\{portal\}/, 'no empty host or {portal}');
    assert.doesNotMatch(l, /https:\/\/DOMAIN\/api/, 'never the bare DOMAIN');
  }
  assert.ok(text.includes('"format":"env"'));
  assert.ok(text.includes('the ONLY new command needing approval is the single docker run'));
  assert.ok(text.indexOf('Before any DNS work') < text.indexOf('1. POST'));
  assert.doesNotMatch(text, /fastdog-run\.sh|python3/);
  assert.doesNotMatch(text, /"\$KEY"/, 'no command that expands a secret variable');
  assert.doesNotMatch(text, /If the user pastes the key, write it/);
});

test('human docs have an AI assistant section with the same guidance', () => {
  const html = read('site/docs/index.html');
  const section = html.slice(html.indexOf('id="ai-assistant"'), html.indexOf('id="api-keys"'));
  for (const needle of ['curl -H @/absolute/path/HOSTNAME.header', 'accept only one plain command per call', 'automatically on the first HTTPS request', 'per hostname', 'HISTCONTROL=ignorespace', 'revoke the key', 'right after connecting', 'umask 077; curl -sS -w', '<code>--trace</code>', 'you save the', 'approve the assistant running it once', 'umask 077', 'chmod 600', 'not on the server where the app runs', 'docker info', '--network host', 'the ONLY new command needing approval', '24 hours', '3 new commands a day', 'DNS only', '/llms.txt']) {
    assert.ok(section.includes(needle), `docs section mentions ${needle}`);
  }
  assert.doesNotMatch(html, /issued on the first visit/);
  for (const needle of ['400 reserved_hostname', 'gets 403 for any other website', 'may be null']) assert.ok(html.includes(needle), `docs mention ${needle}`);
  assert.ok(html.includes('if you fetched the guide from <code>https://DOMAIN/llms.txt</code>, the API origin is <code>https://portal.DOMAIN</code> (never the bare <code>DOMAIN</code>)'));
  assert.doesNotMatch(html, /\{portal\}|https:\/\/(?![A-Za-z])/);
});

for (const path of ['site/llms.txt', 'docs/TENANT_API.md', 'site/docs/index.html']) {
  test(`${path} describes curl approval, fresh env paths and immediate user cleanup`, () => {
    const text = read(path).replaceAll('&quot;', '"');
    for (const needle of ['"format":"env"', 'http://127.0.0.1:PORT',
      'PORT is the app port the user gave', 'list in one message', 'curl calls to https://portal.DOMAIN',
      'env-file fetch and status polling', 'once/up front',
      'the ONLY new command needing approval is the single docker run',
      'only on a reconnect name conflict', 'HOSTNAME.agent-2.env rather than overwrite it',
      'As soon as agent.connected is true, immediately',
      'rm -f /home/USER/.config/fastdog/app.example.com.agent.env', 'absolute path you used',
      'Docker stored the env at create time', 'single-use bootstrap code', 'needs a new agent image']) {
      assert.ok(text.includes(needle), `${path} mentions ${needle}`);
    }
    assert.doesNotMatch(text, /fastdog-run\.sh/);
    for (const line of text.split('\n').filter(line => line.includes('curl'))) {
      assert.doesNotMatch(line, /127\.0\.0\.1:3000/);
    }
  });
}
