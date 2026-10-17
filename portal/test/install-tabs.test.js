import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import vm from 'node:vm';
import { connectionCommand as buildCommand, showCredential, agentSuffix, defaultChoice, validateOrigin } from '../public/js/agent-view.js';
import { agentSuffix as agentSuffixServer } from '../src/connect-command.js';
const connectionCommand = (env, platform) => buildCommand(env, platform, 'https://portal.example.test');
const env = { AGENT_TOKEN: "private'fixture", AGENT_HOSTNAME: 'app.example.test', EDGE_HTTP_URL: 'https://edge.example.test', AGENT_LOCAL_UPSTREAM: 'http://127.0.0.1:8080' };
test('Linux installer receives quoted token, edge, hostname and origin', () => {
  const command = connectionCommand(env, 'linux');
  assert.match(command, /^curl -fsSL 'https:\/\/portal\.example\.test\/install\/agent.sh' -o \/tmp\/fastdog-agent-install.sh && sudo /);
  assert.ok(command.includes("FASTDOG_AGENT_TOKEN='private'\\''fixture'"));
  for (const [flag, value] of [['edge', env.EDGE_HTTP_URL], ['hostname', env.AGENT_HOSTNAME], ['origin', env.AGENT_LOCAL_UPSTREAM]]) assert.ok(command.includes(`--${flag} '${value}'`));
});
test('Docker command uses host networking, a stable name and replaces the old agent; macOS keeps the Desktop form', () => {
  const docker = connectionCommand(env, 'docker');
  assert.match(docker, /^umask 077; docker pull \S+ && printf/);
  const suffix = agentSuffix('app.example.test');
  assert.match(suffix, /^app-example-test-[0-9a-f]{10}$/);
  assert.equal(suffix, agentSuffixServer('app.example.test'), 'browser and server derive the same name');
  for (const host of ['a-b.example.test', 'a.b-example.test', 'x'.repeat(60) + '.example.test', 'ÄÖ.example.test']) assert.equal(agentSuffix(host), agentSuffixServer(host), host);
  assert.notEqual(agentSuffix('a-b.example.test'), agentSuffix('a.b-example.test'));
  assert.ok(docker.includes(`{ docker rm -f fastdog-agent-${suffix} >/dev/null 2>&1; true; } && docker run -d --name fastdog-agent-${suffix} --network host --cap-drop ALL --security-opt no-new-privileges --restart unless-stopped --env-file fastdog-agent-${suffix}.env `));
  assert.ok(docker.indexOf('docker pull') < docker.indexOf('printf') && docker.indexOf('printf') < docker.indexOf('docker rm -f') && docker.indexOf('docker rm -f') < docker.indexOf('docker run'), 'pull before the token file is written');
  assert.ok(docker.includes(`> fastdog-agent-${suffix}.env && chmod 600 fastdog-agent-${suffix}.env`));
  assert.doesNotMatch(connectionCommand(env, 'macos'), /--network host|docker rm/);
  assert.doesNotMatch(docker, /\$/, 'no shell expansion of secrets');
  assert.ok(docker.includes("'AGENT_TOKEN=private'\\''fixture'"));
});
test('Docker and macOS share a pinned command; Windows uses PowerShell quoting', () => {
  const docker = connectionCommand(env, 'docker');
  for (const platform of ['docker', 'macos', 'windows']) {
    const command = connectionCommand(env, platform);
    assert.match(command, /docker run .*--env-file fastdog-agent[\w.-]*\.env/);
    assert.doesNotMatch(command.slice(command.indexOf('docker run')), /private| -e /);
  }
  assert.match(docker, /ghcr.io\/soupnchill\/fastdog-agent:0.1.2@sha256:[0-9a-f]{64}$/);
  assert.match(docker, /EDGE_WS_URL=wss:\/\/edge.example.test\/_fastdog\/tunnel/);
  assert.ok(connectionCommand(env, 'windows').includes("'AGENT_TOKEN=private''fixture'"));
  assert.match(connectionCommand(env, 'windows'), /^Set-Content /);
  assert.equal(connectionCommand({ AGENT_TOKEN: 'fixture', AGENT_HOSTNAME: 'app.example.test' }, 'linux'), null);
});
test('install tabs start with Docker and support keyboard navigation and credential clearing', () => {
  const previous = { document: globalThis.document, window: globalThis.window };
  const element = () => ({ children: [], attrs: {}, handlers: {}, setAttribute(k,v) { this.attrs[k]=v; }, addEventListener(k,v) { this.handlers[k]=v; }, replaceChildren(...items) { this.children=items; }, append(item) { this.children.push(item); }, focus() { this.focused=true; } });
  const elements = new Map(); let clear;
  globalThis.document = { createElement: element, querySelector(key) { if (!elements.has(key)) elements.set(key, element()); return elements.get(key); } };
  globalThis.window = { location: { origin: 'https://portal.example.test' }, addEventListener(name, callback) { clear = callback; } };
  try {
    showCredential({ agent_env: env });
    const tabs = elements.get('#command-tabs').children;
    assert.equal(tabs[0].textContent, 'Docker (recommended)');
    assert.equal(tabs[1].textContent, 'Linux installer (sudo)');
    assert.equal(tabs[0].attrs['aria-selected'], 'true');
    assert.match(elements.get('#command').textContent, /--network host/);
    assert.equal(tabs[1].tabIndex, -1);
    tabs[0].handlers.keydown({ key: 'End', preventDefault() {} });
    assert.equal(tabs[3].attrs['aria-selected'], 'true');
    assert.equal(tabs[3].focused, true);
    assert.match(elements.get('#command-help').textContent, /Untested.*Docker Desktop.*PowerShell/);
    assert.match(elements.get('#command-help').textContent, /Keep fastdog-agent.env private/);
    tabs[3].handlers.keydown({ key: 'ArrowRight', preventDefault() {} });
    assert.equal(tabs[0].attrs['aria-selected'], 'true');
    clear();
    assert.equal(elements.get('#command').textContent, '');
  } finally { Object.assign(globalThis, previous); }
});
test('root domain hints cover two-part suffixes and include the actual attach target', () => {
  const source = readFileSync(new URL('../public/js/hostname.js', import.meta.url), 'utf8');
  const context = vm.createContext({});
  vm.runInContext(source.slice(source.indexOf('export function rootDomainHelp'), source.indexOf('function updateRootHelp')).replace('export ', ''), context);
  for (const domain of ['example.com', 'example.test', 'example.co.uk', 'example.com.au']) {
    const hint = context.rootDomainHelp(domain, 'edge.example.test');
    assert.ok(hint.includes(`www.${domain}`));
    assert.match(hint, /point it at edge.example.test\./);
    assert.match(hint, /ALIAS\/ANAME\/CNAME flattening/);
  }
  for (const domain of ['', 'app.example.test', 'www.example.co.uk', 'co.uk']) assert.equal(context.rootDomainHelp(domain), '');
});

test('Docker shell command writes private exact values without passing the token to Docker', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'portal-command-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'docker'), '#!/bin/sh\nprintf "%s\\n" "$@" > docker-args\n', { mode: 0o700 });
  const result = spawnSync('/bin/bash', ['-c', connectionCommand(env, 'docker')], {
    cwd: dir, encoding: 'utf8', env: { PATH: `${dir}:/usr/bin:/bin` },
  });
  assert.equal(result.status, 0, result.stderr);
  const file = join(dir, `fastdog-agent-${agentSuffix(env.AGENT_HOSTNAME)}.env`);
  const saved = readFileSync(file, 'utf8');
  for (const [key, value] of Object.entries(env)) assert.ok(saved.includes(`${key}=${value}\n`));
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.doesNotMatch(readFileSync(join(dir, 'docker-args'), 'utf8'), /private/);
});

test('rendered commands never contain angle-bracket placeholders on any tab', () => {
  for (const origin of ['http://127.0.0.1:5000', 'http://localhost:3000', 'http://192.168.1.20:8080', 'http://host.docker.internal:8000']) {
    for (const platform of ['linux', 'docker', 'macos', 'windows']) {
      const command = buildCommand({ ...env, AGENT_LOCAL_UPSTREAM: undefined }, platform, 'https://portal.example.test', origin);
      assert.ok(command, `${platform} ${origin}`);
      assert.doesNotMatch(command, /</);
      assert.doesNotMatch(command.replace(/ > fastdog-agent[\w.-]*\.env /, ' ').replace(' >/dev/null 2>&1;', ';'), />/);
      assert.ok(command.includes('https://edge.example.test'));
      assert.ok(command.includes(origin));
    }
  }
  for (const missing of [{ EDGE_HTTP_URL: undefined }, { AGENT_TOKEN: undefined }, { AGENT_LOCAL_UPSTREAM: 'not a url' }]) {
    for (const platform of ['linux', 'docker', 'macos', 'windows']) assert.equal(buildCommand({ ...env, ...missing }, platform, 'https://portal.example.test'), null);
  }
});
test('default tab is Docker on Linux and the Desktop tab on Mac and Windows', () => {
  assert.equal(defaultChoice({ platform: 'Linux x86_64', userAgent: 'Mozilla/5.0 (X11; Linux x86_64)' }), 0);
  assert.equal(defaultChoice({ platform: 'MacIntel', userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)' }), 2);
  assert.equal(defaultChoice({ platform: 'Win32', userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }), 3);
  assert.equal(defaultChoice({ userAgent: 'Mozilla/5.0 (Windows NT 10.0)' }), 3);
  assert.equal(defaultChoice(undefined), 0);
});
test('link-local origins are refused with a clear error', () => {
  for (const input of ['http://169.254.169.254:80', '169.254.1.1:80', 'http://[fe80::1]:80', 'http://[feb0::1]:80', 'http://[fd00:ec2::254]:80', '[fd00:ec2::254]:80', 'http://[::ffff:169.254.169.254]:80']) {
    assert.match(validateOrigin(input).error, /Link-local/, input);
    assert.equal(buildCommand({ ...env, AGENT_LOCAL_UPSTREAM: undefined }, 'docker', 'https://portal.example.test', input), null);
  }
});
test('origin field accepts local app addresses and explains bad ones', async () => {
  const { validateOrigin } = await import('../public/js/agent-view.js');
  for (const [input, value] of [['http://127.0.0.1:5000', 'http://127.0.0.1:5000'], ['127.0.0.1:3000', 'http://127.0.0.1:3000'], [' http://localhost:8080/ ', 'http://localhost:8080'],
    ['https://10.0.0.5:8443', 'https://10.0.0.5:8443'], ['http://app:8000', 'http://app:8000'], ['http://[::1]:5000', 'http://[::1]:5000']]) assert.equal(validateOrigin(input).value, value, input);
  for (const input of ['', 'ftp://127.0.0.1:21', 'http://127.0.0.1', 'http://127.0.0.1:5000/path', "http://127.0.0.1:5000'; rm -rf /", 'http://example.com:80', 'http://u:p@127.0.0.1:1', 'http://127.0.0.1:70000', '<LOCAL_UPSTREAM>']) {
    assert.ok(validateOrigin(input).error, input);
  }
});
