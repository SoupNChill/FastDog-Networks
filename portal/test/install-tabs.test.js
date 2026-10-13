import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { connectionCommand as buildCommand, showCredential } from '../public/js/agent-view.js';
const connectionCommand = (env, platform) => buildCommand(env, platform, 'https://portal.example.test');
const env = { AGENT_TOKEN: "private'fixture", AGENT_HOSTNAME: 'app.example.test', EDGE_HTTP_URL: 'https://edge.example.test', AGENT_LOCAL_UPSTREAM: 'http://127.0.0.1:8080' };
test('Linux installer receives quoted token, edge, hostname and origin', () => {
  const command = connectionCommand(env, 'linux');
  assert.match(command, /^curl -fsSL 'https:\/\/portal\.example\.test\/install\/agent.sh' \| sudo bash -s -- /);
  assert.ok(command.includes("--token 'private'\\''fixture'"));
  for (const [flag, value] of [['edge', env.EDGE_HTTP_URL], ['hostname', env.AGENT_HOSTNAME], ['origin', env.AGENT_LOCAL_UPSTREAM]]) assert.ok(command.includes(`--${flag} '${value}'`));
});
test('Docker and macOS share a pinned command; Windows uses PowerShell quoting', () => {
  const docker = connectionCommand(env, 'docker');
  assert.equal(docker, connectionCommand(env, 'macos'));
  assert.match(docker, /ghcr.io\/soupnchill\/fastdog-agent:0.1.0$/);
  assert.match(docker, /EDGE_WS_URL=wss:\/\/edge.example.test\/_fastdog\/tunnel/);
  assert.ok(connectionCommand(env, 'windows').includes("-e 'AGENT_TOKEN=private''fixture'"));
  assert.match(connectionCommand(env, 'windows'), /^docker run /);
  assert.match(connectionCommand({ AGENT_TOKEN: 'fixture', AGENT_HOSTNAME: 'app.example.test' }, 'linux'), /--edge '<EDGE_HTTP_URL>'.*--origin '<LOCAL_UPSTREAM>'/);
});
test('install tabs start with Linux and support keyboard navigation and credential clearing', () => {
  const previous = { document: globalThis.document, window: globalThis.window };
  const element = () => ({ children: [], attrs: {}, handlers: {}, setAttribute(k,v) { this.attrs[k]=v; }, addEventListener(k,v) { this.handlers[k]=v; }, replaceChildren(...items) { this.children=items; }, append(item) { this.children.push(item); }, focus() { this.focused=true; } });
  const elements = new Map(); let clear;
  globalThis.document = { createElement: element, querySelector(key) { if (!elements.has(key)) elements.set(key, element()); return elements.get(key); } };
  globalThis.window = { location: { origin: 'https://portal.example.test' }, addEventListener(name, callback) { clear = callback; } };
  try {
    showCredential({ agent_env: env });
    const tabs = elements.get('#command-tabs').children;
    assert.equal(tabs[0].textContent, 'Linux (recommended)');
    assert.equal(tabs[0].attrs['aria-selected'], 'true');
    assert.equal(tabs[1].tabIndex, -1);
    tabs[0].handlers.keydown({ key: 'End', preventDefault() {} });
    assert.equal(tabs[3].attrs['aria-selected'], 'true');
    assert.equal(tabs[3].focused, true);
    assert.match(elements.get('#command-help').textContent, /Untested.*Docker Desktop.*PowerShell/);
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
