import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { normalizeHostname } from '../src/hostname.js';
import { guideStep, renderGuide } from '../public/js/guide.js';

const source = await readFile(new URL('../public/js/hostname.js', import.meta.url), 'utf8');
function client(extra = {}) {
  const context = vm.createContext({ URL, ...extra });
  // Exercise the exported helpers without starting authenticated page initialization.
  vm.runInContext(source.slice(source.indexOf('export function prepareHostname'), source.indexOf('function displayCredential'))
    .replaceAll('export ', ''), context);
  return context;
}
test('website entry cleans pasted links and case while rejecting malformed names', () => {
  const { prepareHostname } = client();
  for (const input of [' https://App.Example.COM./welcome?q=1 ', 'APP.EXAMPLE.COM.', 'app.example.com/path']) {
    const result = prepareHostname(input);
    assert.equal(result.hostname, 'app.example.com');
    assert.equal(result.changed, true);
  }
  assert.equal(prepareHostname('example.com').hostname, 'example.com');
  assert.equal(prepareHostname('bücher.example.com').hostname, 'xn--bcher-kva.example.com');
  for (const [input, message] of [['app .example.com', /spaces/], ['website', /dot/], [`${'a'.repeat(64)}.example.com`, /too long/], ['app.example.com:80', /port/], ['*.example.com', /wildcard/], ['127.0.0.1', /domain name/], ['a..example.com', /valid endings/], ['app.example.com..', /valid endings/]]) {
    assert.throws(() => prepareHostname(input), message);
  }
});
test('server validation explains errors and preserves error codes and URL rejection', () => {
  for (const [input, message] of [['app .example.com', /spaces/], ['website', /dot/], [`${'a'.repeat(64)}.example.com`, /too long/], ['https://app.example.com/path', /without https/], ['app.example.com:80', /without https/], ['-app.example.com', /start and end/]]) {
    assert.throws(() => normalizeHostname(input), (error) => error.code === 'invalid_hostname' && message.test(error.message));
  }
  assert.equal(normalizeHostname(' Example.COM. '), 'example.com');
});
test('guide progresses only from existing claim and agent states', () => {
  assert.equal(guideStep(), 1);
  assert.equal(guideStep({ status: 'pending', agent: { connected: true } }), 2);
  assert.equal(guideStep({ status: 'suspended' }), 2);
  assert.equal(guideStep({ status: 'active' }), 3);
  assert.equal(guideStep({ status: 'active', agent: { connected: false } }), 3);
  assert.equal(guideStep({ status: 'active' }, { connected: true }), 4);
});
test('guide renders four ordered steps with an accessible current step', () => {
  const previous = globalThis.document;
  const element = () => ({ children: [], attributes: {}, append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = items; }, setAttribute(key, value) { this.attributes[key] = value; } });
  globalThis.document = { createElement: element };
  try {
    const container = element();
    renderGuide(container, { hostname: 'app.example.com', status: 'active' }, { connected: false });
    assert.equal(container.children[1].textContent, 'Step 3 of 4: Connect your server');
    assert.equal(container.children[2].children.length, 4);
    assert.equal(container.children[2].children[2].attributes['aria-current'], 'step');
    assert.match(container.children[2].children[0].textContent, /Done/);
  } finally { globalThis.document = previous; }
});
test('copy shows feedback and selects text when clipboard permission is denied or missing', async () => {
  for (const clipboard of [{ writeText: async () => {} }, { writeText: async () => { throw new Error('denied'); } }, undefined]) {
    let notice, focused = false, selected = false;
    const { copyFeedback } = client({ navigator: { clipboard }, message: (text) => { notice = text; }, document: { createRange: () => ({ selectNodeContents() { selected = true; } }) }, window: { getSelection: () => ({ removeAllRanges() {}, addRange() {} }) } });
    const control = {};
    await copyFeedback('record', control, { focus() { focused = true; } });
    if (control.textContent === 'Copied') assert.equal(notice, 'Copied.');
    else { assert.ok(focused && selected); assert.match(notice, /Copy action/); }
  }
});
test('hostname page supplies labelled guidance, mobile styles and support', async () => {
  const html = await readFile(new URL('../public/hostname.html', import.meta.url), 'utf8');
  assert.match(html, /href="\/css\/guide.css"/);
  assert.match(html, /<details class="hostname-help">\s*<summary>What's this\?<\/summary>/);
  assert.match(html, /aria-describedby="hostname-note message root-domain-help"/);
  assert.match(html, /mailto:\{\{SUPPORT_EMAIL\}\}/);
  assert.match(html, /Step 1 of 4/);
  assert.doesNotMatch(html, /01 \/ Hostname|routing and ownership records/);
});

test('hostname page restores pending setup and updates the guide from live agent checks', async () => {
  for (const state of ['empty', 'pending', 'active', 'connected', 'suspended']) {
    const elements = new Map();
    const make = () => ({ children: [], textContent: '', hidden: false, attributes: {}, append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = items; }, setAttribute(key, value) { this.attributes[key] = value; }, addEventListener() {} });
    const document = { createElement: make, querySelector(selector) { if (!elements.has(selector)) elements.set(selector, make()); return elements.get(selector); } };
    document.querySelector('#claim').hidden = true;
    const record = { hostname: 'app.example.com', status: ['connected', 'active'].includes(state) ? 'active' : state, dns: { cname: { type: 'CNAME', name: 'app.example.com', value: 'edge.example.com', ttl: 300 }, txt: { type: 'TXT', name: '_fastdog-challenge.app.example.com', value: 'proof', ttl: 300 } } };
    const calls = [], timers = [], guides = [];
    let stopped;
    const context = vm.createContext({ URL, document, window: { addEventListener(name, fn) { if (name === 'pagehide') stopped = fn; } },
      request: async (path, method = 'GET') => { calls.push([path, method]); if (path.endsWith('/agent')) return { connected: state === 'connected' }; if (path === '/api/hostnames') return { hostnames: state === 'empty' ? [] : [record] }; return record; },
      init: async () => ({ email_verified: true }), form() {}, button: (label, callback) => ({ textContent: label, callback }), message() {}, showCredential() {},
      renderGuide: (container, item, agent) => guides.push(guideStep(item, agent)),
      setTimeout: (fn, ms) => { timers.push({ fn, ms }); return timers.length; }, clearTimeout() {},
    });
    await vm.runInContext(`(async () => { ${source.replace(/^import .*;\n/gm, '').replaceAll('export ', '')} })()`, context);
    assert.equal(guides.at(-1), { empty: 1, pending: 2, active: 3, connected: 4, suspended: 2 }[state]);
    if (state === 'pending') {
      assert.equal(document.querySelector('#claim').hidden, false);
      assert.equal(document.querySelector('#dns').children.length, 4);
      assert.ok(timers.some((timer) => timer.ms === 30000));
    }
    if (['active', 'connected'].includes(state)) {
      const row = document.querySelector('#hostnames').children[0];
      assert.match(row.children[1].textContent, state === 'connected' ? /^Live\./ : /Waiting for your server/);
      assert.equal(row.children[3].hidden, state !== 'connected');
      assert.ok(timers.some((timer) => timer.ms === 10000));
    }
    assert.ok(calls.every(([, method]) => method === 'GET'), 'loading the page never mutates a claim');
    stopped();
  }
});

test('support address comes from PORTAL_SUPPORT_EMAIL with a safe fallback', async () => {
  const { supportEmail, renderHtml } = await import('../src/static.js');
  assert.equal(supportEmail({ PORTAL_SUPPORT_EMAIL: 'help@example.test' }), 'help@example.test');
  assert.equal(supportEmail({ PORTAL_SUPPORT_EMAIL: '<script>@x' }), 'support@example.invalid');
  assert.equal(supportEmail({}), 'support@example.invalid');
  assert.equal(renderHtml(Buffer.from('a {{SUPPORT_EMAIL}} b'), { PORTAL_SUPPORT_EMAIL: 'help@example.test' }).toString(), 'a help@example.test b');
});
