import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { normalizeDomain } from '../src/service.js';

const script = readFileSync(new URL('../../site/js/domain-search.js', import.meta.url), 'utf8');
// Minimal DOM boundary: execute the real browser script with mocked fetch, never network.
class Element {
  constructor(tag = 'div') { this.tag = tag; this.children = []; this.attributes = {}; this.hidden = true; this.value = ''; }
  set textContent(value) { this.text = value; this.children = []; }
  get textContent() { return (this.text || '') + this.children.map((child) => child.textContent).join(' '); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  setAttribute(key, value) { this.attributes[key] = value; }
  removeAttribute(key) { delete this.attributes[key]; }
  addEventListener(type, listener) { this[type] = listener; }
  querySelector() { return this.button; }
  focus() { this.focused = true; }
}
function setup(response = { ok: true, status: 200, json: async () => ({ results: [] }) }) {
  const elements = Object.fromEntries(['domain-search-form', 'domain-name', 'domain-search-results', 'domain-search-fallback'].map((id) => [id, new Element()]));
  const form = elements['domain-search-form'];
  form.button = new Element('button');
  const requests = [];
  vm.runInNewContext(script, {
    document: { getElementById: (id) => elements[id], createElement: (tag) => new Element(tag) },
    fetch: async (...args) => { requests.push(args); if (response instanceof Error) throw response; return response; },
    AbortController, setTimeout, clearTimeout,
  });
  return { elements, form, requests, input: elements['domain-name'], results: elements['domain-search-results'],
    async submit(value) { elements['domain-name'].value = value; await form.submit({ preventDefault() {} }); },
  };
}
const descendants = (element) => element.children.flatMap((child) => [child, ...descendants(child)]);

test('enhancement and browser validation match the service, only normalized same-origin requests', async () => {
  const ui = setup();
  assert.equal(ui.form.hidden, false);
  assert.equal(ui.elements['domain-search-fallback'].hidden, true);
  for (const value of ['', '-a.com', 'a-.com', 'a..com', 'xn--abc.com', 'ab--cd.com', 'ex ample.com', 'example.zz', 'a.b.com', 'a'.repeat(64) + '.com', '<script>']) {
    assert.equal(normalizeDomain(value), null);
    await ui.submit(value);
    assert.equal(ui.input.attributes['aria-invalid'], 'true');
  }
  assert.equal(ui.requests.length, 0);
  for (const value of ['example', 'example.com', 'EXAMPLE.COM.', 'a-b.dev', 'a'.repeat(63) + '.com']) {
    await ui.submit(value);
    assert.equal(ui.requests.at(-1)[0], `/api/domains/search?q=${normalizeDomain(value)}`);
    assert.equal(ui.requests.at(-1)[1].credentials, 'same-origin');
  }
  assert.equal(ui.input.attributes['aria-invalid'], undefined);
});

test('available and premium rows show both prices and encoded email CTA; taken and unknown have none', async () => {
  const ui = setup({ ok: true, status: 200, json: async () => ({ results: [
    { domain: 'example.com', status: 'available', premium: true, price_year: '14.50', price_renewal: '16.00' },
    { domain: 'example.net', status: 'taken', premium: false },
    { domain: 'example.org', status: 'unknown', premium: false },
  ] }) });
  await ui.submit('example');
  const rows = ui.results.children;
  assert.match(rows[0].textContent, /example.com.*Premium.*Available.*\$14.50 \/ yr first year.*Renews at \$16.00 \/ yr/);
  const link = descendants(rows[0]).find((node) => node.tag === 'a');
  assert.equal(link.textContent, 'Email us to register');
  const url = new URL(link.href);
  assert.equal(url.protocol, 'mailto:');
  assert.equal(url.pathname, 'support@fastdognetworks.com');
  assert.equal(url.searchParams.get('subject'), 'Register example.com');
  assert.match(url.searchParams.get('body'), /example.com/);
  assert.ok(link.href.includes('subject=Register%20example.com'));
  assert.match(rows[1].textContent, /Taken/);
  assert.match(rows[2].textContent, /Unknown/);
  assert.ok(rows.slice(1).every((row) => descendants(row).every((node) => node.tag !== 'a')));
  assert.equal(ui.form.button.disabled, false);
  assert.equal(ui.results.attributes['aria-busy'], undefined);
});

test('429, degraded, 5xx, malformed data, and network failures show the specified safe messages', async () => {
  const unavailable = "Live availability is unavailable right now. Email us the name you want and we'll check it.";
  for (const response of [
    { ok: false, status: 503 }, new Error('private error'),
    { ok: true, status: 200, json: async () => ({ degraded: 'daily_cap', results: [] }) },
    { ok: true, status: 200, json: async () => ({ results: [{ domain: '<script>', status: 'available' }] }) },
  ]) {
    const ui = setup(response);
    await ui.submit('example');
    assert.equal(ui.results.textContent, unavailable);
    assert.equal(ui.form.button.disabled, false);
  }
  const limited = setup({ ok: false, status: 429 });
  await limited.submit('example');
  assert.equal(limited.results.textContent, 'Too many searches. Try again in a few minutes, or email us.');
});

test('large prices use thousands separators', async () => {
  const ui = setup({ ok: true, status: 200, json: async () => ({ results: [
    { domain: 'example.io', status: 'available', premium: true, price_year: '2400.00', price_renewal: '60.00' },
    { domain: 'example.co', status: 'available', premium: true, price_year: '123456789.50', price_renewal: '1000.00' },
  ] }) });
  await ui.submit('example.io');
  const [first, second] = ui.results.children;
  assert.match(first.textContent, /\$2,400\.00 \/ yr first year.*Renews at \$60\.00 \/ yr/);
  assert.match(second.textContent, /\$123,456,789\.50 \/ yr first year.*Renews at \$1,000\.00 \/ yr/);
});
