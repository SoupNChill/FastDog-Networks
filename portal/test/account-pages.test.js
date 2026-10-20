import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { renderHtml, signupCopy } from '../src/static.js';

const read = (file) => readFileSync(new URL(`../public/${file}`, import.meta.url), 'utf8');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
async function run(name, mocks) {
  const source = read(`js/${name}.js`).replace(/^import .*;\n/gm, '');
  await new AsyncFunction(...Object.keys(mocks), source)(...Object.values(mocks));
}

test('verification clears the fragment before CSRF initialization and auto POST, with session-aware continue', async () => {
  for (const tenant of [null, { id: 'tenant-example' }]) {
    const calls = [];
    const submit = {};
    const formNode = { querySelector: () => submit };
    const next = { hidden: true };
    let manual;
    let status;
    await run('verify-email', {
      api: async (...args) => calls.push(args),
      init: async () => { calls.push('init'); return { tenant }; },
      form: (_, callback) => { manual = callback; }, message: (text) => { status = text; },
      location: { hash: '#token=example-token', pathname: '/verify-email' },
      history: { replaceState: (...args) => calls.push(args) },
      document: { querySelector: (id) => id === '#continue' ? next : formNode },
    });
    assert.deepEqual(calls, [[null, '', '/verify-email'], 'init', ['/api/verify-email', 'POST', { token: 'example-token' }]]);
    assert.equal(formNode.hidden, true);
    assert.equal(next.hidden, false);
    assert.equal(next.href, tenant ? '/hostname' : '/login');
    assert.match(status, /Email verified/);
    await manual();
    assert.equal(calls.length, 3, 'successful token is discarded');
  }
});

test('verification never reads query tokens; failures leave a working manual retry', async () => {
  for (const hash of ['', '#token=example-token']) {
    let manual;
    let attempts = 0;
    let status;
    const submit = {};
    const node = { hidden: false, querySelector: () => submit };
    await run('verify-email', {
      api: async () => { if (++attempts === 1) throw new Error('Please try again.'); },
      init: async () => ({ tenant: null }),
      form: (_, callback) => { manual = callback; }, message: (text) => { status = text; },
      location: { hash, search: '?token=ignored', pathname: '/verify-email' },
      history: { replaceState() {} }, document: { querySelector: () => node },
    });
    assert.equal(node.hidden, false);
    if (hash) {
      assert.equal(attempts, 1);
      assert.equal(submit.disabled, false);
      assert.match(status, /expired or already been used/);
      await manual();
      assert.equal(attempts, 2);
      assert.match(status, /Email verified/);
    } else {
      await manual();
      assert.equal(attempts, 0);
      assert.match(status, /complete verification link/);
    }
  }
});

function signupNodes() {
  const element = (extra = {}) => ({ hidden: false, textContent: 'original', attributes: {}, listeners: {},
    setAttribute(name, value) { this.attributes[name] = value; }, removeAttribute(name) { delete this.attributes[name]; },
    addEventListener(name, cb) { this.listeners[name] = cb; }, focus() { this.focused = true; }, ...extra });
  return { '#invite': element({ required: true, value: '', attributes: { required: '' } }), '#invite-field': element(),
    '#invite-label': element({ textContent: 'Invitation code' }), '#invite-toggle': element({ hidden: true }),
    '#signup-intro': element(), '#signup-help': element() };
}
async function signupPage(init, nodes = signupNodes()) {
  const calls = { sent: null, status: null, callback: null };
  const all = { ...nodes, '#show-password': { addEventListener() {}, setAttribute() {} }, '#password': { type: 'password' },
    '#signup': { reset() {} }, '#accept-terms': { checked: true } };
  await run('signup', { api: async (...args) => { calls.sent = args; return { ok: true }; }, init,
    form: (_, cb) => { calls.callback = cb; }, message: (text) => { calls.status = text; },
    document: { querySelector: (id) => all[id] } });
  return { nodes, calls };
}

test('signup shows the same inbox copy for a generic response and resets password visibility', async () => {
  let callback;
  let click;
  let status;
  let sent;
  const password = { type: 'password' };
  const toggle = { addEventListener: (_, cb) => { click = cb; }, setAttribute: (name, value) => { toggle[name] = value; } };
  await run('signup', {
    api: async (...args) => { sent = args; return { ok: true }; }, init: async () => ({}),
    form: (_, cb) => { callback = cb; }, message: (text) => { status = text; },
    document: { querySelector: (id) => ({ '#password': password, '#show-password': toggle, '#signup': { reset() {} }, '#accept-terms': { checked: true },
      ...signupNodes() })[id] },
  });
  click();
  assert.equal(password.type, 'text');
  assert.equal(toggle['aria-pressed'], 'true');
  assert.equal(toggle.textContent, 'Hide password');
  click();
  assert.equal(password.type, 'password');
  click();
  await callback({ email: 'invited@example.test', accept_terms: 'on' });
  assert.deepEqual(sent, ['/api/signup', 'POST', { email: 'invited@example.test', accept_terms: true }]);
  assert.equal(status, 'Check your inbox. We sent a link to invited@example.test. It expires in one hour.');
  assert.equal(password.type, 'password');
  assert.equal(toggle['aria-pressed'], 'false');
});

test('signup with open_signup hides an optional invite field behind a toggle and shows trial copy', async () => {
  const { nodes, calls } = await signupPage(async () => ({ open_signup: true, csrf: 'c' }));
  assert.equal(nodes['#invite'].required, false);
  assert.equal('required' in nodes['#invite'].attributes, false);
  assert.equal(nodes['#invite-field'].hidden, true);
  assert.equal(nodes['#invite-toggle'].hidden, false);
  assert.equal(nodes['#signup-intro'].textContent, 'Start your 7-day free trial: 1 hostname, no card needed.');
  assert.doesNotMatch(nodes['#signup-help'].textContent, /No email yet|invitation/i);
  assert.equal(calls.status, null);
  await calls.callback({ email: 'new@example.test', password: 'p', invite_code: '' });
  assert.deepEqual(calls.sent, ['/api/signup', 'POST', { email: 'new@example.test', password: 'p', accept_terms: true }]);
  nodes['#invite-toggle'].listeners.click();
  assert.equal(nodes['#invite-field'].hidden, false);
  assert.equal(nodes['#invite-toggle'].attributes['aria-expanded'], 'true');
  assert.equal(nodes['#invite'].focused, true);
  await calls.callback({ email: 'invited@example.test', password: 'p', invite_code: 'code-1' });
  assert.equal(calls.sent[2].invite_code, 'code-1', 'an expanded invite field still sends the code');
  assert.match(nodes['#invite-label'].textContent, /optional/);
  await calls.callback({ email: 'new@example.test', password: 'p', invite_code: '   ' });
  assert.equal('invite_code' in calls.sent[2], false, 'a blank code takes the open path');
  await calls.callback({ email: 'invited@example.test', password: 'p', invite_code: ' code-2 ' });
  assert.equal(calls.sent[2].invite_code, 'code-2');
  nodes['#invite'].value = 'typed';
  nodes['#invite-toggle'].listeners.click();
  assert.equal(nodes['#invite-field'].hidden, true);
  assert.equal(nodes['#invite'].value, '');
});

test('signup without open_signup shows the invite-only form, even on a page rendered while sign-up was open', async () => {
  const renderedOpen = () => {
    const nodes = signupNodes();
    nodes['#invite'].required = false;
    delete nodes['#invite'].attributes.required;
    nodes['#invite-label'].textContent = 'Invitation code (optional)';
    return nodes;
  };
  for (const me of [{ open_signup: false }, {}]) for (const initial of [signupNodes(), renderedOpen()]) {
    const { nodes, calls } = await signupPage(async () => me, initial);
    assert.equal(nodes['#invite'].required, true);
    assert.equal('required' in nodes['#invite'].attributes, true);
    assert.equal(nodes['#invite-label'].textContent, 'Invitation code');
    assert.equal(nodes['#invite-field'].hidden, false);
    assert.equal(nodes['#invite-toggle'].hidden, true);
    assert.equal(nodes['#signup-intro'].textContent, signupCopy.closed.SIGNUP_INTRO);
    assert.equal(nodes['#signup-help'].textContent, signupCopy.closed.SIGNUP_HELP);
    assert.equal(calls.status, null);
    await calls.callback({ email: 'invited@example.test', password: 'p', invite_code: 'code-1' });
    assert.equal(calls.sent[2].invite_code, 'code-1');
  }
});

test('signup falls back to a visible optional invite field when the status check fails', async () => {
  const { nodes, calls } = await signupPage(async () => { throw new Error('The request could not be completed. Please try again.'); });
  assert.equal(nodes['#invite'].required, false);
  assert.equal(nodes['#invite-field'].hidden, false);
  assert.match(nodes['#invite-label'].textContent, /optional/);
  assert.equal(typeof calls.callback, 'function', 'the form still submits');
  assert.match(calls.status, /could not be completed/);
  await calls.callback({ email: 'new@example.test', password: 'p', invite_code: '' });
  assert.equal(calls.sent[2].invite_code, '', 'fallback sends the field as typed; the server is the gate');
});

test('account pages label the sign-up nav link Create account', () => {
  for (const name of ['login', 'signup', 'verify-email']) {
    assert.match(read(`${name}.html`), /<a href="\/signup">Create account<\/a>/);
    assert.doesNotMatch(read(`${name}.html`), /Use an invitation|with an invitation/);
  }
  assert.match(read('signup.html'), /id="invite-toggle" aria-controls="invite-field" aria-expanded="false" hidden/);
});

test('plan renders human labels and singular or plural limits', async () => {
  for (const [plan, expected, limit] of [['assigned', 'Early access', 1], ['pro', 'Pro', 5]]) {
    const nodes = { '#plan-name': {}, '#hostname-limit': {} };
    await run('plan', { init: async () => ({}), api: async () => ({ plan, hostname_limit: limit }),
      message: assert.fail, document: { querySelector: (id) => nodes[id] } });
    assert.equal(nodes['#plan-name'].textContent, expected);
    assert.equal(nodes['#hostname-limit'].textContent, limit === 1 ? 'Up to 1 web address' : 'Up to 5 web addresses');
  }
});

test('lane C pages include support, plain step names and accessible password and continue controls', () => {
  for (const name of ['login', 'signup', 'verify-email', 'plan', 'domains']) {
    const html = read(`${name}.html`);
    assert.match(html, /class="footer-support" href="mailto:{{SUPPORT_EMAIL}}"/);
    assert.doesNotMatch(html, /Private access|\d\d \/ (Plan|Domains)|Assigned plan|Contact the operator/);
  }
  assert.match(renderHtml(Buffer.from(read('signup.html')), {}).toString(), /exact email address/);
  assert.match(read('signup.html'), /type="button" id="show-password" aria-controls="password" aria-pressed="false"/);
  assert.match(read('verify-email.html'), /id="continue"[^>]+href="\/login" hidden/);
  assert.match(read('css/portal.css'), /nav a \{ min-width: 44px/);
});

test('login gives the same recovery guidance for failed credentials and preserves rate-limit advice', async () => {
  for (const failure of ['Please sign in, verify your email, or check the details and try again.', 'Please wait before trying again.']) {
    const callbacks = {};
    let status;
    const calls = [];
    await run('login', {
      init: async () => { calls.push('init'); }, api: async () => { throw new Error(failure); },
      form: (id, cb) => { callbacks[id] = cb; }, message: (text) => { status = text; },
      location: { hash: '', pathname: '/login', assign: assert.fail },
      history: { replaceState: () => calls.push('clear') }, document: {},
    });
    assert.deepEqual(calls, ['clear', 'init']);
    await callbacks['#login']({ email: 'unknown@example.test', password: 'example-password' });
    assert.ok(status.startsWith(failure));
    assert.match(status, /Check your email address and password/);
    assert.doesNotMatch(status, /account (exists|does not exist)/);
  }
});

test('automatic verification suppresses overlapping manual requests', async () => {
  let manual;
  let release;
  let started;
  const ready = new Promise((resolve) => { started = resolve; });
  const gate = new Promise((resolve) => { release = resolve; });
  let posts = 0;
  const node = { querySelector: () => ({}) };
  const running = run('verify-email', {
    init: async () => { started(); await gate; return {}; }, api: async () => { posts++; },
    form: (_, cb) => { manual = cb; }, message() {},
    location: { hash: '#token=example-token', pathname: '/verify-email' },
    history: { replaceState() {} }, document: { querySelector: () => node },
  });
  await ready;
  await manual();
  release();
  await running;
  assert.equal(posts, 1);
});


test('open verification waits for a new password and sends it only on submission', async () => {
  const calls = [], submit = {}, next = { hidden: true };
  const password = { value: 'synthetic-password-value', parentElement: { hidden: true } };
  const node = { querySelector: (selector) => selector.startsWith('input') ? password : submit };
  let manual;
  await run('verify-email', {
    api: async (...args) => calls.push(args), init: async () => ({ tenant: { id: 'tenant-example' } }),
    form: (_, callback) => { manual = callback; }, message() {},
    location: { hash: '#token=example-token&setup=1', pathname: '/verify-email' },
    history: { replaceState() {} }, document: { querySelector: (id) => id === '#continue' ? next : node },
  });
  assert.equal(calls.length, 0);
  assert.equal(password.parentElement.hidden, false);
  assert.equal(password.required, true);
  await manual();
  assert.deepEqual(calls, [['/api/verify-email', 'POST', { token: 'example-token', password: password.value }]]);
  assert.equal(next.href, '/login');
});
