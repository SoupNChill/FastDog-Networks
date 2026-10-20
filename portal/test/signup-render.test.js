import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { renderHtml, serveStatic, signupCopy, pages } from '../src/static.js';
import { fixture, request } from './helpers.js';

const read = (file) => readFileSync(new URL(`../public/${file}`, import.meta.url));
const sha = (buffer) => createHash('sha256').update(buffer).digest('hex');
const served = (path, options) => {
  let body;
  serveStatic(path, { writeHead() {}, end(content) { body = content; } }, options);
  return body;
};
const closedIntro = 'Use the exact email address that received your invitation. Copy the invitation code from that email.';
const closedHelp = 'No email yet? Check your spam folder and the email address and code in your invitation. If you already have an account, sign in below.';
const openIntro = 'Start your 7-day free trial: 1 hostname, no card needed.';
const openHelp = 'After you create your account, check your inbox and spam folder for a verification link. If you already have an account, sign in below.';

test('invite-only /signup renders byte-identical to the page served before server rendering', () => {
  // SHA-256 of renderHtml(signup.html, {}) at the parent commit, when the invite copy was static HTML.
  const before = '3be4b9af3126238f651c3ae4ca38b1b6f0094793a5004ef291a8e3dc33d11b5e';
  for (const options of [undefined, {}, { openSignup: false }, { openSignup: 'true' }, { openSignup: 1 }]) {
    assert.equal(sha(renderHtml(read('signup.html'), {}, options)), before, JSON.stringify(options));
  }
});

test('GET /signup follows open_signup in the raw HTML, before any JavaScript runs', async (t) => {
  const closed = (await request((await fixture(t)).port, '/signup')).text;
  assert.equal(closed, renderHtml(read('signup.html')).toString(), 'closed is the default render');
  assert.ok(closed.includes(`<p id="signup-intro">${closedIntro}</p>`));
  assert.ok(closed.includes('<label for="invite" id="invite-label">Invitation code</label><input id="invite" name="invite_code" autocomplete="off" required></div>'));
  assert.ok(closed.includes(`<p id="signup-help">${closedHelp}</p>`));

  const open = (await request((await fixture(t, { openSignup: true })).port, '/signup')).text;
  assert.ok(open.includes(`<p id="signup-intro">${openIntro}</p>`));
  // Without JavaScript the toggle cannot open the field, so the optional field stays visible and the toggle hidden.
  assert.ok(open.includes('<button type="button" id="invite-toggle" aria-controls="invite-field" aria-expanded="false" hidden>Have an invitation code?</button><div id="invite-field"><label for="invite" id="invite-label">Invitation code (optional)</label><input id="invite" name="invite_code" autocomplete="off"></div>'));
  assert.ok(open.includes(`<p id="signup-help">${openHelp}</p>`));
  assert.doesNotMatch(open, /invitation\. Copy|code in your invitation/);
  for (const html of [closed, open]) {
    assert.match(html, /<input type="checkbox" id="accept-terms" name="accept_terms" required>/);
    assert.doesNotMatch(html, /\{\{/);
  }
});

test('no page leaks a placeholder and only /signup changes with the flag', () => {
  for (const path of [...Object.keys(pages), '/signup/']) {
    const [closed, open] = [served(path, { openSignup: false }), served(path, { openSignup: true })].map(String);
    for (const html of [closed, open]) assert.doesNotMatch(html, /\{\{/, path);
    if (pages[path.replace(/(.)\/$/, '$1')] === 'signup.html') assert.notEqual(open, closed, path);
    else assert.equal(open, closed, path);
  }
});

test('server copy matches the strings signup.js applies after /api/me', () => {
  const script = read('js/signup.js').toString();
  assert.deepEqual(signupCopy.closed, { SIGNUP_INTRO: closedIntro, INVITE_LABEL: 'Invitation code', INVITE_REQUIRED: ' required', SIGNUP_HELP: closedHelp });
  assert.deepEqual(signupCopy.open, { SIGNUP_INTRO: openIntro, INVITE_LABEL: 'Invitation code (optional)', INVITE_REQUIRED: '', SIGNUP_HELP: openHelp });
  for (const copy of [signupCopy.closed, signupCopy.open]) {
    for (const text of [copy.SIGNUP_INTRO, copy.INVITE_LABEL, copy.SIGNUP_HELP]) assert.ok(script.includes(`'${text}'`), text);
  }
});
