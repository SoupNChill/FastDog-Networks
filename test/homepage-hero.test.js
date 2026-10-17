import test from 'node:test';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../site/index.html', import.meta.url), 'utf8');
const section = (label) => {
  const match = html.match(new RegExp(`<section\\b[^>]*aria-labelledby="${label}"[^>]*>[\\s\\S]*?</section>`));
  assert.ok(match, `${label} section exists`);
  return match[0];
};

test('homepage hero has exact onboarding copy and invite/docs actions', () => {
  const hero = section('hero-title');
  assert.ok(hero.includes('<h1 id="hero-title">Your AI can put your app on FastDog safely <em>in one prompt.</em></h1>'));
  assert.ok(hero.includes('<p class="hero-lede">Paste one prompt into your coding assistant. It sets up the hostname, HTTPS, and a private tunnel to your app. You add two DNS records and approve the docker command. No open ports, and the setup keys it uses only work for your account and expire on their own. The agent key stays on your server.</p>'));
  assert.ok(hero.includes('<p class="small-note">In our Oct 17 production test (single run), a fresh Claude Code session took a new hostname to live HTTPS in under 3 minutes, DNS included, for about $0.17 of AI usage. With web requests allowed up front, its only approval was the docker run.</p>'));
  assert.match(hero, /<a class="cta" href="mailto:support@fastdognetworks\.com\?subject=Request%20an%20invite">Request an invite <span aria-hidden="true">↗<\/span><\/a>/);
  assert.match(hero, /<a class="text-link" href="\/docs\/">Read the docs<\/a>/);
});

test('AI setup section sits between hero and products with scoped guidance', () => {
  const ai = section('for-ai-assistants');
  assert.ok(html.includes(`${section('hero-title')}\n${ai}\n<section class="section product-band`));
  assert.ok(ai.includes('<div class="section-marker">For AI coding assistants</div>'));
  assert.ok(ai.includes('<h2 id="for-ai-assistants">Let your coding assistant do the setup.</h2>'));
  assert.equal((ai.match(/<li>/g) || []).length, 4);
  for (const lead of ['Copy a prompt.', 'Scoped, short-lived setup keys.', 'Docs your AI can read.', 'What you still do.']) {
    assert.ok(ai.includes(`<strong>${lead}</strong>`));
  }
  assert.match(ai, /href="\/llms\.txt"/);
  assert.ok(ai.includes('<a href="/docs/">the docs</a>'));
  assert.ok(ai.includes('<strong>Scoped, short-lived setup keys.</strong> The prompt carries a connect token that only covers that one hostname, expires after an hour, and can be revoked any time from the same page. API keys stay inside your account and expire on their own (30 days by default, 90 at most). The agent key it sets up is long-lived, works only for that hostname, and stays valid on your server until you reconnect, rotate it, or remove the hostname. Your password and sudo prompts stay with you.'));
  assert.match(ai, /Questions\? Email <a href="mailto:support@fastdognetworks\.com">support@fastdognetworks\.com<\/a>\./);
  assert.ok(!ai.includes('First reply the same business day'));
  assert.doesNotMatch(ai, /same[- ]business[- ]day/i);
});

test('pricing markup remains byte-identical to the pre-review homepage', () => {
  // SHA-256 of the unchanged pricing section before this review (also identical to origin/master).
  const baseline = '5b80f3aea1d01280000283ad4690b2c3ff1b5e3c239ff922a8e7e34af786203d';
  assert.equal(createHash('sha256').update(section('pricing'), 'utf8').digest('hex'), baseline);
});
