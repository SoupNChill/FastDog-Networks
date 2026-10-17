import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const site = fileURLToPath(new URL('../site/', import.meta.url));
const read = (path) => readFileSync(join(site, path), 'utf8');
const pages = ['terms/index.html', 'privacy/index.html', 'faq/index.html'];
const resolves = (href) => {
  const path = href.split('#')[0];
  return existsSync(join(site, path.endsWith('/') ? `${path}index.html` : path));
};

for (const page of pages) {
  test(`${page} is a noindex draft in the shared subpage layout`, () => {
    const html = read(page);
    assert.match(html, /<meta name="robots" content="noindex">/);
    assert.match(html, /DRAFT\. Not yet in effect\./);
    assert.match(html, /Version 2026-10-17-draft/);
    assert.match(html, /<link rel="stylesheet" href="\/css\/site\.css">/);
    assert.match(html, /<header class="site-header wrap">/);
    assert.match(html, /<footer class="footer wrap">/);
    assert.doesNotMatch(html, /gradient|<style|<script|[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u);
    assert.doesNotMatch(html, /\$\d/, 'prices live on the pricing page only');
    for (const [, address] of html.matchAll(/mailto:([^"?]+)/g)) assert.match(address, /@example\.invalid$/);
  });

  test(`${page} internal links resolve to site files`, () => {
    const hrefs = [...read(page).matchAll(/(?:href|src|srcset)="(\/[^"]*)"/g)].map(([, href]) => href);
    assert.ok(hrefs.length > 0);
    for (const href of hrefs) assert.ok(resolves(href), href);
    for (const target of ['/terms/', '/privacy/', '/faq/']) assert.ok(hrefs.includes(target), target);
  });
}

test('legal pages cover the required topics', () => {
  const terms = read('terms/index.html');
  for (const topic of ['FastDog Networks', 'phish', 'malware', 'spam', 'open proxies', 'illegal content', 'suspend',
    'href="/edge/#pricing"', 'service level agreement', 'Limitation of liability', 'Termination', 'Changes']) assert.ok(terms.includes(topic), topic);
  const privacy = read('privacy/index.html');
  for (const topic of ['email address', 'hash of your password', 'rate limits', 'access logs', 'hostnames', 'bot scoring',
    'How long we keep it', 'TODO(owner)', 'do not sell', 'Your rights']) assert.ok(privacy.includes(topic), topic);
  const faq = read('faq/index.html');
  const questions = faq.match(/<dt>/g).length;
  assert.ok(questions >= 8 && questions <= 10, String(questions));
  for (const topic of ['/docs/', 'CNAME', 'log', 'delete my account', '/edge/#pricing', 'help']) assert.ok(faq.includes(topic), topic);
});

test('docs subpage footer links the legal pages', () => {
  const footer = read('docs/index.html').match(/<footer[\s\S]*<\/footer>/)[0];
  for (const target of ['/terms/', '/privacy/', '/faq/']) assert.ok(footer.includes(`href="${target}"`), target);
});
