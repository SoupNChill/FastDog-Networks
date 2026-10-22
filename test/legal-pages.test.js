import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const site = fileURLToPath(new URL('../site/', import.meta.url));
const read = (path) => readFileSync(join(site, path), 'utf8');
const pages = ['terms/index.html', 'privacy/index.html', 'faq/index.html'];
// Head metadata (canonical, og:url, og:image, twitter:image) must carry the absolute origin; body copy must not.
const body = (html) => html.slice(html.indexOf('</head>'));
const resolves = (href) => {
  const path = href.split('#')[0];
  return existsSync(join(site, path.endsWith('/') ? `${path}index.html` : path));
};

for (const page of pages) {
  test(`${page} is indexable and keeps the shared subpage layout`, () => {
    const html = read(page);
    assert.doesNotMatch(html, /<meta name="robots" content="noindex">/);
    assert.match(html, /<link rel="stylesheet" href="\/css\/site\.css">/);
    assert.match(html, /<header class="site-header wrap">/);
    assert.match(html, /<footer class="footer wrap">/);
    assert.doesNotMatch(html, /gradient|<style|<script|[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u);
    assert.doesNotMatch(html, /\$\d/, 'prices live on the pricing page only');
  });

  test(`${page} internal links resolve to site files`, () => {
    const hrefs = [...read(page).matchAll(/(?:href|src|srcset)=\x22(\/[^\x22]*)\x22/g)].map(([, href]) => href);
    assert.ok(hrefs.length > 0);
    for (const href of hrefs) assert.ok(resolves(href), href);
    for (const target of ['/terms/', '/privacy/', '/faq/']) assert.ok(hrefs.includes(target), target);
  });
}

for (const [page, title] of [['terms/index.html', 'Terms of Service'], ['faq/index.html', 'FAQ']]) {
  test(`${page} is final copy (no DRAFT), version 2026-10-19`, () => {
    const html = read(page);
    assert.doesNotMatch(html, /draft/i);
    assert.doesNotMatch(html, /not yet in effect/i);
    assert.match(html, /Version 2026-10-19/);
    assert.ok(html.includes(`<title>${title} — FastDog Networks</title>`));
    assert.doesNotMatch(html, /TODO|example\.invalid/);
    const canonical = read('index.html').match(/<link rel=\x22canonical\x22 href=\x22([^\x22]+)\x22>/);
    assert.ok(canonical, 'homepage has a canonical origin');
    const host = new URL(canonical[1]).hostname;
    const address = `support@${host}`;
    assert.doesNotMatch(address, /@example\.invalid$/);
    assert.deepEqual([...html.matchAll(/mailto:([^\x22?]+)/g)].map(([, value]) => value), [address]);
    // Subject strings stay as written in the page; they are not repeated here (the name scan reads test literals).
    const contactLink = html.match(new RegExp(`<a href="mailto:${address.replaceAll('.', '\\.')}\\?subject=[^"]+">${address.replaceAll('.', '\\.')}</a>`))?.[0];
    assert.ok(contactLink, 'contact keeps a subject and the visible address');
    // The FAQ header also carries the site-wide sign-up button (Terms and Privacy do not).
    const signupLink = `<a class="nav-cta" href="https://portal.${host}/signup">Start free: 7 days, no card</a>`;
    assert.equal(html.includes(signupLink), page === 'faq/index.html');
    assert.ok(!body(html).replace(contactLink, '').replace(signupLink, '').includes(host), 'public host appears only in the contact and sign-up links');
  });
}

test('privacy/index.html is final copy (no DRAFT), version 2026-10-20', () => {
  const html = read('privacy/index.html');
  assert.doesNotMatch(html, /DRAFT/);
  assert.doesNotMatch(html, /-draft/);
  assert.match(html, /Version 2026-10-20/);
  assert.match(html, /<title>Privacy Policy — FastDog Networks<\/title>/);
  const canonical = read('index.html').match(/<link rel=\x22canonical\x22 href=\x22([^\x22]+)\x22>/);
  assert.ok(canonical, 'homepage has a canonical origin');
  const host = new URL(canonical[1]).hostname;
  const address = `support@${host}`;
  assert.doesNotMatch(address, /@example\.invalid$/);
  assert.deepEqual([...html.matchAll(/mailto:([^\x22?]+)/g)].map(([, value]) => value), [address]);
  const contactLink = `<a href="mailto:${address}?subject=Privacy">${address}</a>`;
  assert.ok(html.includes(contactLink), 'Privacy contact keeps its subject and visible address');
  assert.doesNotMatch(html, /TODO/);
  assert.doesNotMatch(html, /Stripe/i);
  assert.doesNotMatch(html, /DigitalOcean|Hetzner|MXRoute/i);
  assert.ok(!body(html).replace(contactLink, '').includes(host), 'public host appears only in the contact link (head SEO metadata excluded)');
});

test('legal pages cover the required topics', () => {
  const terms = read('terms/index.html');
  for (const topic of ['FastDog Networks', 'phish', 'malware', 'spam', 'open proxies', 'illegal content', 'suspend',
    'href="/edge/#pricing"', 'service level agreement', 'Limitation of liability', 'Termination', 'Changes']) assert.ok(terms.includes(topic), topic);
  const privacy = read('privacy/index.html');
  for (const topic of ['email address', 'hash of your password', 'rate limits', 'access logs', 'hostnames', 'bot scoring',
    'How long we keep it', 'cloud hosting providers and our email provider', 'do not sell', 'Your rights', '30 days']) {
    assert.ok(privacy.includes(topic), topic);
  }
  const faq = read('faq/index.html');
  const questions = faq.match(/<dt>/g).length;
  assert.equal(questions, 11);
  for (const topic of ['/docs/', 'CNAME', 'log', 'delete my account', '/edge/#pricing', 'help']) assert.ok(faq.includes(topic), topic);
});

test('privacy and FAQ describe retention, logging and email delivery as implemented', () => {
  const privacy = read('privacy/index.html');
  for (const claim of ['<dt>Terms acceptance</dt>', 'we record which versions of the Terms of Service and this Privacy Policy you accepted', 'private outbox',
    'deleted automatically. Many are gone within 30 days', 'system logs and DNS lookup logs are stored in files', 'Our DNS servers also log each lookup they answer', 'entries in these logs can be kept for more than 30 days', '24 hours',
    'sent through our email provider', 'most recent backup of each kind', 'any backup needed to roll back a change',
    'payment processor will be added when paid plans launch', 'cloud hosting providers and our email provider']) {
    assert.ok(privacy.includes(claim), claim);
  }
  for (const stale of ['(planned)', 'does not record this yet', 'on a short schedule', 'minutes to hours', 'request headers such as the user agent, IP',
    'TODO(owner)', 'planned but not in place yet', 'DRAFT. Not yet in effect.',
    'not fully in place', 'once connected', 'not yet sent through the email provider', 'aim to delete', 'no longer than we reasonably need']) {
    assert.ok(!privacy.includes(stale), stale);
  }
  const outbox = privacy.match(/<li>[^<]*outbox[^<]*<\/li>/i)?.[0];
  assert.ok(outbox, 'outbox retention item exists');
  assert.match(outbox, /deleted automatically after about 7 days/);
  assert.doesNotMatch(outbox, /not built|manual|by hand/i);
  const outgoing = privacy.match(/<dt>Outgoing emails<\/dt><dd>([^<]*)<\/dd>/)?.[1];
  assert.ok(outgoing, 'outgoing emails entry exists');
  assert.ok(outgoing.includes('whether it was sent'));
  assert.doesNotMatch(outgoing, /\bthe link\b/);
  assert.ok(outgoing.includes('These notices include the account\'s email address and go only to us; the outbox record keeps only the message type and whether it was sent.'));
  for (const claim of ['on our own website the log also keeps the browser\'s user agent; other headers and cookies are removed.',
    '<li>To count visits to our own website: daily totals are worked out from its access logs, and only the totals are kept.</li>',
    '<li>Email delivery: our email provider sends sign-in emails and our own account notices.</li>']) assert.ok(privacy.includes(claim), claim);
  assert.ok(!privacy.includes('shortened IP address; headers and cookies are removed'), 'access logs no longer claim all headers are dropped');
  assert.ok(!privacy.includes('It stores only a decision log'), 'Verdict no longer claims a decision log only');
  for (const claim of ['It stores a decision log: time, IP address, path without the query string, and the decision.',
    'Verdict also keeps a scoring log with the time, hostname, a shortened IP address (last part removed), network (ASN), method, path (without the query string), user agent and the score it would have given, which is deleted automatically after about 30 days.',
    '<li>Verdict scoring log (our own sites): deleted automatically after about 30 days.</li>']) assert.ok(privacy.includes(claim), claim);
  const faq = read('faq/index.html');
  assert.ok(!faq.includes('does not store them'));
  for (const claim of ['Other headers and cookies are not stored', 'scoring log for about 30 days', 'also the browser’s user agent', 'remove both if you leave', 'DNS servers’ lookup logs',
    'the requesting IP address, the name and record type asked for, and the result', 'Logs are deleted automatically',
    'Many are gone within 30 days', 'some are kept longer', 'Is there a free trial?', 'When you sign up in the portal without an invitation, you get a 7-day free trial with 1 hostname',
    'don’t need a card', 'On day 8 we pause the hostname', 'To pick one, email support from your account’s email address', 'We don’t delete the hostname']) assert.ok(faq.includes(claim), claim);
  assert.ok(!faq.includes('status and user agent'));
  assert.doesNotMatch(faq, /(all|every) logs?[^.]*within 30 days/i);
  assert.match(faq, /<dt>Is there a free trial\?<\/dt><dd>[^\n]+<\/dd>\n<dt>How much does it cost\?<\/dt>/);
  const terms = read('terms/index.html');
  assert.ok(terms.includes('stay blocked for every other account until we review them and release them'));
  for (const claim of ['Domain registration is billed separately. You can cancel at any time.', 'To ask for a refund, email support at the address under <a href="#contact">Contact</a>',
    'we handle refund requests case by case.']) assert.ok(terms.includes(claim), claim);
  assert.ok(terms.includes('Accounts created through open sign-up start with a free trial that lasts 7 days from sign-up and covers 1 hostname. When the trial ends, we pause your hostnames, without deleting anything, until you are on a paid plan. Accounts created from an invitation start on the plan named in the invitation.'));
  for (const stale of ['setup promise', 'fees already paid are not refunded']) assert.ok(!terms.includes(stale), stale);
  assert.doesNotMatch(terms, /refunds? (are|is|will be) (guaranteed|always)|refund[^.]*within \d+ (business )?days/i, 'no new money promise');
});

test('docs subpage footer links the legal pages', () => {
  const footer = read('docs/index.html').match(/<footer[\s\S]*<\/footer>/)[0];
  for (const target of ['/terms/', '/privacy/', '/faq/']) assert.ok(footer.includes(`href="${target}"`), target);
});
