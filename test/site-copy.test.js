import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (page) => readFileSync(new URL(`../site/${page}`, import.meta.url), 'utf8');
const homepage = read('index.html');
// Derive the public origin from the site's canonical URL, as the legal-page tests do.
const host = new URL(homepage.match(/<link rel="canonical" href="([^"]+)"/)[1]).hostname;

for (const page of ['edge/index.html', 'index.html']) {
  test(`${page} offers self-serve hostname setup with support`, () => {
    const html = read(page);
    const expected = `<p class="small-note">Add your hostname yourself: <a href="https://portal.${host}/signup">sign up in the portal</a> and add it there. Need help? Email <a href="mailto:support@${host}?subject=Attach%20a%20hostname">support@${host}</a>. Agency plans get a same-business-day first reply.</p>`;
    assert.ok(html.includes(expected));
    // Same-business-day replies are an Agency-plan promise, not a promise to everyone.
    assert.doesNotMatch(html, /we reply the same business day/);
    assert.ok(html.includes('<li>On the Agency plan: same-business-day first reply (America/Denver).'));
    assert.equal([...html.matchAll(/same-business-day/gi)].length, 3, 'small note, guarantee and the Agency plan row');
    assert.doesNotMatch(html, /goes through us/);
    assert.ok(html.includes(`<p class="guarantee-start">How to start: <a href="https://portal.${host}/signup">sign up in the portal</a> and add your hostname. For guided setup, email`));
    assert.doesNotMatch(html, /How to start: email/);
  });
}

test('timing claims carry their context and unbacked promises are gone', () => {
  const story = homepage.match(/<a class="text-link" href="\/(customers\/[^/]+\/)">Read the customer story/)[1];
  const pages = ['index.html', 'domains/index.html', 'verdict/index.html', `${story}index.html`].map(read);
  for (const html of pages) {
    assert.doesNotMatch(html, /same day/i);
    assert.doesNotMatch(html, /7 ms|p99|200 requests per second/);
  }
  const [home, domains, verdict, customer] = pages;
  assert.ok(home.includes('<p>Registered at cost, in your name.</p><p>You are the registrant. Then attach a hostname to the edge.</p>'));
  assert.equal(domains.split('in your name, then attached to the FastDog edge. You are the registrant.').length - 1, 3);
  const local = 'Verdict runs on the edge server itself, so each decision is a local call, not a trip across the internet.';
  assert.ok(home.includes(`<p>${local}</p>`));
  assert.ok(verdict.includes(`<h2 id="a-measured-decision-path">A local decision path.</h2><p class="measurement">${local}</p>`));
  assert.ok(home.includes('22 seconds (timed on a test hostname in a zone on FastDog\'s own nameservers), with every step run by our operator from scripts.'));
  assert.ok(customer.includes('<h1>Under 30 seconds from DNS record to live HTTPS</h1><p class="hero-lede">22 seconds end to end (timed on a test hostname in a zone on FastDog’s own nameservers, every step run by our operator from scripts).'));
});

for (const page of ['edge/index.html', 'index.html']) test(`${page} pricing explains the trial and retains exactly the three monthly plans`, () => {
  const pricing = read(page).match(/<section[^>]*aria-labelledby="pricing"[\s\S]*?<\/section>/)?.[0];
  assert.ok(pricing);
  assert.ok(pricing.includes('7-day free trial: 1 hostname, no card needed'));
  assert.ok(pricing.includes('paused, not deleted'));
  assert.ok(pricing.includes(`<p class="cta-repeat"><a class="cta" href="https://portal.${host}/signup">Start free: 7 days, no card</a></p>`));
  const note = pricing.match(/<p class=\x22small-note\x22>Free for 7 days on one hostname\. No card\. When you\x27re ready to pick a plan, email <a href=\x22mailto:([^\x22?]+)\?subject=FastDog%20plan\x22>([^<]+)<\/a> from your account\x27s email address\.<\/p>/);
  assert.deepEqual(note?.slice(1), [`support@${host}`, `support@${host}`]);
  assert.doesNotMatch(pricing, /Email us to (start|pick a plan)/);
  assert.deepEqual([...pricing.matchAll(/\$(\d+) <small>\/ mo/g)].map(([, price]) => price), ['9', '29', '149']);
  assert.deepEqual([...pricing.matchAll(/<div><span>([^<]+)<small>[^<]*<\/small><\/span><strong>\$(\d+) <small>\/ mo<\/small><\/strong><\/div>/g)]
    .map(([, plan, price]) => [plan, price]), [['Hobby', '9'], ['Pro', '29'], ['Agency', '149']]);
});

const signup = () => `<a class="cta" href="https://portal.${host}/signup">Start free: 7 days, no card</a>`;
const navCta = () => `<a class="nav-cta" href="https://portal.${host}/signup">Start free: 7 days, no card</a></nav>`;
const storyPath = homepage.match(/<a class="text-link" href="\/(customers\/[^/]+\/)">Read the customer story/)[1];
for (const page of ['index.html', 'edge/index.html', 'domains/index.html', 'verdict/index.html', `${storyPath}index.html`, 'faq/index.html', 'docs/index.html']) {
  test(`${page} header ends with one sign-up button`, () => {
    const html = read(page);
    assert.equal(html.split('class="nav-cta"').length - 1, 1);
    assert.ok(html.match(/<nav aria-label="Main navigation">.*<\/nav>/)[0].endsWith(navCta()));
    assert.doesNotMatch(html, /signup\x22>[^<]*<span aria-hidden=\x22true\x22>↗/, 'sign-up buttons have no external-link arrow');
  });
}

test('legal pages keep their header without the sign-up button', () => {
  for (const page of ['privacy/index.html', 'terms/index.html']) assert.doesNotMatch(read(page), /nav-cta/);
});

test('homepage repeats the sign-up button after the proof line and the customer story', () => {
  const hero = homepage.match(/<section class="hero wrap"[\s\S]*?<\/section>/)[0];
  assert.match(hero, new RegExp(`<div class="hero-actions">${signup().replace(/[.?]/g, '\\$&')}<a class="text-link" href="/docs/">Read the docs</a></div><p class="small-note">In our Oct 17 production test`));
  const story = homepage.match(/<section[^>]*aria-labelledby="customer-story"[\s\S]*?<\/section>/)[0];
  assert.ok(story.includes(`Read the customer story <span aria-hidden="true">↗</span></a><p class="cta-repeat">${signup()}</p></div>`));
  assert.equal(homepage.split(signup()).length - 1, 3, 'hero, customer story and pricing');
});

test('sign-up buttons are styled as a compact filled button that fits small screens', () => {
  const css = readFileSync(new URL('../site/css/site.css', import.meta.url), 'utf8');
  assert.match(css, /\n\.nav-cta\{[^}]*background:var\(--cyan\);color:var\(--button-ink\);white-space:nowrap\}/);
  assert.match(css, /\.nav-cta:hover\{color:var\(--button-ink\)/, 'hover keeps the label readable on the cyan fill');
  assert.match(css, /@media\(max-width:760px\)\{[^\n]*\.nav-cta\{padding:0 12px;font-size:12px\}/);
  assert.match(css, /\.section-body>\.cta-repeat\{margin-top:28px\}/);
});
