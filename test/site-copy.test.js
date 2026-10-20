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
    const expected = `<p class="small-note">Add your hostname yourself: <a href="https://portal.${host}/signup">sign up in the portal</a> and add it there. Need help? Email <a href="mailto:support@${host}?subject=Attach%20a%20hostname">support@${host}</a> and we reply the same business day.</p>`;
    assert.ok(html.includes(expected));
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
  assert.ok(pricing.includes('Email us to pick a plan'));
  assert.doesNotMatch(pricing, /Email us to start/);
  assert.deepEqual([...pricing.matchAll(/\$(\d+) <small>\/ mo/g)].map(([, price]) => price), ['9', '29', '149']);
  assert.deepEqual([...pricing.matchAll(/<div><span>([^<]+)<small>[^<]*<\/small><\/span><strong>\$(\d+) <small>\/ mo<\/small><\/strong><\/div>/g)]
    .map(([, plan, price]) => [plan, price]), [['Hobby', '9'], ['Pro', '29'], ['Agency', '149']]);
});
