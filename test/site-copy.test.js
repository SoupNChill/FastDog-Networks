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
  });
}

test('edge pricing explains the trial and retains exactly the three monthly plans', () => {
  const pricing = read('edge/index.html').match(/<section[^>]*aria-labelledby="pricing"[\s\S]*?<\/section>/)?.[0];
  assert.ok(pricing);
  assert.ok(pricing.includes('7-day free trial: 1 hostname, no card needed'));
  assert.ok(pricing.includes('paused, not deleted'));
  assert.deepEqual([...pricing.matchAll(/\$(\d+) <small>\/ mo/g)].map(([, price]) => price), ['9', '29', '149']);
  assert.deepEqual([...pricing.matchAll(/<div><span>([^<]+)<small>[^<]*<\/small><\/span><strong>\$(\d+) <small>\/ mo<\/small><\/strong><\/div>/g)]
    .map(([, plan, price]) => [plan, price]), [['Hobby', '9'], ['Pro', '29'], ['Agency', '149']]);
});
