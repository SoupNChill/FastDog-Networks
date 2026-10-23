import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

const site = new URL('../site/', import.meta.url);
const read = (path) => readFileSync(new URL(path, site), 'utf8');
function pages(dir = '') {
  return readdirSync(new URL(dir, site), { withFileTypes: true }).flatMap((entry) => {
    const path = dir + entry.name;
    if (entry.isDirectory()) return path === 'og' ? [] : pages(path + '/');
    return entry.name === 'index.html' ? [path] : [];
  });
}
const head = (path) => read(path).match(/<head>([\s\S]*?)<\/head>/i)[1];
const meta = (html, key) => html.match(new RegExp(`<meta (?:name|property)="${key}" content="([^"]*)"`))?.[1];
const canonical = (html) => html.match(/<link rel=\x22canonical\x22 href=\x22([^\x22]+)\x22/)?.[1];
// Use the existing public origin, as the site's copy and legal tests do.
const origin = new URL(canonical(head('index.html'))).origin;
const image = `${origin}/og/${['og', 'png'].join('.')}`;
const files = pages();
const sitemapFile = ['sitemap', 'xml'].join('.');

test('all site pages have complete, consistent SEO metadata', () => {
  const titles = [], descriptions = [];
  assert.ok(files.length > 0);
  for (const file of files) {
    const html = head(file);
    const title = html.match(/<title>([^<]+)<\/title>/)?.[1];
    const description = meta(html, 'description');
    assert.ok(title?.trim(), file);
    assert.ok(description?.trim(), file);
    titles.push(title);
    descriptions.push(description);
    const url = `${origin}/${file.slice(0, -'index.html'.length)}`;
    assert.equal(canonical(html), url, file);
    for (const [key, value] of Object.entries({
      'og:title': title, 'og:description': description, 'og:type': 'website', 'og:url': url,
      'og:image': image, 'og:image:width': '1200', 'og:image:height': '630',
      'og:image:alt': 'FastDog Networks. Fast by Design.',
      'twitter:card': 'summary_large_image', 'twitter:title': title,
      'twitter:description': description, 'twitter:image': image,
      'twitter:image:alt': 'FastDog Networks. Fast by Design.',
    })) assert.equal(meta(html, key), value, `${file}: ${key}`);
  }
  assert.equal(new Set(titles).size, files.length, 'unique titles');
  assert.equal(new Set(descriptions).size, files.length, 'unique descriptions');
});

test('sitemap matches canonical pages and robots allows crawlers', () => {
  const sitemap = read(sitemapFile);
  const locs = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map(([, loc]) => loc);
  assert.deepEqual(new Set(locs), new Set(files.map((file) => canonical(head(file)))));
  assert.equal(locs.length, files.length);
  assert.doesNotMatch(sitemap, /<lastmod/);
  const robots = read('robots.txt');
  for (const line of ['Allow: /', 'Disallow: /_fastdog/', 'Disallow: /www/',
    `Sitemap: ${origin}/${sitemapFile}`, 'User-agent: GPTBot']) assert.ok(robots.split('\n').includes(line), line);
});

test('homepage structured data describes the three monthly software offers', () => {
  const scripts = [...head('index.html').matchAll(/<script type=\x22application\/ld\+json\x22>([\s\S]*?)<\/script>/g)];
  assert.equal(scripts.length, 1);
  const raw = scripts[0][1];
  const data = JSON.parse(raw);
  assert.equal(data['@type'], 'SoftwareApplication');
  assert.equal(data.name, 'FastDog Networks');
  assert.equal(data.url, `${origin}/`);
  assert.equal(data.applicationCategory, 'DeveloperApplication');
  assert.equal(data.operatingSystem, 'Linux');
  assert.equal(data.description, meta(head('index.html'), 'description'));
  assert.equal(data.image, image);
  assert.deepEqual(data.offers.map((offer) => offer.price), ['9', '29', '149']);
  assert.deepEqual(data.offers.map((offer) => offer.name), ['Hobby', 'Pro', 'Agency']);
  assert.deepEqual(data.offers.map((offer) => offer.description), ['Up to 3 hostnames', 'Up to 15 hostnames', 'Up to 50 hostnames']);
  for (const offer of data.offers) {
    assert.equal(offer['@type'], 'Offer');
    assert.equal(offer.priceCurrency, 'USD');
    assert.deepEqual(offer.priceSpecification, {
      '@type': 'UnitPriceSpecification', price: offer.price, priceCurrency: 'USD',
      billingDuration: 'P1M', unitCode: 'MON',
    });
  }
  function checkKeys(value) {
    if (!value || typeof value !== 'object') return;
    for (const [key, child] of Object.entries(value)) {
      assert.ok(!['aggregateRating', 'review'].includes(key), key);
      checkKeys(child);
    }
  }
  checkKeys(data);
  assert.doesNotMatch(raw, /first month/i);
});
