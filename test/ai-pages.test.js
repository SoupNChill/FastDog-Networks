import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const site = fileURLToPath(new URL('../site/', import.meta.url));
const read = (path) => readFileSync(join(site, path), 'utf8');
const paths = ['docs/ai-assistants/', 'compare/cloudflare-tunnel/', 'compare/ngrok/', 'compare/tailscale-funnel/'];
const origin = new URL(read('index.html').match(/rel=\x22canonical\x22 href=\x22([^\x22]+)\x22/)[1]).origin;
const walk = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((entry) => entry.isDirectory()
  ? walk(join(dir, entry.name)) : [join(dir, entry.name)]);

for (const path of paths) test(`${path} has metadata, sitemap entry and approved trial copy`, () => {
  const html = read(`${path}index.html`);
  assert.match(html, /<title>[^<]+<\/title>/);
  assert.match(html, /name=\x22description\x22 content=\x22[^\x22]+\x22/);
  assert.ok(html.includes(`rel="canonical" href="${origin}/${path}"`));
  assert.ok(html.includes(`property="og:url" content="${origin}/${path}"`));
  assert.match(html, /name=\x22twitter:card\x22 content=\x22summary_large_image\x22/);
  assert.ok(read(['sitemap', 'xml'].join('.')).includes(`<loc>${origin}/${path}</loc>`));
  assert.match(html, /7 days/);
  assert.match(html, /no card/i);
  if (path.startsWith('compare/')) {
    for (const price of ['$9', '$29', '$149']) assert.ok(html.includes(price));
    assert.match(html, /class=\x22comparison-table\x22[^>]*tabindex=\x220\x22><table>/);
    assert.match(html, /<h2>Sources \(checked Oct 22, 2026\)<\/h2>\s*<ol>/);
  }
});

test('all site footers match and link to the four discovery pages', () => {
  const footers = walk(site).filter((path) => path.endsWith('/index.html')).map((path) => {
    const footer = readFileSync(path, 'utf8').match(/<footer[\s\S]*?<\/footer>/)?.[0];
    assert.ok(footer, path);
    for (const target of paths) assert.ok(footer.includes(`href="/${target}"`), path);
    return footer;
  });
  assert.equal(new Set(footers).size, 1);
});

test('site copy has no stale trial promises or review tags', () => {
  for (const file of walk(site).filter((file) => /\.(html|txt|css|js|xml|svg)$/.test(file))) {
    const text = readFileSync(file, 'utf8');
    assert.doesNotMatch(text, /first month free|free month|\[matches PR/i, file);
  }
});

test('assistant reference retains secure commands, errors and optional fields', () => {
  const text = read('llms.txt');
  for (const value of ['umask 077', 'reserved_hostname', '403', 'chmod 600', '0700',
    ['agent', 'agent_version (may be null)'].join('.'), 'checks may be absent once verified', 'delete every intermediate copy']) assert.ok(text.includes(value), value);
  // #112 keeps a do-not-rely-on-it aside about curl --create-file-mode; the flag itself must never be used with a mode.
  assert.doesNotMatch(text, /--create-file-mode\s+\d/);
  assert.match(text, /do not rely on it/);
});

test('how-to uses the approved screenshot once and every image exists', () => {
  const html = read('docs/ai-assistants/index.html');
  assert.doesNotMatch(html, /portal-api-keys\.png/);
  assert.equal([...html.matchAll(/src=\x22[^\x22]*portal-create-prompt\.png\x22/g)].length, 1);
  assert.match(html, /width=\x221024\x22 height=\x22594\x22 loading=\x22lazy\x22 alt=\x22[^\x22]+\x22/);
  for (const [, src] of html.matchAll(/<img[^>]*src=\x22([^\x22]+)\x22/g)) {
    assert.ok(existsSync(join(site, src.startsWith('/') ? src.slice(1) : `docs/ai-assistants/${src}`)), src);
  }
});
