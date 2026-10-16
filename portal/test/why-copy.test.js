import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(`../public/${path}`, import.meta.url), 'utf8');

test('every setup step explains why in one plain sentence', () => {
  const connect = read('connect.html');
  assert.match(connect, /Why no ports\?<\/strong> The connection software makes one outbound connection/);
  assert.match(read('hostname.html'), /Why two records\?<\/strong> The CNAME sends visitors[^<]*TXT proves you own the domain/);
  const hostname = read('js/hostname.js');
  assert.match(hostname, /Grey cloud means Cloudflare only answers DNS/);
  assert.match(hostname, /Why: visitors who type your address are sent to FastDog/);
  assert.match(hostname, /Why: only someone who controls your domain/);
});

test('a "What just happened?" explainer appears only once the server is healthy', () => {
  const connect = read('connect.html');
  assert.match(connect, /<section id="what-happened" class="what-happened" hidden/);
  assert.match(connect, /What just happened\?/);
  const view = read('js/agent-view.js');
  assert.match(view, /explainer\.hidden = !healthy/);
});
