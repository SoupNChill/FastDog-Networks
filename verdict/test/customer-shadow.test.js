import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, appendFileSync, readFileSync, statSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scoreScrubbedLine, createCountStore, createCustomerTail, excludedHosts } from '../src/shadow/customer.js';
import { resetVelocity } from '../src/engine/heuristic.js';

const HOUR = 3600000;
const NOW = Date.parse('2026-10-16T12:30:00Z');
const temp = (t) => { const d = mkdtempSync(join(tmpdir(), 'vcs-')); t.after(() => rmSync(d, { recursive: true, force: true })); return d; };
const line = (uri, method = 'GET') => JSON.stringify({ request: { client_ip: '198.51.100.0', method, uri }, status: 200, duration: 0.01 });

test('scrubbed lines: no headers means unknown, not suspicious; probe paths still count', () => {
  resetVelocity();
  assert.equal(scoreScrubbedLine(line('/')), 'allow');
  assert.equal(scoreScrubbedLine(line('/about')), 'allow');
  assert.equal(scoreScrubbedLine(line('/wp-login.php')), 'block');
  assert.equal(scoreScrubbedLine('not json'), null);
});

test('count store keeps per-host hourly counts only, prunes after 25h, writes 0640 atomically', async (t) => {
  const dir = temp(t);
  let clock = NOW;
  const file = join(dir, 'counts.json');
  const store = createCountStore(file, { now: () => clock });
  await store.load();
  store.add('app.example.test', 'allow');
  store.add('app.example.test', 'challenge');
  store.add('app.example.test', 'block');
  store.add('../evil', 'block');
  assert.equal(await store.flush(), true);
  assert.equal(await store.flush(), false, 'nothing new, no write');
  const saved = JSON.parse(readFileSync(file, 'utf8'));
  assert.deepEqual(saved.hosts, { 'app.example.test': { [Math.floor(NOW / HOUR)]: { scored: 3, block: 1, challenge: 1 } } });
  assert.equal(statSync(file).mode & 0o777, 0o640);
  assert.deepEqual(readdirSync(dir), ['counts.json']);
  clock += 26 * HOUR;
  store.add('other.example.test', 'allow');
  await store.flush();
  assert.deepEqual(Object.keys(JSON.parse(readFileSync(file, 'utf8')).hosts), ['other.example.test']);
});

test('tail: new files start at the end, rotation restarts, partial lines wait, excluded hosts are skipped', async (t) => {
  resetVelocity();
  const logs = temp(t);
  const out = join(temp(t), 'counts.json');
  const store = createCountStore(out, { now: () => NOW });
  await store.load();
  writeFileSync(join(logs, 'app.example.test.log'), line('/old') + '\n');
  writeFileSync(join(logs, 'first.example.test.log'), '');
  writeFileSync(join(logs, 'notes.txt'), 'x');
  writeFileSync(join(logs, 'app.example.test-2026-10-16T10-00-00.000.log'), '');
  writeFileSync(join(logs, 'bad..name.log'), line('/'));
  const tail = createCustomerTail({ logDir: logs, store, exclude: excludedHosts({ VERDICT_SHADOW_CUSTOMER_EXCLUDE: 'First.example.test' }), now: () => NOW });
  assert.equal(await tail.poll(), 0, 'existing lines are not backfilled');
  appendFileSync(join(logs, 'app.example.test.log'), line('/') + '\n' + line('/.env') + '\n' + line('/partial'));
  appendFileSync(join(logs, 'first.example.test.log'), line('/') + '\n');
  appendFileSync(join(logs, 'app.example.test-2026-10-16T10-00-00.000.log'), line('/') + '\n');
  assert.equal(await tail.poll(), 2);
  appendFileSync(join(logs, 'app.example.test.log'), '\n');
  assert.equal(await tail.poll(), 1, 'the partial line is scored once complete');
  writeFileSync(join(logs, 'app.example.test.log'), line('/x') + '\n');
  assert.equal(await tail.poll(), 1, 'rotated file read from the start');
  const hosts = store.snapshot().hosts;
  assert.deepEqual(Object.keys(hosts), ['app.example.test']);
  assert.deepEqual(Object.values(hosts['app.example.test'])[0], { scored: 4, block: 1, challenge: 0 });
  const text = readFileSync(out, 'utf8');
  for (const leak of ['198.51.100', '/.env', '/partial', 'GET']) assert.equal(text.includes(leak), false, `counts file never holds ${leak}`);
});

test('shadow only: no enforce path imports the customer scorer or its counts', () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  const files = [...readdirSync(join(root, 'src/edge')).map((f) => join(root, 'src/edge', f)), join(root, 'src/server.js'),
    join(root, 'src/routes/v1.js'), join(root, 'scripts/caddy-apply-hosts.js'), join(root, 'src/config/hosts.js')];
  for (const f of files) {
    const src = readFileSync(f, 'utf8');
    assert.equal(/shadow\/customer|customer-counts|SHADOW_COUNTS/.test(src), false, f);
  }
  const unit = readFileSync(join(root, 'deploy/verdict-shadow-customer.service'), 'utf8');
  assert.match(unit, /^User=verdict-shadow$/m);
  assert.doesNotMatch(unit, /^User=root/m);
  assert.match(unit, /^Nice=\d+/m);
  assert.match(unit, /^CPUQuota=\d+%/m);
  assert.match(unit, /^MemoryMax=/m);
  assert.match(unit, /^ReadOnlyPaths=\/var\/log\/caddy/m);
  assert.doesNotMatch(unit, /^EnvironmentFile/m);
  assert.doesNotMatch(unit, /ENFORCE|VERDICT_EDGE_FORCE/);
});
