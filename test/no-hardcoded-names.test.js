// Exemptions require review because each one weakens the tenant-name guard.
// Prefer synthetic fixtures. For legitimate existing configuration/documentation,
// add a reason and SHA-256 lineHash of the exact line (without its newline) to
// no-hardcoded-names.allow.json, with the exact occurrence count. Keep paths
// sorted to group directories. Remove stale hashes; never regenerate the legacy
// list wholesale. Any change to the committed counts below needs explicit review.
// Only the deny-list data itself may have a whole-file exemption.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, basename, relative } from 'node:path';
import { scanRepository, scanText, filesUnder, hostnameViolations, lineHash, unscannableAllow } from './helpers/name-scanner.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const denyNames = JSON.parse(readFileSync(new URL('./deny-names.json', import.meta.url), 'utf8'));
const allow = JSON.parse(readFileSync(new URL('./no-hardcoded-names.allow.json', import.meta.url), 'utf8'));

test('deny-list is lowercase data and exemptions are explicitly reviewed', () => {
  assert.ok(Array.isArray(denyNames) && denyNames.length > 0);
  assert.equal(new Set(denyNames).size, denyNames.length);
  assert.deepEqual(Object.entries(allow).filter(([, rule]) => rule.data || rule.documentation || !rule.lines)
    .map(([path]) => path), ['test/deny-names.json']);
  for (const name of denyNames) assert.ok(typeof name === 'string' && name.length > 2 && name === name.toLowerCase());
  for (const [path, rule] of Object.entries(allow)) {
    assert.ok(rule.reason?.length > 15, path);
    assert.ok(!path.includes('*') && !path.includes('..'), 'no wildcard or traversal exemptions');
    assert.deepEqual(Object.keys(rule).sort(), path === 'test/deny-names.json' ? ['data', 'reason'] : ['lines', 'reason']);
    if (path === 'test/deny-names.json') assert.equal(rule.data, true);
    else {
      assert.ok(rule.lines && Object.keys(rule.lines).length > 0, 'legacy exemptions pin only reviewed lines');
      for (const [hash, count] of Object.entries(rule.lines)) {
        assert.match(hash, /^[a-f0-9]{64}$/);
        assert.ok(Number.isSafeInteger(count) && count > 0);
      }
    }
  }
});

// Homepage onboarding: replace the old hero hash; add the required support link
// and byte-identical pricing fixture (one file, two hashes, two occurrences).
test('allowlist stays grouped by directory and at exact reviewed baseline counts', () => {
  assert.deepEqual(Object.keys(allow), Object.keys(allow).sort());
  assert.equal(Object.keys(allow).length, 62, 'review required to change exempt files');
  const lines = Object.values(allow).flatMap((rule) => Object.values(rule.lines || {}));
  assert.equal(lines.length, 352, 'review required to change line-hash entries');
  assert.equal(lines.reduce((sum, count) => sum + count, 0), 400, 'review required to change exempt occurrences');
});

test('whole-file flags cannot exempt documentation or arbitrary source files', () => {
  for (const path of ['docs/TENANT_API.md', 'docs/SELF_SERVE_PLAN.md', 'src/example.js']) {
    for (const rule of [{ documentation: true }, { data: true }]) {
      assert.equal(scanText(path, 'synthetic-denied-marker', ['synthetic-denied-marker'], { [path]: rule }).length, 1);
    }
  }
  assert.deepEqual(scanText('test/deny-names.json', 'synthetic-denied-marker', ['synthetic-denied-marker'],
    { 'test/deny-names.json': { data: true } }), []);
});

test('scoped source scan contains no new real tenant, customer, or owner names', () => {
  assert.deepEqual(scanRepository(root, denyNames, allow), []);
});

test('repository scan rejects stale hashes, deleted files and unused duplicate allowances', async (t) => {
  const { mkdtempSync, writeFileSync, unlinkSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { execFileSync } = await import('node:child_process');
  const dir = mkdtempSync(join(tmpdir(), 'scanner-stale-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  execFileSync('git', ['init', '-q', dir]);
  const path = 'example.md';
  const marker = 'synthetic-denied-marker';
  const hash = lineHash(marker);
  const baseline = { [path]: { lines: { [hash]: 2 } } };
  const scan = () => scanRepository(dir, [marker], baseline);
  writeFileSync(join(dir, path), `${marker}\n${marker}\n`);
  execFileSync('git', ['add', path], { cwd: dir });
  assert.deepEqual(scan(), []);
  writeFileSync(join(dir, path), marker);
  assert.deepEqual(scan(), [{ path, hash, unused: 1 }]);
  writeFileSync(join(dir, path), `changed ${marker}`);
  assert.deepEqual(scan(), [{ path, line: 1 }, { path, hash, unused: 2 }]);
  unlinkSync(join(dir, path));
  assert.deepEqual(scan(), [{ path, hash, unused: 2 }]);
  execFileSync('git', ['rm', '--cached', '-q', path], { cwd: dir });
  assert.deepEqual(scan(), [{ path, hash, unused: 2 }]);
});

test('scanner fails on each injected deny-list value, including uppercase and allowed legacy paths', () => {
  for (const name of denyNames) {
    assert.equal(scanText('portal/src/example.js', `const fixture = ${JSON.stringify(name.toUpperCase())};`, denyNames).length, 1);
  }
  const line = JSON.stringify(denyNames[0]);
  const path = 'src/onboard/example.js';
  const baseline = { [path]: { lines: { [lineHash(line)]: 1 } } };
  assert.deepEqual(scanText(path, line, denyNames, baseline), []);
  assert.equal(scanText(path, `${line}\n${line}`, denyNames, baseline).length, 1);
  assert.equal(scanText(path, `// new ${line}`, denyNames, baseline).length, 1);
});

test('tenant, portal, hostname and internal test literals use synthetic hostname suffixes', () => {
  const violations = [];
  for (const file of filesUnder(root, join(root, 'test'))) {
    if (!/^(tenant-|portal-|hostname-|internal-)/.test(basename(file))) continue;
    const buffer = readFileSync(file);
    if (buffer.includes(0)) continue;
    for (const host of hostnameViolations(buffer.toString('utf8'))) violations.push({ path: relative(root, file), host });
  }
  assert.deepEqual(violations, []);
});

test('hostname scanner catches literal external domains without flagging property accesses', () => {
  const external = ['outside', 'com'].join('.');
  for (const literal of [`'${external}'`, `"https://${external}/"`, '`' + external + '`']) {
    assert.deepEqual(hostnameViolations(literal), [external]);
  }
  assert.deepEqual(hostnameViolations("response.body.error; 'app.example.com'; 'x.example.test'; 'x.invalid'; 'attach.example-edge.test'; '../src/internal/server.js'"), []);
});

test('tracked-file scan covers legacy roots and scans env.js and rejects dot-env files without reading them', async (t) => {
  const { mkdtempSync, mkdirSync, writeFileSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { execFileSync } = await import('node:child_process');
  const dir = mkdtempSync(join(tmpdir(), 'scanner-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  execFileSync('git', ['init', '-q', dir]);
  const paths = ['src/status/env.js', 'src/dns/check.js', 'src/operator/check.js', 'src/billing/check.js',
    'agent/check.js', 'config/check.js', 'deploy/check.md', 'scripts/check.js', 'README.md', 'site/index.html'];
  for (const path of [...paths, '.env', '.env.local']) {
    mkdirSync(join(dir, path, '..'), { recursive: true });
    writeFileSync(join(dir, path), 'synthetic-denied-marker');
  }
  execFileSync('git', ['add', '.'], { cwd: dir });
  assert.deepEqual(scanRepository(dir, ['synthetic-denied-marker'], {}).map((hit) => hit.path).sort(), [...paths, '.env', '.env.local'].sort());
});


test('unscannable exemptions are exact paths with reviewed reasons', () => {
  assert.deepEqual(Object.keys(unscannableAllow), [
    '.env.example', 'deploy/prod1-fastdog-agent/.env.example',
    'site/apple-touch-icon.png', 'site/favicon-32.png',
    'site/fonts/Mulish-Regular.ttf', 'site/fonts/Mulish-SemiBold.ttf',
    'site/fonts/SpaceGrotesk-Bold.ttf', 'site/fonts/SpaceGrotesk-Medium.ttf',
    'portal/public/fonts/Mulish-Regular.ttf', 'portal/public/fonts/Mulish-SemiBold.ttf',
    'portal/public/fonts/SpaceGrotesk-Bold.ttf', 'portal/public/fonts/SpaceGrotesk-Medium.ttf',
    'site/og/og.png', 'verdict/.env.example',
  ]);
  for (const reason of Object.values(unscannableAllow)) assert.ok(reason.length > 15);
});

test('tracked binary, sensitive and symlink files fail unless explicitly allowed', async (t) => {
  const { mkdtempSync, writeFileSync, symlinkSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { execFileSync } = await import('node:child_process');
  const dir = mkdtempSync(join(tmpdir(), 'scanner-types-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  execFileSync('git', ['init', '-q', dir]);
  const cases = [
    ['nul.txt', Buffer.from('synthetic-denied-marker\0'), 'binary/NUL file'],
    ['binary.bin', Buffer.from([0xff, 0xfe]), 'binary/invalid UTF-8 file'],
    ['certificate.pem', 'synthetic fixture', 'sensitive file'],
    ['private.KEY', 'synthetic fixture', 'sensitive file'],
    ['bundle.p12', 'synthetic fixture', 'sensitive file'],
    ['bundle.pfx', 'synthetic fixture', 'sensitive file'],
    ['linked.txt', null, 'symlink'],
    ['dangling.txt', null, 'symlink'],
  ];
  writeFileSync(join(dir, 'target.txt'), 'safe synthetic text');
  for (const [path, content] of cases) {
    if (content === null) symlinkSync(path === 'dangling.txt' ? 'missing.txt' : 'target.txt', join(dir, path));
    else writeFileSync(join(dir, path), content);
  }
  execFileSync('git', ['add', '.'], { cwd: dir });
  const expected = cases.map(([path, , reason]) => ({ path, reason }))
    .sort((a, b) => a.path.localeCompare(b.path));
  const scan = (exemptions = {}) => scanRepository(dir, ['synthetic-denied-marker'], {}, exemptions)
    .sort((a, b) => a.path.localeCompare(b.path));
  assert.deepEqual(scan(), expected);
  for (const [path] of cases) {
    assert.deepEqual(scan({ [path]: 'Synthetic fixture explicitly exempted for this assertion.' }),
      expected.filter((hit) => hit.path !== path));
  }
  assert.deepEqual(scan({ '*.txt': 'Wildcards must not exempt any paths.' }), expected);
});
