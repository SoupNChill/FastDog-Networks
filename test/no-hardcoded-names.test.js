import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, basename, relative } from 'node:path';
import { scanRepository, scanText, filesUnder, hostnameViolations, lineHash } from './helpers/name-scanner.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const denyNames = JSON.parse(readFileSync(new URL('./deny-names.json', import.meta.url), 'utf8'));
const allow = JSON.parse(readFileSync(new URL('./no-hardcoded-names.allow.json', import.meta.url), 'utf8'));

test('deny-list is lowercase data and exemptions are explicitly reviewed', () => {
  assert.ok(Array.isArray(denyNames) && denyNames.length > 0);
  assert.equal(new Set(denyNames).size, denyNames.length);
  for (const name of denyNames) assert.ok(typeof name === 'string' && name.length > 2 && name === name.toLowerCase());
  for (const [path, rule] of Object.entries(allow)) {
    assert.ok(rule.reason?.length > 15, path);
    assert.ok(!path.includes('*') && !path.includes('..'), 'no wildcard or traversal exemptions');
    if (rule.data) assert.equal(path, 'test/deny-names.json');
    else if (rule.documentation) assert.ok(['docs/TENANT_API.md', 'docs/SELF_SERVE_PLAN.md'].includes(path));
    else assert.ok(rule.lines && Object.keys(rule.lines).length > 0, 'legacy exemptions pin only reviewed lines');
  }
});

test('scoped source scan contains no new real tenant, customer, or owner names', () => {
  assert.deepEqual(scanRepository(root, denyNames, allow), []);
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
