import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { laneSkip, LANE_FILES } from './helpers/lanes.js';

test('--lane list stays in sync with the npm test glob and every lane-gated suite', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.match(pkg.scripts.test, /(?:^|\s)test\/\*\.test\.js$/, 'lane list check assumes the test/*.test.js glob');
  const globbed = readdirSync(new URL('./', import.meta.url)).filter((name) => name.endsWith('.test.js'))
    .map((name) => name.slice(0, -'.test.js'.length));
  assert.equal(new Set(LANE_FILES).size, LANE_FILES.length, 'no duplicate lane entries');
  for (const name of LANE_FILES) assert.ok(globbed.includes(name), `lane suite ${name} is not matched by test/*.test.js`);
  // Suites that skip unless their lane is merged must also run under --lane (this file only tests the helper).
  const gated = globbed.filter((name) => name !== 'test-guards' &&
    /\blaneSkip\(/.test(readFileSync(new URL(`./${name}.test.js`, import.meta.url), 'utf8')));
  assert.ok(gated.length > 0);
  for (const name of gated) assert.ok(LANE_FILES.includes(name), `lane-gated suite ${name} is missing from --lane`);
  const runner = readFileSync(new URL('./helpers/run-tests.js', import.meta.url), 'utf8');
  assert.match(runner, /import \{ LANE_FILES \} from '\.\/lanes\.js'/);
  assert.doesNotMatch(runner, /\[\s*'tenant-/, 'runner must not keep its own lane list');
});

test('required lanes fail closed; optional missing lanes explain their skip', () => {
  const previous = process.env.REQUIRE_LANES;
  try {
    process.env.REQUIRE_LANES = '1';
    assert.equal(laneSkip(true, 'missing lane'), false);
    assert.throws(() => laneSkip(false, 'missing lane'), /missing lane/);
    process.env.REQUIRE_LANES = '0';
    assert.equal(laneSkip(false, 'missing lane'), 'missing lane');
  } finally {
    if (previous === undefined) delete process.env.REQUIRE_LANES;
    else process.env.REQUIRE_LANES = previous;
  }
});

test('offline preload blocks remote commands through every child-process API', () => {
  const result = spawnSync(process.execPath, ['--require', './test/helpers/offline.cjs', '-e', `
    const assert = require('node:assert/strict');
    const cp = require('node:child_process');
    for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync']) {
      for (const command of ['/usr/bin/curl', 'curl']) {
        if (name === 'spawnSync') assert.equal(cp[name](command, []).status, 1);
        else assert.throws(() => cp[name](command), /external command disabled/);
      }
    }
    assert.throws(() => cp.exec('true; curl https://example.invalid'), /external command disabled/);
    assert.throws(() => cp.spawn('sh', ['-c', 'curl https://example.invalid']), /external command disabled/);
    assert.equal(cp.execFileSync(process.execPath, ['-p', '1 + 1'], {encoding:'utf8'}).trim(), '2');
  `], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});
