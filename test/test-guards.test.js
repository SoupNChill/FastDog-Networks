import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { laneSkip } from './helpers/lanes.js';

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
