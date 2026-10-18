import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, existsSync, rmdirSync } from 'node:fs';
import { join } from 'node:path';
import { acquireLock } from '../src/mail-lock.js';
import { temporary } from './helpers.js';

for (const releasedAt of [1, 2, 3, null]) {
  test(`mail lock retries contention: release at ${releasedAt}`, (t) => {
    const path = join(temporary(t), 'lock');
    mkdirSync(path);
    let sleeps = 0;
    t.mock.method(Atomics, 'wait', (buffer, index, value, timeout) => {
      assert.equal(timeout, 10);
      if (++sleeps === releasedAt) rmdirSync(path);
      return 'timed-out';
    });
    const release = acquireLock(path);
    assert.equal(sleeps, releasedAt ?? 3);
    assert.ok(existsSync(path));
    if (releasedAt) { assert.equal(typeof release, 'function'); release(); assert.ok(!existsSync(path)); }
    else assert.equal(release, null);
  });
}
