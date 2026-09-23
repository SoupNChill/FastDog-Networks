import { it } from 'node:test';
import assert from 'node:assert/strict';
import { computeBackoffMs } from '../agent/backoff.js';
import { computeBackoffMs as prodBackoff } from '../deploy/prod1-fastdog-agent/app/backoff.js';
import { reconnectLoop } from '../agent/index.js';

it('full jitter stays below the exponential cap and then the maximum', () => {
  for (const backoff of [computeBackoffMs, prodBackoff]) {
    assert.equal(backoff(0, { random: () => 0 }), 0);
    assert.equal(backoff(0, { random: () => 0.999 }), 999);
    assert.equal(backoff(2, { random: () => 0.5 }), 2000);
    assert.equal(backoff(20, { random: () => 0.5 }), 15000);
    assert.throws(() => backoff(-1), RangeError);
  }
});

it('uses each seeded random draw for full jitter', () => {
  const draws = [0.1, 0.8, 0.25];
  const random = () => draws.shift();
  assert.deepEqual([0, 1, 2].map((attempt) => computeBackoffMs(attempt, { random })), [100, 1600, 1000]);
});

it('re-registers after a drop and resets attempt after welcome', async () => {
  const ids = [];
  const delays = [];
  let calls = 0;
  const done = new Error('done');
  await assert.rejects(reconnectLoop({
    registerAgent: async () => ({ id: `id-${++calls}` }),
    connect: async (id, onWelcome) => {
      ids.push(id);
      if (id === 'id-2') onWelcome();
    },
    backoff: (attempt) => attempt + 1,
    delay: async (ms) => {
      delays.push(ms);
      if (delays.length === 3) throw done;
    },
  }), done);
  assert.deepEqual(ids, ['id-1', 'id-2', 'id-3']);
  assert.deepEqual(delays, [1, 1, 2]);
});

it('retries registration failure without exiting', async () => {
  let calls = 0;
  const done = new Error('done');
  await assert.rejects(reconnectLoop({
    registerAgent: async () => {
      calls++;
      if (calls === 1) throw new Error('edge down');
      return { id: 'fresh' };
    },
    connect: async (id) => assert.equal(id, 'fresh'),
    delay: async () => { if (calls === 2) throw done; },
    backoff: () => 0,
  }), done);
  assert.equal(calls, 2);
});
