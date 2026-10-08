import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { decide } from '../src/engine/jev.js';
import { resetVelocity } from '../src/engine/heuristic.js';

const requests = JSON.parse(await readFile(new URL('../fixtures/good-requests.json', import.meta.url), 'utf8'));
resetVelocity();
const counts = { allow: 0, challenge: 0, block: 0 };
for (const state of requests) {
  // Explicitly disable the paid engine regardless of the caller's environment.
  const result = await decide(state, { apiKey: '' });
  counts[result.action]++;
}
const allowRate = counts.allow / requests.length;
console.log(JSON.stringify({ total: requests.length, ...counts, allow_rate: allowRate, allow_percent: allowRate * 100 }));
assert.ok(allowRate >= 0.95, `Allow rate ${allowRate * 100}% is below 95%`);
