// With PORTAL_AGENT_BOOTSTRAP_ENABLED unset, every existing page, script and route answers exactly as before milestone 4.
// fixtures/flag-off-snapshot.json was recorded from the pre-milestone-4 portal (HEAD d9d780c) with flag-off-recorder.js
// and verified identical to the milestone-4 portal at the time; per-run secrets, IDs and times are masked.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { record } from './flag-off-recorder.js';

test('flag off: existing pages, scripts and routes are byte-for-byte unchanged (snapshot)', async (t) => {
  const snapshot = JSON.parse(readFileSync(new URL('./fixtures/flag-off-snapshot.json', import.meta.url), 'utf8'));
  assert.deepEqual(await record(t), snapshot);
});
