import assert from 'node:assert/strict';
import { replayFixtures } from './replay-fixtures.js';
const report = await replayFixtures();
console.log(JSON.stringify(report));
assert.ok(report.good.total >= 500 && report.bad.total >= 200, 'Fixture suite is too small');
assert.ok(report.fp_rate <= 0.01, `FP ${report.fp_rate * 100}% exceeds 1%`);
assert.ok(report.fn_rate <= 0.05, `FN ${report.fn_rate * 100}% exceeds 5%`);
