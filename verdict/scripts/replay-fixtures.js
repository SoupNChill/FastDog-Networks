import { readFile } from 'node:fs/promises';
import { localDecision, resetVelocity } from '../src/engine/heuristic.js';
import { createGoodBotVerifier } from '../src/engine/goodbots.js';

export async function replayFixtures() {
  const report = {};
  for (const kind of ['good', 'bad']) {
    const fixtures = JSON.parse(await readFile(new URL(`../fixtures/${kind}-requests.json`, import.meta.url), 'utf8'));
    resetVelocity();
    const counts = { allow: 0, challenge: 0, block: 0 };
    for (const { mock_dns, ...state } of fixtures) {
      // Fixture metadata supplies DNS answers, never a trusted verdict. No network calls.
      const verifyBot = createGoodBotVerifier({ resolver: {
        reverse: async () => mock_dns?.hosts || [],
        lookup: async () => (mock_dns?.addresses || []).map(address => ({ address })),
      } });
      counts[(await localDecision(state, { verifyBot })).action]++;
    }
    report[kind] = { total: fixtures.length, ...counts };
  }
  report.fp_rate = (report.good.challenge + report.good.block) / report.good.total;
  report.fn_rate = report.bad.allow / report.bad.total;
  resetVelocity();
  return report;
}
