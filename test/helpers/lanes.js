// Suites run by `node test/helpers/run-tests.js --lane`; test-guards checks this list against the npm test glob.
export const LANE_FILES = Object.freeze(['tenant-isolation', 'tenant-abuse', 'portal-isolation', 'hostname-table', 'no-hardcoded-names']);

export function laneSkip(available, reason) {
  if (available) return false;
  if (process.env.REQUIRE_LANES === '1') throw new Error(reason);
  return reason;
}
