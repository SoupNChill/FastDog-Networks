export function laneSkip(available, reason) {
  if (available) return false;
  if (process.env.REQUIRE_LANES === '1') throw new Error(reason);
  return reason;
}
