export function fixedClock(initial = Date.parse('2026-10-10T12:00:00.000Z')) {
  let value = initial;
  return { now: () => value, advance: (ms) => { value += ms; return value; } };
}
