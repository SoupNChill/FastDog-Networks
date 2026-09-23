export function computeBackoffMs(attempt, { baseMs = 1000, maxMs = 30000, random = Math.random } = {}) {
  if (!Number.isInteger(attempt) || attempt < 0 || baseMs <= 0 || maxMs <= 0) {
    throw new RangeError('attempt must be nonnegative and delays must be positive');
  }
  return Math.floor(random() * Math.min(maxMs, baseMs * 2 ** attempt));
}
