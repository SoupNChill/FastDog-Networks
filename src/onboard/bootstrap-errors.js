// Never reflect exception text, arbitrary exception codes, or upstream diagnostics.
const codes = new Map([
  [400, new Set(['invalid_request', 'invalid_json', 'invalid_hostname', 'invalid_tenant'])],
  [401, new Set(['unauthorized'])], [404, new Set(['not_found', 'hostname_not_found', 'bootstrap_not_found', 'candidate_not_found'])],
  [405, new Set(['method_not_allowed'])], [409, new Set(['bootstrap_used', 'candidate_mismatch'])],
  [410, new Set(['bootstrap_expired'])], [413, new Set(['payload_too_large'])],
  [429, new Set(['rate_limited'])], [503, new Set(['bootstrap_unavailable'])],
]);
export function bootstrapError(error) {
  const known = codes.get(error?.status)?.has(error?.code);
  return { status: known ? error.status : 503, code: known ? error.code : 'bootstrap_unavailable',
    ...(known && Number.isSafeInteger(error.retry_after) && error.retry_after > 0 ? { retry_after: error.retry_after } : {}) };
}
