export const statuses = Object.freeze({
  unauthorized: 401, not_found: 404, hostname_not_found: 404, method_not_allowed: 405,
  invalid_hostname: 400, reserved_hostname: 400, invalid_limit: 400, invalid_tenant: 400,
  invalid_json: 400, payload_too_large: 413, hostname_unavailable: 409,
  hostname_limit_reached: 409, not_active: 409, invalid_origin: 400, token_used: 409, invalid_key: 400, key_limit_reached: 409, forbidden: 403, plan_required: 403, password_required: 403, rate_limited: 429, internal_error: 500,
});
export function fail(code, retryAfter) {
  return Object.assign(new Error(code), { code, status: statuses[code] || 500, retry_after: retryAfter });
}
