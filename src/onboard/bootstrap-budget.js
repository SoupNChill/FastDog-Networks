// These ledgers live inside agent-bootstrap in the authoritative auth snapshot.
const DAY = 86400000;
const fail = () => Object.assign(new Error('rate_limited'), { status: 429, code: 'rate_limited', retry_after: 3600 });
export function chargeReissue(state, tenant, host, issuer, time) {
  if (!state.codes.some((c) => c.tenant_id === tenant && c.hostname === host && !c.cancelled && !c.request_fingerprint && c.expires_at > time)) return;
  const key = JSON.stringify([tenant, issuer.kind, issuer.id]);
  const day = Math.floor(time / DAY);
  const ledger = state.reissues ??= {};
  for (const [id, times] of Object.entries(ledger)) {
    const live = times.filter((v) => v > time - 3600000 || Math.floor(v / DAY) === day);
    if (live.length) ledger[id] = live; else delete ledger[id];
  }
  const times = ledger[key] ?? [];
  if (times.filter((v) => v > time - 3600000).length >= 3 || times.filter((v) => Math.floor(v / DAY) === day).length >= 6) throw fail();
  ledger[key] = [...times, time];
}
export function refundIssuance(state, code, time) {
  // Missing charge metadata (including pre-M5 records) is uncertain, never creditable.
  if (code.refund) return { refunded: true, refunded_units: code.refund.units };
  if (code.request_fingerprint || code.redeemed_at !== undefined || !(code.cancelled || time >= code.expires_at) || code.charge?.rotations !== 1) return { refunded: false, refunded_units: 0 };
  const day = Math.floor(time / DAY), budget = state.budgets[code.hostname];
  if (code.charge.day !== day || budget?.day !== day || !(budget.rotations > 0) || (budget.refunds ?? 0) >= 3) return { refunded: false, refunded_units: 0 };
  budget.rotations--;
  budget.refunds = (budget.refunds ?? 0) + 1;
  // The scoped issuance ID is the idempotency key; issuance totals are never decremented.
  code.refund = { issuance_id: code.issuance_id, day, units: 1 };
  return { refunded: true, refunded_units: 1 };
}
