const velocity = new Map();
export const resetVelocity = () => velocity.clear();
const text = value => typeof value === 'string' ? value : '';

export function localHeuristic(input, { now = Date.now() } = {}) {
  const state = input && typeof input === 'object' ? input : {};
  const signals = Array.isArray(state.signals) ? state.signals.map(text).join(' ') : '';
  const ua = text(state.ua);
  let score = 0.2;
  if (/botnet|credential[ _-]?stuffing|card[ _-]?testing|sqlmap|nikto/i.test(`${ua} ${text(state.notes)} ${signals}`)) score += 0.55;
  if (/headless|puppeteer|selenium|scrapy/i.test(`${ua} ${signals}`)) score += 0.25;
  if (/(?:^|[/_.-])(login|signin|oauth|checkout)(?:$|[/_.? #-])/i.test(text(state.path)) &&
      (text(state.method).toUpperCase() === 'POST' || /credential|automation/i.test(signals))) score += 0.1;
  if (Number.isFinite(state.prior_score)) score += Math.max(0, Math.min(1, state.prior_score)) * 0.25;
  if (Number.isFinite(state.account_age_hours) && state.account_age_hours < 1) score += 0.1;
  if (typeof state.ip === 'string' && state.ip) {
    for (const [ip, bucket] of velocity) if (now - bucket.start >= 60_000) velocity.delete(ip);
    const bucket = velocity.get(state.ip) || { start: now, hits: 0 };
    bucket.hits += 1;
    velocity.set(state.ip, bucket);
    if (bucket.hits > 30) score += 0.2;
  }
  score = Math.min(score, 0.99);
  const engine = 'local_heuristic_v2';
  if (score >= 0.75) return { action: 'block', confidence: score, reason: 'high_risk_signals', engine };
  if (score >= 0.45) return { action: 'challenge', confidence: score, reason: 'ambiguous_automation', engine };
  return { action: 'allow', confidence: 1 - score, reason: 'low_risk', engine };
}
