export function localHeuristic(state) {
  const lower = JSON.stringify(state).toLowerCase();
  let score = 0.2;
  if (/botnet|credential.?stuff|card.?test|sqlmap|nikto/.test(lower)) score += 0.55;
  if (/headless|puppeteer|selenium|scrapy/.test(lower)) score += 0.25;
  if (/login|signin|oauth|checkout/.test(lower)) score += 0.1;
  if (typeof state === 'object' && state !== null) {
    if (typeof state.prior_score === 'number') score += Math.max(0, Math.min(1, state.prior_score)) * 0.25;
    if (typeof state.account_age_hours === 'number' && state.account_age_hours < 1) score += 0.1;
  }
  score = Math.min(score, 0.99);
  if (score >= 0.75) return { action: 'block', confidence: score, reason: 'high_risk_signals', engine: 'local_heuristic_v1' };
  if (score >= 0.45) return { action: 'challenge', confidence: score, reason: 'ambiguous_automation', engine: 'local_heuristic_v1' };
  return { action: 'allow', confidence: 1 - score, reason: 'low_risk', engine: 'local_heuristic_v1' };
}
