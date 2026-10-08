const text = value => typeof value === 'string' ? value : '';
export function normalizedHeaders(headers) {
  return Object.fromEntries(Object.entries(headers || {}).map(([key, value]) => [key.toLowerCase(), value]));
}
export function structuredSignals(state) {
  const fired = [];
  const add = (id, weight) => fired.push({ id, weight });
  const headers = normalizedHeaders(state.headers);
  const ua = text(state.ua) || text(headers['user-agent']);
  const signals = Array.isArray(state.signals) ? state.signals.map(text).join(' ') : '';
  if (/botnet|credential[ _-]?stuffing|card[ _-]?testing|sqlmap|nikto/i.test(`${ua} ${text(state.notes)} ${signals}`)) add('malicious_tool', 0.55);
  if (/headless|puppeteer|selenium|scrapy/i.test(`${ua} ${signals}`)) add('headless_automation', 0.25);
  let path = text(state.path).split(/[?#]/)[0];
  try { path = decodeURIComponent(path); } catch { /* Score the original malformed path. */ }
  if (/(?:^|\/)(?:wp-login(?:\.php)?|xmlrpc\.php|\.env(?:\.[^/]*)?|\.git|phpmyadmin|pma|wp-admin)(?:\/|$)/i.test(path)) add('probe_path', 0.55);
  if (/(?:^|[/_.-])(login|signin|oauth|checkout)(?:$|[/_.? #-])/i.test(text(state.path)) &&
      (text(state.method).toUpperCase() === 'POST' || /credential|automation/i.test(signals))) add('sensitive_action', 0.1);
  if (Number.isFinite(state.prior_score) && state.prior_score > 0) add('prior_risk', Math.max(0, Math.min(1, state.prior_score)) * 0.25);
  if (Number.isFinite(state.account_age_hours) && state.account_age_hours < 1) add('new_account', 0.1);
  // Absent header context is unknown; an explicitly supplied collection is observable.
  if (state.headers && !text(headers['accept-language']).trim()) add('missing_accept_language', 0.1);
  const order = headers._order ?? headers.header_order ?? state.header_order;
  if (Array.isArray(order)) {
    const names = order.map(name => text(name).toLowerCase());
    const observed = names.filter(name => !['_order', 'header_order'].includes(name));
    if (new Set(observed).size !== observed.length || observed.some(name => !(name in headers)) ||
        Object.keys(headers).some(name => !['_order', 'header_order'].includes(name) && !observed.includes(name))) add('header_order_inconsistent', 0.1);
    // Browser families vary, but send UA before Accept and Accept before language.
    const baseline = ['user-agent', 'accept', 'accept-language'].filter(name => names.includes(name));
    if (baseline.some((name, index) => index > 0 && names.indexOf(name) < names.indexOf(baseline[index - 1]))) add('unusual_header_order', 0.1);
  }
  const brands = text(headers['sec-ch-ua']);
  const chromium = /(?:Chrome|Chromium|CriOS|Edg|OPR)\//i.test(ua);
  const uaMajor = ua.match(/(?:Chrome|Chromium|CriOS)\/(\d+)/)?.[1];
  const hintMajor = brands.match(/"(?:Chromium|Google Chrome)"\s*;\s*v="(\d+)/i)?.[1];
  if (ua && brands && ((/"(?:Chromium|Google Chrome|Microsoft Edge)"/i.test(brands) && !chromium) ||
      (/"Microsoft Edge"/i.test(brands) && !/Edg(?:A|iOS)?\//i.test(ua)) ||
      (/"Firefox"/i.test(brands) && !/(?:Firefox|FxiOS)\//i.test(ua)) ||
      (/"Safari"/i.test(brands) && (!/Version\//i.test(ua) || chromium)) ||
      (uaMajor && hintMajor && uaMajor !== hintMajor))) add('ua_client_hint_mismatch', 0.2);
  const mobile = text(headers['sec-ch-ua-mobile']).trim();
  if (ua && ['?0', '?1'].includes(mobile) && (mobile === '?1') !== /Mobile|iPhone|iPod/i.test(ua)) add('ua_mobile_hint_mismatch', 0.2);
  if (ua && headers['user-agent'] && ua !== headers['user-agent']) add('ua_header_mismatch', 0.1);
  return fired;
}
