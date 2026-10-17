// Canonical /_fastdog control-path detection. Express matches control routes on the raw path
// (case-insensitively, without collapsing slashes), so variants such as //_fastdog/metrics miss
// them and would otherwise fall through to the tenant proxy.
const PREFIX = '/_fastdog';

export function rawPathname(url) {
  let s = String(url || '');
  if (!s.startsWith('/')) {
    const m = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i.exec(s);
    s = m ? s.slice(m[0].length) : s;
  }
  const end = s.search(/[?#]/);
  return end === -1 ? s : s.slice(0, end);
}

export function canonicalPath(raw) {
  // Decode once; malformed escapes are left as-is rather than throwing.
  const decoded = String(raw)
    .replace(/%([0-9a-f]{2})/gi, (_m, h) => String.fromCharCode(parseInt(h, 16)))
    .replaceAll('\\', '/');
  const out = [];
  for (const seg of decoded.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') out.pop();
    else out.push(seg);
  }
  const trailing = out.length > 0 && /\/(\.{1,2})?$/.test(decoded) ? '/' : '';
  return `/${out.join('/')}${trailing}`;
}

function underControl(canonical) {
  const c = canonical.toLowerCase();
  return c === PREFIX || c.startsWith(`${PREFIX}/`);
}

// Under the control namespace by canonical form, but not spelled exactly as a raw control path.
export function isNonCanonicalControlPath(url) {
  const raw = rawPathname(url);
  const canonical = canonicalPath(raw);
  if (!underControl(canonical)) return false;
  return raw !== canonical || !(raw === PREFIX || raw.startsWith(`${PREFIX}/`));
}

// Under the control namespace by any spelling.
export function isControlPath(url) {
  return underControl(canonicalPath(rawPathname(url)));
}
