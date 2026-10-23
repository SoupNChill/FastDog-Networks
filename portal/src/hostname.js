import { domainToASCII } from 'node:url';
import { isIP } from 'node:net';
export function normalizeHostname(input) {
  const invalid = (message = 'Use a domain name such as app.example.com. Each part must start and end with a letter or number.') => { throw Object.assign(new Error(message), { code: 'invalid_hostname' }); };
  if (typeof input !== 'string') return invalid('Enter your website address, such as app.example.com.');
  let host = input.trim().replace(/\.$/, '').toLowerCase();
  if (/\s/u.test(host)) return invalid('Remove the spaces inside your website address.');
  if (/[/:]/u.test(host)) return invalid('Enter only the website address, without https://, a port or a path.');
  if (!host || /[\s\x00-\x1f\x7f*:/\\@?#%]/u.test(host)) return invalid();
  host = domainToASCII(host);
  const labels = host.split('.');
  if (host.length > 253 || labels.some((label) => label.length > 63)) return invalid('This address is too long. Use at most 253 characters, with at most 63 between dots.');
  if (labels.length < 2) return invalid('Enter a full address with a dot, such as app.example.com.');
  if (!host || host.length > 253 || isIP(host) || labels.length < 2
    || labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
    || !/^(?:[a-z]{2,63}|xn--[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)$/.test(labels.at(-1))) return invalid();
  return host;
}
export function isReserved(host, reservedSuffixes = []) {
  return reservedSuffixes.some((suffix) => {
    const name = suffix.trim().toLowerCase().replace(/\.$/, '');
    return name && (host === name || host.endsWith(`.${name}`));
  });
}

// Reserved names for API key allow-lists, mirroring the edge's reservedSuffixes() (src/lib/config.js):
// PORTAL_RESERVED_SUFFIXES (comma-separated) if set, else the generic defaults; plus the registrable
// domain (final two labels) of the portal origin and the public edge URL. The edge stays the authority
// when a hostname is created; this only stops a key from being locked to a name that can never be added.
export const DEFAULT_RESERVED_SUFFIXES = Object.freeze(['localhost', 'local', 'lan', 'internal', 'test', 'invalid', 'example']);
export function portalReservedSuffixes(env = {}) {
  const configured = env.PORTAL_RESERVED_SUFFIXES;
  const suffixes = configured !== undefined ? configured.split(',').map((s) => s.trim().toLowerCase().replace(/\.$/, '')).filter(Boolean)
    : [...DEFAULT_RESERVED_SUFFIXES];
  const domains = [env.PORTAL_ORIGIN, env.PORTAL_EDGE_URL].filter(Boolean).map((url) => {
    try { return new URL(url).hostname.toLowerCase().split('.').slice(-2).join('.'); } catch { return ''; }
  }).filter((d) => d.includes('.'));
  return [...new Set([...domains, ...suffixes])];
}
// Internal operator test labels (e2e-<label>.<domain>, one extra label) are decided by the edge per tenant.
const TEST_LABEL = /^e2e-[a-z0-9-]{1,40}$/;
export function isReservedForKey(host, reservedSuffixes = []) {
  if (!isReserved(host, reservedSuffixes)) return false;
  const dot = host.indexOf('.');
  const rest = host.slice(dot + 1);
  return !(TEST_LABEL.test(host.slice(0, dot)) && rest.includes('.') && reservedSuffixes.some((s) => s.trim().toLowerCase().replace(/\.$/, '') === rest));
}
