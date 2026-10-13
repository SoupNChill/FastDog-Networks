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
