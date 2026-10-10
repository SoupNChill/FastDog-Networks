import { domainToASCII } from 'node:url';
import { isIP } from 'node:net';
export function normalizeHostname(input) {
  const invalid = () => { throw Object.assign(new Error('invalid_hostname'), { code: 'invalid_hostname' }); };
  if (typeof input !== 'string') return invalid();
  let host = input.trim().replace(/\.$/, '').toLowerCase();
  if (!host || /[\s\x00-\x1f\x7f*:/\\@?#%]/u.test(host)) return invalid();
  host = domainToASCII(host);
  const labels = host.split('.');
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
