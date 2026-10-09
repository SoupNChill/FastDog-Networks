import { domainToASCII } from 'node:url';
import { isIP } from 'node:net';

export function normalizeHostname(input) {
  const invalid = () => { throw Object.assign(new Error('invalid_hostname'), { code: 'invalid_hostname', status: 400 }); };
  if (typeof input !== 'string') invalid();
  const value = input.trim().replace(/\.$/, '').toLowerCase();
  if (!value || /[\s\x00-\x1f\x7f*:/\\?#@%\[\]]/u.test(value)) invalid();
  const host = domainToASCII(value);
  const labels = host.split('.');
  if (!host || host.length > 253 || isIP(host) || labels.length < 2) invalid();
  if (labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) invalid();
  if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]+)$/.test(labels.at(-1))) invalid();
  return host;
}

export function isReserved(host, reservedSuffixes) {
  return reservedSuffixes.some((entry) => {
    const suffix = entry.trim().toLowerCase().replace(/\.$/, '');
    return suffix && (host === suffix || host.endsWith(`.${suffix}`));
  });
}
