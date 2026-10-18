import { domainToASCII } from 'node:url';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
export const token = () => randomBytes(32).toString('hex');
export const digest = (value) => createHash('sha256').update(String(value)).digest('hex');
export const equal = (a, b) => typeof a === 'string' && typeof b === 'string'
  && timingSafeEqual(Buffer.from(digest(a), 'hex'), Buffer.from(digest(b), 'hex'));
export function tenantId() {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  return `t_${Array.from(randomBytes(20), (byte) => alphabet[byte & 31]).join('')}`;
}
export function normalizeEmail(value) {
  if (typeof value !== 'string' || /[\s\x00-\x1f\x7f]/.test(value)) return null;
  const parts = value.split('@');
  if (parts.length !== 2) return null;
  const [local, inputDomain] = parts;
  if (local.length > 64 || !/^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/i.test(local)) return null;
  // Reject URL syntax before domainToASCII, which also accepts URL host inputs.
  if (/[\/:?#%\[\]\\]/.test(inputDomain)) return null;
  const domain = domainToASCII(inputDomain).toLowerCase();
  if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(domain)) return null;
  const email = `${local.toLowerCase()}@${domain}`;
  return email.length <= 254 ? email : null;
}
