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
  if (typeof value !== 'string' || value.length > 254) return null;
  const email = value.trim().toLowerCase();
  return /^[^\s@\x00-\x1f\x7f]+@[^\s@\x00-\x1f\x7f]+\.[^\s@\x00-\x1f\x7f]+$/.test(email) ? email : null;
}
