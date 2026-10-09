import { randomBytes, scrypt as derive, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { commonPasswords } from './common-passwords.js';
const scrypt = promisify(derive);
const parameters = Object.freeze({ N: 32768, r: 8, p: 1 });
export function validPassword(password) {
  return typeof password === 'string' && password.length >= 12 && password.length <= 1024
    && !commonPasswords.has(password.toLowerCase());
}
export async function hashPassword(password) {
  if (!validPassword(password)) throw new Error('Password policy');
  const salt = randomBytes(16).toString('hex');
  const hash = await scrypt(password, Buffer.from(salt, 'hex'), 32, { ...parameters, maxmem: 64 * 1024 * 1024 });
  return { algorithm: 'scrypt', ...parameters, salt, hash: hash.toString('hex') };
}
export async function verifyPassword(password, stored) {
  if (typeof password !== 'string' || password.length > 1024 || !stored
    || stored.algorithm !== 'scrypt' || stored.N !== parameters.N || stored.r !== 8 || stored.p !== 1
    || !/^[a-f0-9]{32}$/.test(stored.salt) || !/^[a-f0-9]{64}$/.test(stored.hash)) return false;
  const actual = await scrypt(password, Buffer.from(stored.salt, 'hex'), 32, { ...parameters, maxmem: 64 * 1024 * 1024 });
  return timingSafeEqual(actual, Buffer.from(stored.hash, 'hex'));
}
// Unknown accounts still incur the same password derivation cost.
export const dummyPassword = Object.freeze({ algorithm: 'scrypt', ...parameters, salt: '0'.repeat(32), hash: '0'.repeat(64) });
