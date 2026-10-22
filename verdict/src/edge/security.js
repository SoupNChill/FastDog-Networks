import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import { normalizeHost } from '../config/hosts.js';
export const sign = (payload, secret) => createHmac('sha256', secret).update(payload).digest('base64url');
export function equal(a, b) { if (typeof a !== 'string' || typeof b !== 'string') return false; const x=Buffer.from(a), y=Buffer.from(b); return x.length === y.length && timingSafeEqual(x,y); }
// v6Bits: 64 (default; live rate-limit and clearance keys) or 48 (stored shadow rows only).
export function ipPrefix(ip, { v6Bits = 64 } = {}) {
  if (!isIP(ip || '')) return null;
  if (isIP(ip) === 4) return ip.split('.').slice(0, 3).join('.') + '.0/24';
  let value = ip.toLowerCase().split('%')[0];
  if (value.includes('.')) value = value.replace(/(\d+)\.(\d+)\.(\d+)\.(\d+)$/, (_, a,b,c,d) => ((+a<<8)+ +b).toString(16) + ':' + ((+c<<8)+ +d).toString(16));
  const [left, right] = value.split('::');
  const a = left ? left.split(':') : [], b = right ? right.split(':') : [];
  const words = right !== undefined ? [...a, ...Array(8-a.length-b.length).fill('0'), ...b] : a;
  const nums = words.map(x => parseInt(x,16));
  if (nums.slice(0,5).every(x => x === 0) && nums[5] === 65535) return `${nums[6]>>8}.${nums[6]&255}.${nums[7]>>8}.0/24`;
  const bits = v6Bits === 48 ? 48 : 64;
  return nums.slice(0, bits / 16).map(x => x.toString(16).padStart(4,'0')).join(':') + `::/${bits}`;
}
export const DEMO_HOST = 'verdict-demo.fastdognetworks.com';
export function binding(req) {
  const forwarded = isLoopbackAddr(req.socket?.remoteAddress) && req.get('x-forwarded-host');
  return { host: normalizeHost(forwarded || req.get('host') || ''), ip: clientIP(req), ua: req.get('user-agent') || '' };
}
export function isLoopbackAddr(address = '') {
  return address === '::1' || address === '::ffff:127.0.0.1' || /^(?:::ffff:)?127\.\d+\.\d+\.\d+$/.test(address || '');
}
/** Prefer socket when not behind local proxy; when peer is loopback (Caddy→Verdict), trust rightmost XFF hop. */
export function clientIP(req) {
  const peer = req.socket?.remoteAddress || '';
  const xff = (req.get('x-forwarded-for') || '').split(',').map(s => s.trim()).filter(Boolean);
  const real = (req.get('x-real-ip') || '').trim();
  if (isLoopbackAddr(peer)) {
    const candidate = (xff.length ? xff[xff.length - 1] : real);
    if (isIP(candidate)) return candidate;
  }
  if (isIP(peer)) return peer.startsWith('::ffff:') ? peer.slice(7) : peer;
  return peer || '0.0.0.0';
}
const uaHash = ua => createHash('sha256').update(ua).digest('hex').slice(0,8);
const context = ({host, ip, ua = ''}) => `${host}.${ipPrefix(ip)}.${uaHash(ua)}`;
export function issueClearance(secret, bound, ttl = 300, now = Date.now()) {
  const payload = `${Math.floor(now/1000)+ttl}.${context(bound)}`;
  return `${Buffer.from(payload).toString('base64url')}.${sign(payload,secret)}`;
}
export function validClearance(token, secret, bound, now = Date.now()) {
  if (!secret || typeof token !== 'string' || token.length > 2048 || !ipPrefix(bound.ip)) return false;
  const [encoded, signature, extra] = token.split('.');
  if (extra !== undefined || !encoded) return false;
  const payload = Buffer.from(encoded,'base64url').toString();
  const exp = payload.split('.')[0];
  return /^\d+$/.test(exp) && Number(exp)>Math.floor(now/1000) && payload === `${exp}.${context(bound)}` && equal(signature,sign(payload,secret));
}
export function difficultyFor(score) { return score >= .75 ? 22 : score >= .65 ? 20 : score >= .45 ? 18 : 16; }
export function hasWork(id, nonce, bits) {
  if (!Number.isInteger(bits) || bits < 1 || bits > 256 || typeof id !== 'string' || id.length > 128 || typeof nonce !== 'string' || nonce.length > 20) return false;
  const hash = createHash('sha256').update(`${id}:${nonce}`).digest();
  for (let i=0;i<bits;i++) if (hash[i>>3] & (128>>(i%8))) return false;
  return true;
}
export function seal(value, secret) { const data = Buffer.from(JSON.stringify(value)).toString('base64url'); return `${data}.${sign(data,secret)}`; }
export function unseal(token, secret) {
  if (!secret || typeof token !== 'string' || token.length>4096) return null;
  const [data, sig, extra] = token.split('.');
  if (extra !== undefined || !data || !equal(sig,sign(data,secret))) return null;
  try { const value=JSON.parse(Buffer.from(data,'base64url')); return value.exp>Date.now() ? value : null; } catch { return null; }
}
