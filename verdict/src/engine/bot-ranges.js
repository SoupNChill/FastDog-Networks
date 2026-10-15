import { readFileSync, statSync } from 'node:fs';
import { isIP } from 'node:net';
import { join } from 'node:path';

// Deliberately small bootstrap subset; refresh replaces it with published lists.
export const seed = { version: 1, updated_at: '2026-10-15', sources: ['https://developers.google.com/static/search/apis/ipranges/googlebot.json'], bots: {
  google: ['192.178.6.0/24', '66.249.72.0/24'], bing: [],
} };
export const rangesFile = () => process.env.VERDICT_BOT_RANGES_FILE || join(process.env.VERDICT_DATA_DIR || 'data', 'bot-ranges.json');
function address(ip) {
  const family = isIP(ip);
  if (!family || ip.includes('%')) throw new Error('invalid_ip');
  if (family === 4) return [32, ip.split('.').reduce((n, x) => (n << 8n) | BigInt(x), 0n)];
  if (ip.includes('.')) {
    const pos = ip.lastIndexOf(':');
    const [, n] = address(ip.slice(pos + 1));
    ip = `${ip.slice(0, pos)}:${(n >> 16n).toString(16)}:${(n & 65535n).toString(16)}`;
  }
  const [left, right] = ip.split('::');
  const a = left ? left.split(':') : [], b = right ? right.split(':') : [];
  const words = right === undefined ? a : [...a, ...Array(8 - a.length - b.length).fill('0'), ...b];
  return [128, words.reduce((n, x) => (n << 16n) | BigInt(`0x${x}`), 0n)];
}
export function parseCIDR(cidr) {
  if (typeof cidr !== 'string' || !/^.+\/\d+$/.test(cidr)) throw new Error('invalid_cidr');
  const [ip, prefix] = cidr.split('/');
  const [bits, value] = address(ip), size = Number(prefix);
  // Reject over-broad ranges so a bad list cannot allow the whole Internet for claimed bots.
  if (size > bits || (bits === 32 && size < 12) || (bits === 128 && size < 24)) throw new Error('invalid_prefix');
  const shift = BigInt(bits - size), start = (value >> shift) << shift;
  return { bits, start, end: start + (1n << shift) - 1n };
}
export function compileRanges(raw) {
  if (raw?.version !== 1 || !raw.bots || !Array.isArray(raw.sources) || typeof raw.updated_at !== 'string') throw new Error('invalid_ranges');
  const index = {};
  for (const bot of ['google', 'bing']) {
    if (!Array.isArray(raw.bots[bot])) throw new Error('invalid_bot_ranges');
    index[bot] = {};
    const parsed = raw.bots[bot].map(parseCIDR);
    for (const bits of [32, 128]) {
      const merged = [];
      for (const range of parsed.filter(r => r.bits === bits).sort((a, b) => a.start < b.start ? -1 : a.start > b.start ? 1 : 0)) {
        const last = merged.at(-1);
        if (last && range.start <= last.end + 1n) { if (range.end > last.end) last.end = range.end; }
        else merged.push(range);
      }
      index[bot][bits] = merged;
    }
  }
  return (bot, ip) => {
    let bits, value;
    try { [bits, value] = address(ip); } catch { return false; }
    const rows = index[bot]?.[bits] || [];
    let lo = 0, hi = rows.length - 1, best = -1;
    while (lo <= hi) { const mid = (lo + hi) >>> 1; if (rows[mid].start <= value) { best = mid; lo = mid + 1; } else hi = mid - 1; }
    return best >= 0 && value <= rows[best].end;
  };
}
export function createBotRanges({ file = rangesFile, now = Date.now } = {}) {
  let nextCheck = -Infinity, stamp, match = compileRanges(seed);
  return (bot, ip) => {
    if (now() >= nextCheck) {
      nextCheck = now() + 1000;
      try {
        const path = typeof file === 'function' ? file() : file;
        const stat = statSync(path), nextStamp = `${path}:${stat.mtimeMs}:${stat.size}`;
        if (nextStamp !== stamp) { match = compileRanges(JSON.parse(readFileSync(path, 'utf8'))); stamp = nextStamp; }
      } catch { /* Missing/invalid files retain the last valid snapshot or bootstrap seed. */ }
    }
    return match(bot, ip);
  };
}
export const matchesBotRange = createBotRanges();
