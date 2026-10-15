import { promises as dns } from 'node:dns';
import { isIP } from 'node:net';
import { URL } from 'node:url';
import { matchesBotRange } from './bot-ranges.js';
import { normalizedHeaders } from './signals.js';

export function claimedGoodBot(state) {
  const ua = state?.ua || normalizedHeaders(state?.headers)['user-agent'] || '';
  if (/\b(?:Googlebot|Google-Extended|GoogleOther|Storebot-Google|Google-InspectionTool|GoogleProducer)\b/i.test(ua)) return 'google';
  if (/\bbingbot\b/i.test(ua)) return 'bing';
  return null;
}
const canonicalIP = ip => isIP(ip) === 6 ? new URL(`http://[${ip}]/`).hostname : ip;
export function createGoodBotVerifier({ resolver = dns, now = Date.now, timeoutMs = 200, ranges = matchesBotRange } = {}) {
  const cache = new Map();
  return (state, { dnsEnabled = true } = {}) => {
    const bot = claimedGoodBot(state);
    if (!bot) return null;
    const ip = state.ip;
    if (isIP(ip || '') && ranges(bot, ip)) return 'verified';
    if (!dnsEnabled) return 'pending';
    if (!isIP(ip || '')) return 'failed';
    const key = `${bot}:${canonicalIP(ip)}`;
    for (const [key, value] of cache) if (value.expires <= now()) cache.delete(key);
    if (cache.has(key)) return cache.get(key).result;
    return (async () => {
      let timer;
      const lookup = async () => {
        const hosts = await resolver.reverse(ip);
        const suffix = bot === 'google' ? '.googlebot.com' : '.search.msn.com';
        for (const host of hosts) {
          const name = host.toLowerCase().replace(/\.$/, '');
          if (!name.endsWith(suffix)) continue;
          try {
            const addresses = await resolver.lookup(name, { all: true });
            if (addresses.some(({ address }) => isIP(address) && canonicalIP(address) === canonicalIP(ip))) return 'verified';
          } catch { /* Another PTR may still verify. */ }
        }
        return 'failed';
      };
      const result = await Promise.race([
        Promise.resolve().then(lookup).catch(() => 'failed'),
        new Promise(resolve => { timer = setTimeout(() => resolve('timeout'), timeoutMs); }),
      ]);
      clearTimeout(timer);
      if (cache.size >= 10000) cache.delete(cache.keys().next().value);
      cache.set(key, { result, expires: now() + 3_600_000 });
      return result;
    })();
  };
}
export const verifyGoodBot = createGoodBotVerifier();
