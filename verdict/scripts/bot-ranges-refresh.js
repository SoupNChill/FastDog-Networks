#!/usr/bin/env node
import { mkdir, writeFile, rename, unlink } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';
import { compileRanges, parseCIDR, rangesFile } from '../src/engine/bot-ranges.js';

export const sources = [
  { bot: 'google', url: 'https://developers.google.com/static/search/apis/ipranges/googlebot.json', min: 100 },
  { bot: 'google', url: 'https://developers.google.com/static/search/apis/ipranges/google-special-crawlers.json', min: 10 },
  { bot: 'bing', url: 'https://www.bing.com/toolbox/bingbot.json', min: 10 },
];
export async function refreshBotRanges({ fetchImpl = globalThis.fetch, file = rangesFile() } = {}) {
  const bots = { google: [], bing: [] };
  for (const source of sources) {
    const response = await fetchImpl(source.url, { signal: AbortSignal.timeout(30000) });
    if (!response.ok) throw new Error('bot_source_http_failure');
    const body = await response.json();
    if (!Array.isArray(body.prefixes)) throw new Error('invalid_prefixes');
    const ranges = [...new Set(body.prefixes.map(p => {
      if (!p || Boolean(p.ipv4Prefix) === Boolean(p.ipv6Prefix)) throw new Error('invalid_source_prefix');
      const cidr = p.ipv4Prefix || p.ipv6Prefix;
      const parsed = parseCIDR(cidr);
      if (parsed.bits !== (p.ipv4Prefix ? 32 : 128)) throw new Error('invalid_source_family');
      return cidr;
    }))];
    if (ranges.length < source.min) throw new Error('undersized_bot_source');
    bots[source.bot].push(...ranges);
  }
  for (const bot of Object.keys(bots)) bots[bot] = [...new Set(bots[bot])];
  const result = { version: 1, updated_at: new Date().toISOString(), sources: sources.map(s => s.url), bots };
  compileRanges(result);
  await mkdir(dirname(file), { recursive: true });
  const temporary = `${file}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, JSON.stringify(result) + '\n', { mode: 0o600, flag: 'wx' });
    await rename(temporary, file);
  } finally { await unlink(temporary).catch(() => {}); }
  return result;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { await refreshBotRanges(); console.log('Bot ranges refreshed'); }
  catch { console.error('Bot ranges refresh failed; previous file retained'); process.exitCode = 1; }
}
