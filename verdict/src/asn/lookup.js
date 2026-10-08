import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

function ipToBigInt(ip) {
  const v = isIP(ip);
  if (!v) return null;
  if (v === 4) {
    const parts = ip.split('.').map(Number);
    return (BigInt(parts[0]) << 24n) + (BigInt(parts[1]) << 16n) + (BigInt(parts[2]) << 8n) + BigInt(parts[3]);
  }
  // IPv6 → BigInt
  let value = ip.toLowerCase().split('%')[0];
  if (value.includes('.')) {
    // v4-mapped handled via isIP already mostly
  }
  const [left, right = ''] = value.split('::');
  const a = left ? left.split(':').filter(Boolean) : [];
  const b = right ? right.split(':').filter(Boolean) : [];
  const mid = 8 - a.length - b.length;
  const words = [...a, ...Array(Math.max(0, mid)).fill('0'), ...b].map(x => parseInt(x || '0', 16));
  while (words.length < 8) words.push(0);
  return words.reduce((acc, w) => (acc << 16n) + BigInt(w), 0n);
}

export function createAsnDb() {
  /** @type {BigInt[]} */
  let starts = [];
  /** @type {BigInt[]} */
  let ends = [];
  /** @type {number[]} */
  let asns = [];
  /** @type {string[]} */
  let names = [];
  /** @type {string[]} */
  let countries = [];
  let loaded = false;
  let source = null;
  let rowCount = 0;

  function clear() {
    starts = []; ends = []; asns = []; names = []; countries = [];
    loaded = false; rowCount = 0; source = null;
  }

  function parseTsv(text) {
    const s = [], e = [], a = [], n = [], c = [];
    for (const line of text.split('\n')) {
      if (!line || line.startsWith('#')) continue;
      const parts = line.split('\t');
      if (parts.length < 3) continue;
      const start = ipToBigInt(parts[0].trim());
      const end = ipToBigInt(parts[1].trim());
      const asn = Number(parts[2]);
      if (start === null || end === null || !Number.isFinite(asn)) continue;
      s.push(start); e.push(end); a.push(asn);
      c.push(parts[3] || '');
      n.push(parts.slice(4).join('\t') || '');
    }
    // ensure sorted by start
    const idx = s.map((_, i) => i).sort((i, j) => (s[i] < s[j] ? -1 : s[i] > s[j] ? 1 : 0));
    starts = idx.map(i => s[i]);
    ends = idx.map(i => e[i]);
    asns = idx.map(i => a[i]);
    countries = idx.map(i => c[i]);
    names = idx.map(i => n[i]);
    rowCount = starts.length;
    loaded = rowCount > 0;
  }

  async function loadFile(path) {
    const text = await readFile(path, 'utf8');
    parseTsv(text);
    source = path;
    return { rows: rowCount, source };
  }

  function loadText(text, label = 'inline') {
    parseTsv(text);
    source = label;
    return { rows: rowCount, source };
  }

  function lookup(ip) {
    if (!loaded) return null;
    const key = ipToBigInt(ip);
    if (key === null) return null;
    let lo = 0, hi = starts.length - 1, best = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (starts[mid] <= key) { best = mid; lo = mid + 1; }
      else hi = mid - 1;
    }
    if (best < 0) return null;
    if (key > ends[best]) return null;
    return { asn: asns[best], as_name: names[best], country: countries[best] };
  }

  return {
    loadFile, loadText, lookup, clear,
    get loaded() { return loaded; },
    get rows() { return rowCount; },
    get source() { return source; },
  };
}

const defaultDb = createAsnDb();
export const asnDb = defaultDb;
export const lookupAsn = ip => defaultDb.lookup(ip);

export function loadHostingAsns(path) {
  const file = path || join(dirname(fileURLToPath(import.meta.url)), './hosting-asns.json');
  const raw = JSON.parse(readFileSync(file, 'utf8'));
  const set = new Set(Object.keys(raw.asns || raw).map(String));
  return {
    has(asn) { return set.has(String(asn).replace(/^AS/i, '')); },
    size: set.size,
  };
}
