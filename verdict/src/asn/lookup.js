import { readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

/**
 * Compact ASN DB. IPv4 ranges: three Uint32Arrays (start, end, asn).
 * IPv6 ranges: top 64 bits only, as hi/lo Uint32 pairs (+ asn). ip2asn v6
 * allocations are /64 or shorter, so 64-bit prefixes keep the ranges exact
 * enough for an ASN-level signal. No per-row JS objects, no names in memory.
 */
const MAGIC = 'VASN1\0\0\0';

export function ipv4ToInt(ip) {
  const p = ip.split('.');
  return ((+p[0] << 24) >>> 0) + (+p[1] << 16) + (+p[2] << 8) + +p[3];
}

export function ipv6Hi64(ip) {
  let v = ip.toLowerCase().split('%')[0];
  if (v.includes('.')) {
    const i = v.lastIndexOf(':');
    const n = ipv4ToInt(v.slice(i + 1));
    v = `${v.slice(0, i)}:${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const [l, r] = v.split('::');
  const a = l ? l.split(':') : [];
  const b = r !== undefined ? (r ? r.split(':') : []) : [];
  const words = r !== undefined ? [...a, ...Array(8 - a.length - b.length).fill('0'), ...b] : a;
  const w = words.map(x => parseInt(x || '0', 16) & 0xffff);
  return [((w[0] << 16) | w[1]) >>> 0, ((w[2] << 16) | w[3]) >>> 0];
}

/** Growable Uint32 column. */
class Col {
  constructor(n = 1 << 16) { this.a = new Uint32Array(n); this.n = 0; }
  push(v) {
    if (this.n === this.a.length) { const b = new Uint32Array(this.a.length * 2); b.set(this.a); this.a = b; }
    this.a[this.n++] = v;
  }
  done() { return this.a.slice(0, this.n); }
}

/** Streaming compiler: feed TSV lines, get compact columns. */
export function createCompiler() {
  const v4s = new Col(), v4e = new Col(), v4a = new Col();
  const v6sh = new Col(), v6sl = new Col(), v6eh = new Col(), v6el = new Col(), v6a = new Col();
  let lastV4 = -1, lastV6h = -1, lastV6l = -1, unsorted = 0, skipped = 0;
  return {
    line(line) {
      if (!line || line[0] === '#') return;
      const t1 = line.indexOf('\t'); if (t1 < 0) { skipped++; return; }
      const t2 = line.indexOf('\t', t1 + 1); if (t2 < 0) { skipped++; return; }
      const t3 = line.indexOf('\t', t2 + 1);
      const s = line.slice(0, t1), e = line.slice(t1 + 1, t2);
      const asn = Number(line.slice(t2 + 1, t3 < 0 ? undefined : t3));
      if (!Number.isInteger(asn) || asn <= 0) { skipped++; return; } // 0 = not routed
      const kind = isIP(s);
      if (kind === 4 && isIP(e) === 4) {
        const si = ipv4ToInt(s);
        if (si < lastV4) unsorted++;
        lastV4 = si;
        v4s.push(si); v4e.push(ipv4ToInt(e)); v4a.push(asn);
      } else if (kind === 6 && isIP(e) === 6) {
        const [sh, sl] = ipv6Hi64(s); const [eh, el] = ipv6Hi64(e);
        if (sh < lastV6h || (sh === lastV6h && sl < lastV6l)) unsorted++;
        lastV6h = sh; lastV6l = sl;
        v6sh.push(sh); v6sl.push(sl); v6eh.push(eh); v6el.push(el); v6a.push(asn);
      } else skipped++;
    },
    finish() {
      return {
        v4: { s: v4s.done(), e: v4e.done(), a: v4a.done() },
        v6: { sh: v6sh.done(), sl: v6sl.done(), eh: v6eh.done(), el: v6el.done(), a: v6a.done() },
        unsorted, skipped,
      };
    },
  };
}

export function serialize(db) {
  const n4 = db.v4.s.length, n6 = db.v6.sh.length;
  const buf = Buffer.alloc(16 + n4 * 12 + n6 * 20);
  buf.write(MAGIC, 0, 'latin1');
  buf.writeUInt32LE(n4, 8); buf.writeUInt32LE(n6, 12);
  let o = 16;
  for (const col of [db.v4.s, db.v4.e, db.v4.a, db.v6.sh, db.v6.sl, db.v6.eh, db.v6.el, db.v6.a]) {
    Buffer.from(col.buffer, col.byteOffset, col.byteLength).copy(buf, o); o += col.byteLength;
  }
  return buf;
}

export function deserialize(buf) {
  if (buf.toString('latin1', 0, 8) !== MAGIC) throw new Error('bad_asn_magic');
  const n4 = buf.readUInt32LE(8), n6 = buf.readUInt32LE(12);
  if (buf.length !== 16 + n4 * 12 + n6 * 20) throw new Error('bad_asn_length');
  // Copy into a fresh aligned ArrayBuffer so typed views are valid.
  const ab = new ArrayBuffer(buf.length - 16);
  new Uint8Array(ab).set(buf.subarray(16));
  let o = 0;
  const take = n => { const v = new Uint32Array(ab, o, n); o += n * 4; return v; };
  const v4 = { s: take(n4), e: take(n4), a: take(n4) };
  const v6 = { sh: take(n6), sl: take(n6), eh: take(n6), el: take(n6), a: take(n6) };
  return { v4, v6 };
}

export function createAsnDb() {
  let db = null, source = null;
  const set = (next, label) => { db = next; source = label; return { rows: rows(), source }; };
  const rows = () => (db ? db.v4.s.length + db.v6.sh.length : 0);
  function loadText(text, label = 'inline') {
    const c = createCompiler();
    for (const line of text.split('\n')) c.line(line);
    const out = c.finish();
    if (out.unsorted) throw new Error('asn_unsorted');
    return set(out, label);
  }
  async function loadFile(path) {
    const buf = await readFile(path);
    if (buf.toString('latin1', 0, 8) === MAGIC) return set(deserialize(buf), path);
    return loadText(buf.toString('utf8'), path);
  }
  function lookup(ip) {
    if (!db || typeof ip !== 'string') return null;
    const kind = isIP(ip);
    if (kind === 4 || (kind === 6 && /^::ffff:\d+\.\d+\.\d+\.\d+$/i.test(ip))) {
      const k = ipv4ToInt(kind === 4 ? ip : ip.slice(7));
      const { s, e, a } = db.v4;
      let lo = 0, hi = s.length - 1, best = -1;
      while (lo <= hi) { const m = (lo + hi) >>> 1; if (s[m] <= k) { best = m; lo = m + 1; } else hi = m - 1; }
      return best >= 0 && k <= e[best] ? { asn: a[best] } : null;
    }
    if (kind === 6) {
      const [kh, kl] = ipv6Hi64(ip);
      const { sh, sl, eh, el, a } = db.v6;
      let lo = 0, hi = sh.length - 1, best = -1;
      while (lo <= hi) {
        const m = (lo + hi) >>> 1;
        if (sh[m] < kh || (sh[m] === kh && sl[m] <= kl)) { best = m; lo = m + 1; } else hi = m - 1;
      }
      if (best < 0) return null;
      const inside = kh < eh[best] || (kh === eh[best] && kl <= el[best]);
      return inside ? { asn: a[best] } : null;
    }
    return null;
  }
  return {
    loadFile, loadText, lookup,
    clear() { db = null; source = null; },
    get loaded() { return !!db; },
    get rows() { return rows(); },
    get source() { return source; },
  };
}

export const asnDb = createAsnDb();
export const lookupAsn = ip => asnDb.lookup(ip);

export function loadHostingAsns(path) {
  const file = path || join(dirname(fileURLToPath(import.meta.url)), './hosting-asns.json');
  const raw = JSON.parse(readFileSync(file, 'utf8'));
  const names = raw.asns || raw;
  const set = new Set(Object.keys(names).filter(k => /^\d+$/.test(k)));
  return { has: asn => set.has(String(asn).replace(/^AS/i, '')), name: asn => names[String(asn)] || null, size: set.size };
}
