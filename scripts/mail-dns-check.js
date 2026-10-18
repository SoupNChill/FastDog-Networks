#!/usr/bin/env node
// Read-only mail DNS checker: evaluates `dig +short` output for MX, SPF, DKIM and DMARC.
// Never changes DNS. Usage: node scripts/mail-dns-check.js <domain> [--selector x] [--server ip ...] [--expect include:x ...]
import { execFile } from 'node:child_process';
import { createPublicKey } from 'node:crypto';
import { isIP } from 'node:net';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';

const RANK = { PASS: 0, WARN: 1, FAIL: 2 };
const LABEL = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$/;
const result = (check, status, detail) => ({ check, status, detail });
const worst = (notes) => notes.reduce((a, n) => (RANK[n.status] > RANK[a] ? n.status : a), 'PASS');
const combine = (check, notes, ok) => notes.length ? result(check, worst(notes), notes.map((n) => n.detail).join('; ')) : result(check, 'PASS', ok);
const note = (status, detail) => ({ status, detail });

export function isHostname(value, minLabels = 2) {
  if (typeof value !== 'string' || value.length > 253) return false;
  const labels = value.replace(/\.$/, '').split('.');
  return labels.length >= minLabels && labels.every((l) => LABEL.test(l)) && !/^\d+$/.test(labels.at(-1));
}
export const isServer = (value) => isIP(value) !== 0 || isHostname(value);
// A trailing dot would build "x.._domainkey.<domain>", so selectors may not end in one.
export const isSelector = (value) => typeof value === 'string' && !value.endsWith('.') && isHostname(value, 1);

// dig +short prints ";; ..." diagnostics on timeout/SERVFAIL and blank lines for nothing.
export const lines = (out) => String(out || '').split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith(';'));
export const digError = (out) => String(out || '').split(/\r?\n/).map((l) => l.trim()).find((l) => l.startsWith(';;'))?.replace(/^;;\s*/, '') || '';

// TXT answers are quoted chunks ("a" "b"); unquoted lines are CNAME targets and are skipped.
export function txtRecords(out) {
  return lines(out).filter((l) => l.startsWith('"'))
    .map((l) => [...l.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1].replace(/\\(.)/g, '$1')).join(''));
}
const tags = (record) => Object.fromEntries(record.split(';').map((t) => t.trim()).filter(Boolean)
  .map((t) => { const i = t.indexOf('='); return i < 0 ? [t.toLowerCase(), ''] : [t.slice(0, i).trim().toLowerCase(), t.slice(i + 1).trim()]; }));

export function checkMx(out) {
  const mx = lines(out).map((l) => l.match(/^(\d+)\s+(\S+)$/)).filter(Boolean);
  if (!mx.length) return result('MX', 'FAIL', 'no MX records');
  if (mx.length === 1 && mx[0][2] === '.') return result('MX', 'FAIL', 'null MX (domain accepts no mail)');
  return result('MX', 'PASS', mx.sort((a, b) => a[1] - b[1]).map((m) => `${m[1]} ${m[2]}`).join(', '));
}

export function checkSpf(out, expected = []) {
  const spf = txtRecords(out).filter((r) => /^v=spf1(\s|$)/i.test(r));
  if (!spf.length) return result('SPF', 'FAIL', 'no v=spf1 TXT record');
  const notes = [];
  if (spf.length > 1) notes.push(note('WARN', `${spf.length} SPF records (receivers treat this as permerror)`));
  const terms = spf[0].split(/\s+/).slice(1).map((t) => t.toLowerCase());
  const allAt = terms.findIndex((t) => /^[-~?+]?all$/.test(t));
  const all = terms[allAt];
  if (all && all !== '-all') notes.push(note('WARN', `${all} is not a hard fail`));
  if (!all && !terms.some((t) => t.startsWith('redirect='))) notes.push(note('WARN', 'no all mechanism'));
  if (expected.length) {
    // Only pass-qualified (+ or none) mechanisms before the first all authorize senders; redirect= is ignored once all exists.
    const reachable = (allAt < 0 ? terms : terms.slice(0, allAt)).map((t) => t.replace(/^\+/, ''));
    const authorizes = (w) => (w.includes('=') ? allAt < 0 && terms.includes(w) : reachable.includes(w));
    const want = expected.map((e) => (e.includes(':') || e.includes('=') || /^(a|mx|ptr)$/i.test(e) ? e : `include:${e}`).toLowerCase());
    if (!want.some(authorizes)) notes.push(note('FAIL', `none of the expected mechanisms authorize senders (${want.join(', ')}: missing, not pass-qualified, or after all)`));
  }
  return combine('SPF', notes, spf[0]);
}

export function checkDkim(out, selector = 'x') {
  const check = `DKIM ${selector}`;
  const record = txtRecords(out).find((r) => /(^|;)\s*v=DKIM1\s*(;|$)/i.test(r));
  if (!record) return result(check, 'FAIL', `no v=DKIM1 TXT record at ${selector}._domainkey`);
  const t = tags(record);
  const p = (t.p || '').replace(/\s+/g, '');
  if (!p) return result(check, 'FAIL', 'empty p= (key missing or revoked)');
  const der = /^[A-Za-z0-9+/]+={0,2}$/.test(p) ? Buffer.from(p, 'base64') : null;
  if (!der || der.toString('base64') !== p) return result(check, 'FAIL', 'p= is not valid base64');
  const k = (t.k || 'rsa').toLowerCase();
  if (k === 'ed25519') {
    if (der.length !== 32 || !publicKey(Buffer.concat([ED25519_SPKI, der]), 'spki')) return result(check, 'FAIL', `ed25519 p= must be a 32-byte key (got ${der.length} bytes)`);
    return result(check, 'PASS', 'k=ed25519, 32-byte key');
  }
  if (k !== 'rsa') return result(check, 'FAIL', `unsupported k=${k} (expect rsa or ed25519)`);
  // RFC 6376 publishes SubjectPublicKeyInfo; some signers publish a bare PKCS#1 RSAPublicKey.
  const key = publicKey(der, 'spki') || publicKey(der, 'pkcs1');
  if (key?.asymmetricKeyType !== 'rsa') return result(check, 'FAIL', 'p= is not a parseable RSA public key');
  const bits = key.asymmetricKeyDetails.modulusLength;
  // RFC 8301: verifiers must not accept RSA keys under 1024 bits.
  return result(check, bits < 1024 ? 'FAIL' : 'PASS', `RSA ${bits} bits${bits < 1024 ? ' (receivers reject keys under 1024, use 2048)' : ''}`);
}
const ED25519_SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const publicKey = (key, type) => { try { return createPublicKey({ key, format: 'der', type }); } catch { return null; } };

export function checkDmarc(out) {
  const dmarc = txtRecords(out).filter((r) => /^v=DMARC1\s*(;|$)/i.test(r));
  if (!dmarc.length) return result('DMARC', 'FAIL', 'no v=DMARC1 TXT record at _dmarc');
  const notes = [];
  if (dmarc.length > 1) notes.push(note('WARN', `${dmarc.length} DMARC records (receivers ignore all of them)`));
  const t = tags(dmarc[0]);
  const p = (t.p || '').toLowerCase();
  if (!p) notes.push(note('FAIL', 'p= missing'));
  else if (p === 'none') notes.push(note('WARN', 'p=none (monitor only)'));
  else if (!['quarantine', 'reject'].includes(p)) notes.push(note('FAIL', `invalid p=${p}`));
  if (!t.rua) notes.push(note('WARN', 'rua= missing (no aggregate reports)'));
  return combine('DMARC', notes, `p=${p}, rua present`);
}

// query(name, type) -> Promise<string stdout>; throws with code ENOENT if dig is missing.
export async function checkDomain(domain, { selector = 'x', expected = [], query }) {
  const plan = [
    ['MX', domain, 'MX', checkMx],
    ['SPF', domain, 'TXT', (o) => checkSpf(o, expected)],
    [`DKIM ${selector}`, `${selector}._domainkey.${domain}`, 'TXT', (o) => checkDkim(o, selector)],
    ['DMARC', `_dmarc.${domain}`, 'TXT', checkDmarc],
  ];
  const out = [];
  for (const [check, name, type, evaluate] of plan) {
    const stdout = await query(name, type);
    const error = digError(stdout);
    out.push(error && !lines(stdout).length ? result(check, 'FAIL', `query failed: ${error}`) : evaluate(stdout));
  }
  return out;
}

export function digQuery(server, run = execFile) {
  return (name, type) => new Promise((resolve, reject) => {
    const args = ['+short', '+time=3', '+tries=1', ...(server ? [`@${server}`] : []), name, type];
    run('dig', args, { timeout: 15000 }, (error, stdout) => {
      if (error?.code === 'ENOENT') return reject(error);
      resolve(String(stdout || '') || (error ? `;; dig exited ${error.code ?? error.signal}` : ''));
    });
  });
}

const USAGE = 'usage: mail-dns-check.js <domain> [--selector x] [--server ip|host ...] [--expect include:x ...]\n'
  + 'Read-only, but makes live DNS queries: run only in an operator-authorized online window.';

export async function main(argv, { run = execFile, log = console.log, error = console.error } = {}) {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, allowPositionals: true, options: {
      selector: { type: 'string', default: 'x' }, server: { type: 'string', multiple: true, default: [] },
      expect: { type: 'string', multiple: true, default: [] }, help: { type: 'boolean', short: 'h' } } });
  } catch (e) { error(`${e.message}\n${USAGE}`); return 1; }
  const { values, positionals: [domainArg, ...extra] } = parsed;
  if (values.help) { log(USAGE); return 0; }
  const servers = [...values.server, ...extra];
  if (!isHostname(domainArg || '')) { error(`invalid domain\n${USAGE}`); return 1; }
  if (!isSelector(values.selector)) { error('invalid --selector'); return 1; }
  const bad = servers.find((s) => !isServer(s));
  if (bad !== undefined) { error('invalid --server (expect an IP address or hostname)'); return 1; }
  if (values.expect.some((e) => !/^[A-Za-z0-9.:=_\/-]{1,255}$/.test(e))) { error('invalid --expect'); return 1; }
  const domain = domainArg.replace(/\.$/, '').toLowerCase();
  log(`Mail DNS check for ${domain} (read-only)`);
  for (const server of [...servers, null]) {
    const label = server || 'system';
    try {
      for (const r of await checkDomain(domain, { selector: values.selector, expected: values.expect, query: digQuery(server, run) })) {
        log(`${r.status.padEnd(4)} [${label}] ${r.check}: ${r.detail}`);
      }
    } catch (e) {
      if (e?.code === 'ENOENT') { error('FAIL dig is not installed'); return 1; }
      throw e;
    }
  }
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exitCode = await main(process.argv.slice(2));
}
