import { it } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { checkMx, checkSpf, checkDkim, checkDmarc, checkDomain, txtRecords, digError, isHostname, isServer, digQuery, main } from '../scripts/mail-dns-check.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const rsaKey = (bits) => generateKeyPairSync('rsa', { modulusLength: bits }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
// dig +short splits long TXT strings into 255-byte quoted chunks.
const chunked = (text) => (text.match(/.{1,255}/g) || []).map((c) => `"${c}"`).join(' ');

it('parses quoted TXT chunks and ignores CNAME lines and diagnostics', () => {
  assert.deepEqual(txtRecords('dmarc.provider.example.\n"v=DMARC1; " "p=reject"\n\n'), ['v=DMARC1; p=reject']);
  assert.deepEqual(txtRecords('"a \\"quoted\\" value"'), ['a "quoted" value']);
  assert.equal(digError(';; connection timed out; no servers could be reached\n'), 'connection timed out; no servers could be reached');
  assert.equal(digError('10 mx1.provider.example.\n'), '');
});

it('evaluates MX presence, ordering and null MX', () => {
  assert.deepEqual(checkMx('20 mx2.provider.example.\n10 mx1.provider.example.\n'),
    { check: 'MX', status: 'PASS', detail: '10 mx1.provider.example., 20 mx2.provider.example.' });
  assert.equal(checkMx('').status, 'FAIL');
  assert.equal(checkMx('0 .\n').status, 'FAIL');
});

it('evaluates SPF qualifiers, duplicates and expected mechanisms', () => {
  const good = '"google-site-verification=abc"\n"v=spf1 include:mail.provider.example -all"\n';
  assert.equal(checkSpf(good).status, 'PASS');
  assert.equal(checkSpf(good, ['mail.provider.example']).status, 'PASS');
  assert.equal(checkSpf(good, ['include:MAIL.provider.example']).status, 'PASS');
  const missing = checkSpf(good, ['other.provider.example']);
  assert.equal(missing.status, 'FAIL');
  assert.match(missing.detail, /include:other\.provider\.example/);
  for (const q of ['~all', '?all', '+all']) {
    const r = checkSpf(`"v=spf1 include:mail.provider.example ${q}"`);
    assert.equal(r.status, 'WARN', q);
    assert.match(r.detail, new RegExp(`\\${q[0]}all is not a hard fail`));
  }
  assert.equal(checkSpf('"v=spf1 include:mail.provider.example"').status, 'WARN');
  assert.equal(checkSpf('"v=spf1 redirect=_spf.provider.example"').status, 'PASS');
  const dup = checkSpf('"v=spf1 -all"\n"v=spf1 include:mail.provider.example -all"');
  assert.equal(dup.status, 'WARN');
  assert.match(dup.detail, /2 SPF records/);
  assert.equal(checkSpf('"v=spf10 -all"\n"verification=xyz"').status, 'FAIL');
  assert.equal(checkSpf('').status, 'FAIL');
});

it('evaluates DKIM records and estimates RSA key length from base64', () => {
  const k2048 = rsaKey(2048);
  const r = checkDkim(chunked(`v=DKIM1; k=rsa; p=${k2048}`), 'x');
  assert.deepEqual(r, { check: 'DKIM x', status: 'PASS', detail: 'RSA ~2048 bits' });
  assert.doesNotMatch(r.detail, new RegExp(k2048.slice(0, 20).replace(/[+/]/g, '.')), 'key material is never printed');
  assert.equal(checkDkim(`"v=DKIM1; p=${rsaKey(1024)}"`, 's1').detail, 'RSA ~1024 bits');
  assert.equal(checkDkim(`"v=DKIM1; p=${rsaKey(512)}"`).status, 'WARN');
  const ed = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
  assert.match(checkDkim(`"v=DKIM1; k=ed25519; p=${ed}"`).detail, /k=ed25519, 32-byte key/);
  assert.equal(checkDkim('"v=DKIM1; k=rsa; p="').status, 'FAIL');
  assert.equal(checkDkim('"v=DKIM1; k=rsa; p=not*base64"').status, 'FAIL');
  assert.equal(checkDkim('"k=rsa; p=AAAA"').status, 'FAIL');
  assert.equal(checkDkim('').status, 'FAIL');
});

it('evaluates DMARC policy and aggregate reporting', () => {
  assert.equal(checkDmarc('"v=DMARC1; p=reject; rua=mailto:dmarc@example.test"').status, 'PASS');
  const none = checkDmarc('"v=DMARC1; p=none; rua=mailto:dmarc@example.test"');
  assert.equal(none.status, 'WARN');
  assert.match(none.detail, /monitor only/);
  const norua = checkDmarc('"v=DMARC1; p=quarantine"');
  assert.equal(norua.status, 'WARN');
  assert.match(norua.detail, /rua= missing/);
  assert.equal(checkDmarc('"v=DMARC1; rua=mailto:dmarc@example.test"').status, 'FAIL');
  assert.equal(checkDmarc('"v=DMARC1; p=bogus; rua=mailto:dmarc@example.test"').status, 'FAIL');
  assert.equal(checkDmarc('"v=spf1 -all"').status, 'FAIL');
});

it('validates domains and servers strictly', () => {
  for (const ok of ['example.test', 'mail.example.test.', 'a-b.example.invalid']) assert.ok(isHostname(ok), ok);
  for (const bad of ['', 'example', '-x.example.test', 'a..example.test', 'a b.example.test', 'x;rm.example.test', '@1.2.3.4', '+short', '1.2.3.4', `${'a'.repeat(64)}.example.test`]) {
    assert.ok(!isHostname(bad), bad);
  }
  for (const ok of ['192.0.2.1', '2001:db8::1', 'ns1.example.test']) assert.ok(isServer(ok), ok);
  for (const bad of ['-p53', '192.0.2.1;id', '@192.0.2.1', '192.0.2.1 +tcp']) assert.ok(!isServer(bad), bad);
});

const zone = {
  'example.test MX': '10 mx1.provider.example.\n20 mx2.provider.example.\n',
  'example.test TXT': '"v=spf1 include:mail.provider.example -all"\n',
  'x._domainkey.example.test TXT': '"v=DKIM1; k=rsa; p=AAAA"\n',
  '_dmarc.example.test TXT': '"v=DMARC1; p=none"\n',
};

it('builds dig argv without a shell, per server and for the system resolver', async () => {
  const calls = [];
  const run = (cmd, args, opts, cb) => { calls.push([cmd, args]); cb(null, zone[args.slice(-2).join(' ')] || ''); };
  const results = await checkDomain('example.test', { query: digQuery('192.0.2.53', run) });
  assert.deepEqual(results.map((r) => r.status), ['PASS', 'PASS', 'WARN', 'WARN']);
  assert.deepEqual(calls[0], ['dig', ['+short', '+time=3', '+tries=1', '@192.0.2.53', 'example.test', 'MX']]);
  assert.deepEqual(calls[2][1].slice(-2), ['x._domainkey.example.test', 'TXT']);
  calls.length = 0;
  await checkDomain('example.test', { query: digQuery(null, run) });
  assert.deepEqual(calls[0], ['dig', ['+short', '+time=3', '+tries=1', 'example.test', 'MX']]);
});

it('reports query failures as FAIL lines and still exits 0', async () => {
  const out = [];
  const run = (cmd, args, opts, cb) => args.includes('@192.0.2.53')
    ? cb(Object.assign(new Error('exit 9'), { code: 9 }), ';; connection timed out; no servers could be reached\n')
    : cb(null, zone[args.slice(-2).join(' ')] || '');
  const code = await main(['example.test', '--server', '192.0.2.53', '--expect', 'mail.provider.example'], { run, log: (l) => out.push(l), error: (l) => out.push(l) });
  assert.equal(code, 0);
  assert.equal(out.filter((l) => l.startsWith('FAIL [192.0.2.53]') && l.includes('query failed')).length, 4);
  assert.ok(out.includes('PASS [system] MX: 10 mx1.provider.example., 20 mx2.provider.example.'));
  assert.ok(out.includes('PASS [system] SPF: v=spf1 include:mail.provider.example -all'));
  assert.ok(out.includes('WARN [system] DMARC: p=none (monitor only); rua= missing (no aggregate reports)'));
});

it('exits 1 when dig is missing or arguments are invalid, before running dig', async () => {
  const quiet = { log() {}, error() {} };
  const missing = (cmd, args, opts, cb) => cb(Object.assign(new Error('spawn dig ENOENT'), { code: 'ENOENT' }));
  assert.equal(await main(['example.test'], { ...quiet, run: missing }), 1);
  let ran = false;
  const never = () => { ran = true; };
  for (const argv of [[], ['bad;domain'], ['example.test', '--server', '-x'], ['example.test', '192.0.2.1;id'], ['example.test', '--selector', 'a b'], ['example.test', '--bogus']]) {
    assert.equal(await main(argv, { ...quiet, run: never }), 1, argv.join(' '));
  }
  assert.equal(ran, false);
});

it('shell wrapper forwards arguments to the node CLI', () => {
  const r = spawnSync('bash', ['scripts/check-mail-dns.sh', 'not_a_domain'], { cwd: root, encoding: 'utf8' });
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stderr, /invalid domain/);
  const help = spawnSync('bash', ['scripts/check-mail-dns.sh', '--help'], { cwd: root, encoding: 'utf8' });
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stdout, /usage: mail-dns-check\.js/);
});
