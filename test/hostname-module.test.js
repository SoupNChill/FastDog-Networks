import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeHostname, isReserved } from '../src/onboard/hostname.js';
import { reservedSuffixes } from '../src/lib/config.js';

const longest = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(49)}.example.com`;
test('hostname normalization handles IDN, case and length boundaries', () => {
  assert.equal(longest.length, 253);
  for (const [input, expected] of [
    [' App.Example.COM. ', 'app.example.com'], ['bücher.example.com', 'xn--bcher-kva.example.com'],
    ['xn--bcher-kva.example.com', 'xn--bcher-kva.example.com'],
    [`${'a'.repeat(63)}.example.com`, `${'a'.repeat(63)}.example.com`], [longest, longest],
    ['app.example.com', 'app.example.com'], ['myapp.example.com', 'myapp.example.com'], ['x.app.example.com', 'x.app.example.com'],
  ]) assert.equal(normalizeHostname(input), expected);
});
test('invalid hostnames reject without URL parsing ambiguities', () => {
  for (const value of [undefined, null, {}, 42, '', 'example', '*.example.com', 'a*.example.com', 'app.example.com..',
    '127.0.0.1', '[::1]', '0x7f000001', '127.1', 'app.example.com:443', 'https://app.example.com',
    'app.example.com/path', 'app.example.com?x', 'app.example.com#x', 'app%2eexample.com',
    'a@b.example.com', 'a\\b.example.com', 'a b.example.com', 'a\nb.example.com', 'a\0b.example.com',
    '-a.example.com', 'a-.example.com', 'a_b.example.com', 'a..example.com', 'app.12', 'app.c',
    `${'a'.repeat(64)}.example.com`, `a${longest}`]) {
    assert.throws(() => normalizeHostname(value), { code: 'invalid_hostname' }, String(value));
  }
});
test('reserved suffixes match label boundaries and may be overridden', () => {
  const defaults = reservedSuffixes('attach.example.com', 'edge.example.com', undefined);
  assert.equal(isReserved('app.example.com', defaults), true);
  for (const host of ['a.test', 'a.invalid', 'a.example', 'a.local', 'a.lan', 'a.internal', 'a.localhost']) assert.equal(isReserved(host, defaults), true);
  assert.equal(isReserved('app.example.com', []), false);
  assert.equal(isReserved('x.app.example.com', ['app.example.com']), true);
  assert.equal(isReserved('myapp.example.com', ['app.example.com']), false);
  assert.deepEqual(reservedSuffixes('', '', ' restricted.example.com. , '), ['restricted.example.com']);
});
