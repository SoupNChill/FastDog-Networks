export const tenants = ['t_aaaaaaaaaaaaaaaaaaaa', 't_bbbbbbbbbbbbbbbbbbbb', 't_cccccccccccccccccccc'];
export const attachTarget = 'attach.example-edge.test';
export const altAttachTarget = 'alt.example-edge.test';
export const edgePublicIp = '192.0.2.10';
export const reservedSuffixes = ['reserved.example.com', 'example-edge.test'];
export const unicodeHost = 'b\u00fccher.example.com';
export const longestHost = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(49)}.example.com`;
export const acceptedHosts = [
  [`${'a'.repeat(63)}.example.com`, `${'a'.repeat(63)}.example.com`],
  [longestHost, longestHost],
  ['xn--bcher-kva.example.com', 'xn--bcher-kva.example.com'],
  [unicodeHost, 'xn--bcher-kva.example.com'],
  ['App.Example.COM', 'app.example.com'],
  ['app.example.com.', 'app.example.com'],
  ['app.example.com', 'app.example.com'],
  ['myapp.example.com', 'myapp.example.com'],
  ['x.app.example.com', 'x.app.example.com'],
];
export const rejectedClaims = [
  ['*.example.com', 'invalid_hostname'],
  ['a*.example.com', 'invalid_hostname'],
  ['192.0.2.1', 'invalid_hostname'],
  ['reserved.example.com', 'reserved_hostname'],
];
export const hostnameTable = [
  ...acceptedHosts.map(([input, expected]) => ({ input, expected })),
  { input: '  App.Example.COM.  ', expected: 'app.example.com' },
  { input: 'example.com', expected: 'example.com' },
  { input: 'reserved.example.com', expected: 'reserved.example.com' },
  { input: 'xn--p1ai.example.com', expected: 'xn--p1ai.example.com' },
  ...['', ' ', 'localhost', '*.example.com', 'a*.example.com', '192.0.2.1',
    '[::1]', '::1', 'app.example.com:443', 'app.example.com/path',
    'https://app.example.com', 'app.example.com?x=1', 'app.example.com#x',
    'user@app.example.com', 'app..example.com', '.example.com', 'app.example.com..',
    '-app.example.com', 'app-.example.com', 'app_name.example.com', 'app.example.1',
    'app.example.c', 'app example.com', 'app\texample.com', 'app\n.example.com',
    'app\u0000.example.com', `${'a'.repeat(64)}.example.com`, `a${longestHost}`,
  ].map((input) => ({ input, error: 'invalid_hostname' })),
  ...[null, undefined, 42, {}, []].map((input) => ({ input, error: 'invalid_hostname' })),
];
