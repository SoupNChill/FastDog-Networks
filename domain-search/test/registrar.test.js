import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import https from 'node:https';
import { EventEmitter } from 'node:events';
import { createRegistrar } from '../src/registrar.js';
import { username, apiKey, xml, available, taken, invalid, price } from './fixtures.js';

process.env.REGISTRAR_USERNAME = username;
process.env.REGISTRAR_API_KEY = apiKey;

function noLeak(error) {
  for (const secret of ['opensrs', 'OPENSRS', username, apiKey]) assert.ok(!String(error).includes(secret));
  return true;
}

test('hard allowlist rejects before transport, including extra attributes and bad object', async () => {
  let calls = 0;
  const registrar = createRegistrar({ transport: async () => { calls++; return xml(available); } });
  for (const action of ['SW_REGISTER', 'REGISTER', 'RENEW', 'TRANSFER', 'MODIFY', 'NAME_SUGGEST', 'OTHER', 'toString', '__proto__']) {
    await assert.rejects(registrar._callForTest(action, 'DOMAIN', { domain: 'example.com' }), noLeak);
  }
  for (const [action, object, attrs] of [
    ['LOOKUP', 'CONTACT', { domain: 'example.com' }],
    ['LOOKUP', 'DOMAIN', { domain: 'example.com', extra: 'no' }],
    ['GET_PRICE', 'DOMAIN', { domain: 'example.com', period: '1', reg_type: 'transfer' }],
    ['GET_PRICE', 'DOMAIN', { domain: 'example.com', period: '2', reg_type: 'new' }],
    ['GET_PRICE', 'DOMAIN', { domain: 'example.com', period: 1, reg_type: 'new' }],
    ['GET_PRICE', 'DOMAIN', { domain: 'example.com', period: '1', reg_type: 'new', extra: 'no' }],
    ['GET_PRICE', 'DOMAIN', { domain: 'example.com' }],
    ['LOOKUP', 'DOMAIN', { domain: 'example.com', [Symbol('extra')]: 'no' }],
  ]) await assert.rejects(registrar._callForTest(action, object, attrs), noLeak);
  assert.equal(calls, 0);
});

test('exact lookup envelope, HTTPS options, and double-MD5 signature', async () => {
  const registrar = createRegistrar({ transport: async (request) => {
    assert.equal(request.body, "<?xml version='1.0' encoding='UTF-8' standalone='no' ?>\n<!DOCTYPE OPS_envelope SYSTEM 'ops.dtd'>\n<OPS_envelope><header><version>0.9</version></header><body><data_block><dt_assoc><item key=\"protocol\">XCP</item><item key=\"action\">LOOKUP</item><item key=\"object\">DOMAIN</item><item key=\"attributes\"><dt_assoc><item key=\"domain\">example.com</item></dt_assoc></item></dt_assoc></data_block></body></OPS_envelope>");
    const md5 = (value) => createHash('md5').update(value).digest('hex');
    assert.equal(request.headers['X-Signature'], md5(md5(request.body + apiKey) + apiKey));
    assert.match(request.headers['X-Signature'], /^[a-f0-9]{32}$/);
    assert.equal(request.headers['X-Username'], username);
    assert.equal(request.headers['Content-Type'], 'text/xml');
    assert.equal(request.headers['Content-Length'], Buffer.byteLength(request.body));
    assert.equal(request.hostname, 'rr-n1-tor.opensrs.net');
    assert.equal(request.port, 55443);
    assert.equal(request.path, '/');
    assert.equal(request.method, 'POST');
    assert.equal(request.timeout, 8000);
    return xml(available);
  } });
  assert.deepEqual(await registrar.lookup('example.com'), available);
});

test('XML encode/parse round trip with all entities', async () => {
  const domain = `a&<b>"'é.com`;
  const registrar = createRegistrar({ transport: async ({ body }) => {
    assert.ok(body.includes('a&amp;&lt;b&gt;&quot;&apos;é.com'));
    return body;
  } });
  assert.deepEqual(await registrar.lookup(domain), {
    protocol: 'XCP', action: 'LOOKUP', object: 'DOMAIN', attributes: { domain },
  });
});

test('recursive assoc/array, whitespace, numeric entities, empty items, safe property keys', async () => {
  const value = JSON.parse('{"nested":[{"x":"<&\\\""},["one","two"]],"__proto__":"safe","empty":""}');
  const registrar = createRegistrar({ transport: async () => xml(value).replace('<item key="empty"></item>', '<item key="empty"/>').replace('one', '&#111;&#x6e;e') });
  assert.deepEqual(await registrar.lookup('example.com'), value);
  assert.equal({}.safe, undefined);
});

test('live response shapes and registration/renewal request attributes', async () => {
  for (const shape of [available, taken, invalid, { ...available, attributes: { status: 'available', reason: 'Premium Name' } }]) {
    const registrar = createRegistrar({ transport: async () => xml(shape) });
    assert.deepEqual(await registrar.lookup('example.com'), shape);
  }
  for (const type of ['new', 'renewal']) {
    const registrar = createRegistrar({ transport: async ({ body }) => {
      assert.ok(body.includes('<item key="action">GET_PRICE</item>'));
      assert.ok(body.includes('<item key="period">1</item>'));
      assert.ok(body.includes(`<item key="reg_type">${type}</item>`));
      return xml(price('14.50', { is_registry_premium: '1', registry_premium_group: 'tier-a' }));
    } });
    assert.equal((await registrar.getPrice('example.com', type)).attributes.price, '14.50');
  }
});

test('credentials resolved at call time, legacy fallback, override, and sanitized errors', async () => {
  let calls = 0;
  const registrar = createRegistrar({ transport: async (request) => {
    calls++;
    assert.equal(request.headers['X-Username'], 'later-user');
    assert.equal(request.hostname, 'mock.invalid');
    return xml(taken);
  } });
  try {
    delete process.env.REGISTRAR_USERNAME;
    delete process.env.REGISTRAR_API_KEY;
    process.env.OPENSRS_USERNAME = 'later-user';
    process.env.OPENSRS_API_KEY = apiKey;
    process.env.REGISTRAR_HOST = 'mock.invalid';
    await registrar.lookup('example.com');
    assert.equal(calls, 1);
    delete process.env.OPENSRS_API_KEY;
    await assert.rejects(registrar.lookup('example.com'), noLeak);
    assert.equal(calls, 1);
  } finally {
    process.env.REGISTRAR_USERNAME = username;
    process.env.REGISTRAR_API_KEY = apiKey;
    delete process.env.OPENSRS_USERNAME;
    delete process.env.OPENSRS_API_KEY;
    delete process.env.REGISTRAR_HOST;
  }
  const failed = createRegistrar({ transport: async () => { throw new Error(`opensrs OPENSRS ${username} ${apiKey}`); } });
  await assert.rejects(failed.lookup('example.com'), noLeak);
  for (const body of ['not xml', '<OPS_envelope>', xml(available).replace('</dt_assoc>', '</broken>'), '<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]>' + xml(available), 'x'.repeat(1_048_577)]) {
    await assert.rejects(createRegistrar({ transport: async () => body }).lookup('example.com'), noLeak);
  }
});

test('default transport enforces an eight-second deadline without opening a socket', async (t) => {
  const request = new EventEmitter();
  let deadline;
  let cleared = false;
  const timer = {};
  request.end = () => {};
  request.destroy = (error) => {
    request.emit('error', error);
    request.emit('close');
  };
  t.mock.method(https, 'request', () => request);
  t.mock.method(globalThis, 'setTimeout', (callback, delay) => {
    assert.equal(delay, 8000);
    deadline = callback;
    return timer;
  });
  t.mock.method(globalThis, 'clearTimeout', (handle) => {
    assert.equal(handle, timer);
    cleared = true;
  });
  const result = createRegistrar().lookup('example.com');
  const rejected = assert.rejects(result, noLeak);
  deadline();
  await rejected;
  assert.equal(cleared, true);
});

test('default transport rejects non-200 and oversized responses without network', async (t) => {
  for (const [status, body] of [[500, xml(available)], [200, 'x'.repeat(1_048_577)]]) {
    const request = new EventEmitter();
    const response = new EventEmitter();
    response.statusCode = status;
    request.destroy = (error) => { request.emit('error', error); request.emit('close'); };
    request.end = () => {
      response.emit('data', Buffer.from(body));
      response.emit('end');
      request.emit('close');
    };
    const stub = t.mock.method(https, 'request', (_, callback) => {
      callback(response);
      return request;
    });
    await assert.rejects(createRegistrar().lookup('example.com'), noLeak);
    stub.mock.restore();
  }
});
