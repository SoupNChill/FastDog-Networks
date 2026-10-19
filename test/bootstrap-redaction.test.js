import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { EventEmitter } from 'node:events';
import { randomBytes } from 'node:crypto';
import { bootstrapHandler, EXCHANGE_PATH } from '../src/onboard/bootstrap.js';
import { get as getMetrics } from '../src/lib/metrics.js';
import { createInternalServer } from '../src/internal/server.js';
function request(handler, url, headers, body) {
  const req = new PassThrough();
  Object.assign(req, { url, method: 'POST', headers, socket: { remoteAddress: '127.0.0.1' } });
  const res = new EventEmitter();
  res.writableEnded = false;
  return new Promise((resolve, reject) => {
    res.writeHead = (status, headers) => Object.assign(res, { statusCode: status, headers });
    res.end = (text = '') => { res.writableEnded = true; res.emit('finish'); resolve({ status: res.statusCode, text, headers: res.headers }); };
    Promise.resolve(handler(req, res)).catch(reject);
    req.end(JSON.stringify(body));
  });
}
test('injected exceptions and sentinel inputs never reach bootstrap/exchange/refund errors or audit output', async t => {
  const sentinel = randomBytes(32).toString('hex'), audit = [];
  let failure;
  const service = { enabled: true, admit() {}, async exchange() { throw failure; }, issue() { throw failure; }, reconcile() { throw failure; } };
  const exchange = bootstrapHandler(service);
  const portalKey = randomBytes(32).toString('hex');
  const internal = createInternalServer({ bootstrap: service, portalKey, agentToken: randomBytes(32).toString('hex'), logger: event => audit.push(event) });
  const ports = [exchange, internal.listeners('request')[0]];
  t.after(() => internal.close());
  const captured = [], originals = [process.stdout.write, process.stderr.write];
  process.stdout.write = process.stderr.write = function(chunk, ...args) { captured.push(String(chunk)); const cb = args.find(v => typeof v === 'function'); cb?.(); return true; };
  try {
    for (const [status, code] of [[400, 'invalid_request'], [401, 'unauthorized'], [409, 'bootstrap_used'], [410, 'bootstrap_expired'], [429, 'rate_limited'], [503, 'bootstrap_unavailable']]) {
      for (const maliciousCode of [false, true]) {
        failure = Object.assign(new Error(sentinel), { status, code: maliciousCode ? sentinel : code, retry_after: sentinel });
        for (const [port, url, headers] of [
          [ports[0], EXCHANGE_PATH, { authorization: `Bearer ${sentinel}`, 'x-fastdog-agent-proof': sentinel }],
          ...['bootstraps', 'bootstraps/orphan/reconcile'].map(action => [ports[1], `/internal/v1/tenants/t_aaaaaaaaaaaaaaaaaaaa/hostnames/app.example.test/${action}`, { 'x-fastdog-portal-key': portalKey }]),
        ]) {
          const result = await request(port, url, headers, { code: sentinel, proof: sentinel });
          assert.equal(result.status, maliciousCode ? 503 : status);
          assert.ok(!JSON.stringify(result).includes(sentinel));
        }
      }
    }
    failure = new Error(sentinel); // transport exception, without a trusted status/code
    assert.equal((await request(ports[0], EXCHANGE_PATH, {}, {})).status, 503);
  } finally { [process.stdout.write, process.stderr.write] = originals; }
  assert.ok(audit.length > 0);
  assert.ok(!JSON.stringify({ audit, captured, metrics: getMetrics() }).includes(sentinel));
});
