import http from 'node:http';
import assert from 'node:assert/strict';

export async function listen(t, server) {
  assert.equal(server.listening, false, 'factory must return a server that is not listening');
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    server.closeAllConnections?.();
  }));
  return server;
}

export function jsonRequest(server, path, { method = 'GET', headers = {}, body, raw, timeout = 7000 } = {}) {
  const payload = raw ?? (body === undefined ? undefined : JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1', port: server.address().port, path, method,
      headers: { connection: 'close', ...(payload === undefined ? {} : {
        'content-type': 'application/json', 'content-length': Buffer.byteLength(payload),
      }), ...headers },
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('error', reject);
      res.on('end', () => {
        clearTimeout(timer);
        const text = Buffer.concat(chunks).toString('utf8');
        let json;
        try { json = text ? JSON.parse(text) : undefined; } catch { /* HTML pages are valid responses too. */ }
        resolve({ status: res.statusCode, headers: res.headers, body: json, text });
      });
    });
    const timer = setTimeout(() => req.destroy(new Error('test HTTP deadline exceeded')), timeout);
    req.on('error', (error) => { clearTimeout(timer); reject(error); });
    req.end(payload);
  });
}

export function expectError(response, status, error) {
  assert.equal(response.status, status);
  assert.match(response.headers['content-type'] || '', /^application\/json\b/);
  assert.deepEqual(response.body, { error });
}

export function expectRateLimit(response) {
  assert.equal(response.status, 429);
  assert.equal(response.body.error, 'rate_limited');
  assert.ok(Number.isFinite(response.body.retry_after) && response.body.retry_after > 0);
}
