import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import WebSocket from 'ws';

// Exercises the cap through the real edge app (Express middleware chain), not a bare handler.
const CAP = 1024;
const HOST = 'cap-edge.example.test';

describe('tunneled request body cap via the edge app', () => {
  let server;
  let port;
  let agentWs;
  let connections = 0;
  const frames = [];

  before(async () => {
    process.env.NODE_ENV = 'test';
    process.env.AGENT_TOKEN = 'test-token';
    process.env.EDGE_MAX_BODY_BYTES = String(CAP);
    const mod = await import('../src/edge/server.js');
    const { registerAgent } = await import('../src/control/tunnels.js');
    // Model an async middleware ahead of the proxy: hold marked requests until Node has
    // fully received the body (req.complete) while it is still buffered, unconsumed.
    mod.app.use((req, _res, next) => {
      if (req.headers['x-test-defer'] !== '1') return next();
      const wait = () => (req.complete ? next() : setTimeout(wait, 1));
      wait();
    });
    const stack = mod.app._router.stack;
    stack.unshift(stack.pop());
    server = mod.server;
    server.on('connection', () => { connections += 1; });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = server.address().port;

    const { id } = registerAgent({
      name: 'cap-edge', hostname: HOST, localUpstream: 'http://127.0.0.1:9',
      token: 'test-token', expectedToken: 'test-token',
    });
    agentWs = new WebSocket(`ws://127.0.0.1:${port}/_fastdog/tunnel?agentId=${id}`, {
      headers: { authorization: 'Bearer test-token' },
    });
    await new Promise((resolve, reject) => {
      agentWs.once('message', resolve);
      agentWs.once('error', reject);
    });
    agentWs.on('message', (data) => {
      const msg = JSON.parse(String(data));
      if (msg.type !== 'http_req') return;
      frames.push(msg);
      agentWs.send(JSON.stringify({
        type: 'http_res', id: msg.id, status: 200,
        headers: { 'content-type': 'application/octet-stream' },
        bodyBase64: msg.bodyBase64,
      }));
    });
  });

  after(async () => {
    agentWs.close();
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
    delete process.env.EDGE_MAX_BODY_BYTES;
  });

  // Send a raw request in one write and collect everything until the edge closes the socket.
  function raw(text, { timeoutMs = 5000 } = {}) {
    return new Promise((resolve, reject) => {
      const sock = net.connect(port, '127.0.0.1', () => sock.write(text));
      let out = Buffer.alloc(0);
      const timer = setTimeout(() => { sock.destroy(); reject(new Error(`timed out; got: ${out}`)); }, timeoutMs);
      sock.on('data', (c) => {
        out = Buffer.concat([out, c]);
        // A keep-alive 200 never closes; stop once its complete body is in.
        const s = String(out);
        const head = s.indexOf('\r\n\r\n');
        const len = /content-length: (\d+)/i.exec(s)?.[1];
        if (s.startsWith('HTTP/1.1 200 ') && len && head !== -1 && out.length >= head + 4 + Number(len)) sock.end();
      });
      sock.on('close', () => { clearTimeout(timer); resolve(String(out)); });
      sock.on('error', (err) => { clearTimeout(timer); reject(err); });
    });
  }

  function chunked(body, { defer = false } = {}) {
    return `POST /upload HTTP/1.1\r\nHost: ${HOST}\r\n${defer ? 'X-Test-Defer: 1\r\n' : ''}Transfer-Encoding: chunked\r\n\r\n`
      + `${body.length.toString(16)}\r\n${body}\r\n0\r\n\r\n`;
  }

  for (const defer of [true, false]) {
    const when = defer ? 'already received and buffered' : 'streamed';
    it(`rejects a ${when} chunked body over the cap with 413 and sends no frame`, async () => {
      const before = frames.length;
      const out = await raw(chunked('x'.repeat(CAP + 1), { defer }));
      assert.match(out, /^HTTP\/1\.1 413 /);
      assert.match(out, /connection: close/i);
      assert.ok(out.endsWith(JSON.stringify({ error: 'payload_too_large', limit: CAP })));
      assert.equal(frames.length, before);
    });

    it(`delivers a ${when} chunked body under the cap intact, not empty`, async () => {
      const body = 'y'.repeat(CAP - 24);
      const out = await raw(chunked(body, { defer }));
      assert.match(out, /^HTTP\/1\.1 200 /);
      assert.equal(Buffer.from(frames.at(-1).bodyBase64 || '', 'base64').toString(), body);
      assert.ok(out.endsWith(body));
    });
  }

  it('answers Expect: 100-continue with an over-cap Content-Length with a final 413 and no frame', async () => {
    const before = frames.length;
    const out = await raw(`POST /upload HTTP/1.1\r\nHost: ${HOST}\r\nExpect: 100-continue\r\nContent-Length: ${CAP + 1}\r\n\r\n`);
    const statuses = [...out.matchAll(/HTTP\/1\.1 (\d{3}) /g)].map((m) => m[1]);
    assert.equal(statuses.at(-1), '413');
    assert.ok(out.endsWith(JSON.stringify({ error: 'payload_too_large', limit: CAP })));
    assert.equal(frames.length, before);
  });

  it('closes the over-cap connection; a following keep-alive request uses a fresh one', async () => {
    const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
    const send = (body) => new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, method: 'POST', path: '/upload', headers: { host: HOST }, agent }, (res) => {
        const parts = [];
        res.on('data', (c) => parts.push(c));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(parts) }));
      });
      req.setTimeout(5000, () => req.destroy(new Error('timed out')));
      req.on('error', reject);
      req.end(body);
    });
    try {
      const startConnections = connections;
      const big = await send(Buffer.alloc(CAP + 1, 0x61));
      assert.equal(big.status, 413);
      assert.equal(big.headers.connection, 'close');
      const small = await send(Buffer.from('after'));
      assert.equal(small.status, 200);
      assert.equal(String(small.body), 'after');
      assert.equal(connections - startConnections, 2);
    } finally {
      agent.destroy();
    }
  });
});
