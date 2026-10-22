import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import WebSocket, { WebSocketServer } from 'ws';
import {
  proxyViaTunnel,
  parseMaxBodyBytes,
  DEFAULT_MAX_BODY_BYTES,
  MAX_BODY_BYTES_CEILING,
} from '../src/control/tunnels.js';

const CAP = 1024;
const ROOT = fileURLToPath(new URL('..', import.meta.url));

describe('EDGE_MAX_BODY_BYTES parsing', () => {
  it('defaults to 50 MiB when unset or empty', () => {
    assert.equal(DEFAULT_MAX_BODY_BYTES, 52428800);
    assert.equal(parseMaxBodyBytes(undefined), DEFAULT_MAX_BODY_BYTES);
    assert.equal(parseMaxBodyBytes(''), DEFAULT_MAX_BODY_BYTES);
  });

  it('accepts positive integers up to the ceiling', () => {
    assert.equal(parseMaxBodyBytes('1024'), 1024);
    assert.equal(parseMaxBodyBytes(String(MAX_BODY_BYTES_CEILING)), 73400320);
  });

  it('rejects bad and over-ceiling values', () => {
    for (const bad of ['0', '-1', '1.5', 'abc', '1e6', ' 10', String(MAX_BODY_BYTES_CEILING + 1), '999999999999999999999']) {
      assert.throws(() => parseMaxBodyBytes(bad), /invalid EDGE_MAX_BODY_BYTES/, bad);
    }
  });

  it('fails edge startup on an invalid value', () => {
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', "await import('./src/edge/server.js')"], {
      cwd: ROOT,
      env: { ...process.env, NODE_ENV: 'test', AGENT_TOKEN: 'test-token', EDGE_MAX_BODY_BYTES: String(MAX_BODY_BYTES_CEILING + 1) },
      encoding: 'utf8',
      timeout: 20000,
    });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /invalid EDGE_MAX_BODY_BYTES/);
  });
});

describe('tunneled request body cap', () => {
  let wss;
  let edge;
  let edgePort;
  let agentWs;
  const agent = { id: 'agent-cap', hostname: 'cap.example.test', ws: null };
  const frames = [];
  let agentClosed = false;

  before(async () => {
    wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
    await new Promise((resolve) => wss.once('listening', resolve));
    const serverSide = new Promise((resolve) => wss.once('connection', resolve));
    agentWs = new WebSocket(`ws://127.0.0.1:${wss.address().port}`);
    agentWs.on('close', () => { agentClosed = true; });
    agentWs.on('message', (data) => {
      const msg = JSON.parse(String(data));
      frames.push(msg);
      const body = msg.bodyBase64 ? Buffer.from(msg.bodyBase64, 'base64') : Buffer.alloc(0);
      agentWs.send(JSON.stringify({
        type: 'http_res', id: msg.id, status: 200,
        headers: { 'content-type': 'text/plain', 'x-body-bytes': String(body.length) },
        bodyBase64: body.toString('base64'),
      }));
    });
    agent.ws = await serverSide;
    edge = http.createServer((req, res) => {
      const proxy = () => proxyViaTunnel(agent, req, res, { maxBodyBytes: CAP });
      // Stand-ins for earlier middleware: one consumed the body, one paused the stream.
      if (req.url === '/consumed') return req.resume().once('end', () => setImmediate(proxy));
      if (req.url === '/paused') { req.pause(); return setImmediate(proxy); }
      return proxy();
    });
    await new Promise((resolve) => edge.listen(0, '127.0.0.1', resolve));
    edgePort = edge.address().port;
  });

  after(async () => {
    agentWs.close();
    await new Promise((resolve) => edge.close(resolve));
    await new Promise((resolve) => wss.close(resolve));
  });

  function request({ body, chunked = false, headers = {}, path = '/upload' }) {
    return new Promise((resolve, reject) => {
      const req = http.request({
        host: '127.0.0.1', port: edgePort, method: 'POST', path,
        headers: { host: agent.hostname, ...headers },
        agent: false,
      }, (res) => {
        const parts = [];
        res.on('data', (c) => parts.push(c));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(parts) }));
      });
      req.setTimeout(5000, () => req.destroy(new Error('timed out')));
      req.on('error', reject);
      if (chunked) {
        // Write in pieces without Content-Length so the edge must count as data arrives.
        for (let i = 0; i < body.length; i += 256) req.write(body.subarray(i, i + 256));
        req.end();
      } else {
        req.end(body);
      }
    });
  }

  function assert413(r) {
    assert.equal(r.status, 413);
    assert.match(r.headers['content-type'], /application\/json/);
    assert.equal(r.headers.connection, 'close');
    assert.deepEqual(JSON.parse(String(r.body)), { error: 'payload_too_large', limit: CAP });
  }

  it('rejects an over-cap Content-Length without reading the body or sending a frame', async () => {
    const before = frames.length;
    const r = await new Promise((resolve, reject) => {
      // Declare a large body but send none: the 413 must arrive without the edge waiting for it.
      const sock = net.connect(edgePort, '127.0.0.1', () => {
        sock.write(`POST /upload HTTP/1.1\r\nHost: ${agent.hostname}\r\nContent-Length: 104857600\r\n\r\n`);
      });
      let raw = '';
      sock.on('data', (c) => { raw += c; });
      sock.on('close', () => resolve(raw));
      sock.on('error', reject);
    });
    assert.match(r, /^HTTP\/1\.1 413 /);
    assert.match(r, /connection: close/i);
    assert.ok(r.endsWith(JSON.stringify({ error: 'payload_too_large', limit: CAP })));
    assert.equal(frames.length, before);
  });

  it('rejects an over-cap Content-Length sent by a normal client', async () => {
    const before = frames.length;
    assert413(await request({ body: Buffer.alloc(CAP + 1, 0x61) }));
    assert.equal(frames.length, before);
  });

  it('rejects a chunked body that grows past the cap and sends no frame', async () => {
    const before = frames.length;
    const raw = await new Promise((resolve, reject) => {
      // Never send the terminating chunk: the edge must answer and close on its own.
      const sock = net.connect(edgePort, '127.0.0.1', () => {
        sock.write(`POST /upload HTTP/1.1\r\nHost: ${agent.hostname}\r\nTransfer-Encoding: chunked\r\n\r\n`);
        for (let i = 0; i < 6; i++) sock.write(`100\r\n${'b'.repeat(256)}\r\n`);
      });
      let out = '';
      sock.on('data', (c) => { out += c; });
      sock.on('close', () => resolve(out));
      sock.on('error', reject);
    });
    assert.match(raw, /^HTTP\/1\.1 413 /);
    assert.match(raw, /connection: close/i);
    assert.equal(raw.match(/HTTP\/1\.1 /g).length, 1);
    assert.ok(raw.endsWith(JSON.stringify({ error: 'payload_too_large', limit: CAP })));
    assert.equal(frames.length, before);
  });

  it('leaves invalid Content-Length to Node (400) and sends no frame', async () => {
    const before = frames.length;
    const raw = await new Promise((resolve, reject) => {
      const sock = net.connect(edgePort, '127.0.0.1', () => {
        sock.write(`POST /upload HTTP/1.1\r\nHost: ${agent.hostname}\r\nContent-Length: -5\r\n\r\n`);
      });
      let out = '';
      sock.on('data', (c) => { out += c; });
      sock.on('close', () => resolve(out));
      sock.on('error', reject);
    });
    assert.match(raw, /^HTTP\/1\.1 400 /);
    assert.equal(frames.length, before);
  });

  it('proxies a body exactly at the cap intact', async () => {
    const body = Buffer.alloc(CAP, 0x63);
    const r = await request({ body });
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, body);
    assert.equal(Buffer.from(frames.at(-1).bodyBase64, 'base64').length, CAP);
  });

  it('proxies chunked bodies at and under the cap intact', async () => {
    for (const size of [CAP, 300]) {
      const body = Buffer.from(Array.from({ length: size }, (_, i) => i % 251));
      const r = await request({ body, chunked: true });
      assert.equal(r.status, 200);
      assert.deepEqual(r.body, body);
    }
  });

  it('still proxies (empty body, no hang) when an earlier middleware consumed the stream', async () => {
    const r = await request({ body: Buffer.from('eaten'), chunked: true, path: '/consumed' });
    assert.equal(r.status, 200);
    assert.equal(r.headers['x-body-bytes'], '0');
  });

  it('reads and caps a stream an earlier middleware paused', async () => {
    const before = frames.length;
    assert413(await request({ body: Buffer.alloc(CAP + 1), chunked: true, path: '/paused' }));
    assert.equal(frames.length, before);
    const r = await request({ body: Buffer.from('paused-ok'), chunked: true, path: '/paused' });
    assert.equal(r.status, 200);
    assert.equal(String(r.body), 'paused-ok');
  });

  it('keeps the tunnel open and serving after over-cap requests', async () => {
    assert413(await request({ body: Buffer.alloc(CAP + 100) }));
    assert.equal(agentWs.readyState, WebSocket.OPEN);
    assert.equal(agent.ws.readyState, WebSocket.OPEN);
    assert.equal(agentClosed, false);
    const r = await request({ body: Buffer.from('hello') });
    assert.equal(r.status, 200);
    assert.equal(String(r.body), 'hello');
    assert.equal(agentClosed, false);
  });
});
