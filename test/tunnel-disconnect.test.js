import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import {
  registerAgent, getAgentByHost, attachWs, detachWs, proxyViaTunnel, _resetForTests,
} from '../src/control/tunnels.js';

class FakeWs extends EventEmitter {
  readyState = 1;
  frames = [];
  send(frame, callback) {
    this.frames.push(JSON.parse(frame));
    this.callback = callback;
    if (this.sendError) throw new Error('send failed');
  }
}

function fixture(t, { uploading = false } = {}) {
  t.mock.timers.enable(['setTimeout']);
  const directory = mkdtempSync(join(process.cwd(), 'test/.tmp-disconnect-'));
  t.after(() => { _resetForTests(); rmSync(directory, { recursive: true, force: true }); });
  const token = 'synthetic-token';
  const { id } = registerAgent({
    hostname: 'disconnect.example.test', localUpstream: 'http://127.0.0.1:8080',
    token, expectedToken: token, dataDir: directory,
  });
  const ws = new FakeWs();
  attachWs(id, ws, token);
  // Match the edge's close/error listener ordering.
  ws.on('close', () => detachWs(id, ws));
  ws.on('error', () => detachWs(id, ws));
  const baseline = ['message', 'close', 'error'].map(event => ws.listenerCount(event));
  const agent = getAgentByHost('disconnect.example.test');
  const req = Object.assign(new EventEmitter(), {
    headers: {}, method: 'POST', url: '/', readableEnded: !uploading,
    resume() {}, pause() {},
  });
  const res = Object.assign(new EventEmitter(), {
    headersSent: false, writes: 0,
    writeHead(status) { assert.equal(this.headersSent, false); this.status = status; this.headersSent = true; },
    end(body) { this.writes++; this.body = body; },
  });
  function clean() {
    assert.deepEqual(['message', 'close', 'error'].map(event => ws.listenerCount(event)), baseline);
    assert.equal(res.listenerCount('close'), 0);
    assert.equal(req.listenerCount('aborted'), 0);
    assert.equal(req.listenerCount('close'), 0);
    const writes = res.writes;
    assert.doesNotThrow(() => t.mock.timers.tick(30001));
    assert.equal(res.writes, writes);
  }
  return { id, token, ws, agent, req, res, clean, start: () => proxyViaTunnel(agent, req, res) };
}

test('disconnect clears pending timeout even when detach runs first', t => {
  const f = fixture(t); f.start();
  assert.doesNotThrow(() => f.ws.emit('close'));
  assert.equal(f.agent.ws, null);
  assert.equal(f.res.status, 502);
  assert.deepEqual(JSON.parse(f.res.body), { error: 'tunnel_disconnected', id: f.ws.frames[0].id });
  f.clean();
  f.ws.callback(new Error('late send failure'));
  assert.equal(f.res.writes, 1);
});

test('timeout after detach without close does not dereference null', t => {
  const f = fixture(t); f.start();
  detachWs(f.id, f.ws);
  assert.doesNotThrow(() => t.mock.timers.tick(30001));
  assert.equal(f.res.status, 504);
  assert.deepEqual(JSON.parse(f.res.body), { error: 'tunnel_timeout', id: f.ws.frames[0].id });
  f.clean();
});

for (const state of ['detached', 'closing']) {
  test(`disconnect during upload: ${state}`, t => {
    const f = fixture(t, { uploading: true }); f.start();
    f.req.emit('data', Buffer.from('body'));
    if (state === 'detached') detachWs(f.id, f.ws);
    else f.ws.readyState = 2;
    assert.doesNotThrow(() => f.req.emit('end'));
    assert.equal(f.res.status, 502);
    assert.equal(JSON.parse(f.res.body).error, 'tunnel_not_connected');
    assert.equal(f.ws.frames.length, 0);
    f.clean();
  });
}

test('reconnect leaves new socket untouched and removes old listeners', t => {
  const f = fixture(t); f.start();
  const next = new FakeWs();
  const listener = () => {};
  next.on('message', listener);
  attachWs(f.id, next, f.token);
  f.ws.emit('close');
  assert.equal(f.agent.ws, next);
  assert.deepEqual(next.listeners('message'), [listener]);
  assert.equal(next.listenerCount('close'), 0);
  assert.equal(f.res.status, 502);
  f.clean();
});

for (const event of ['response close', 'aborted', 'close']) {
  test(`client ${event} cleans up without a response`, t => {
    const f = fixture(t); f.start();
    f.req.readableEnded = false;
    if (event === 'response close') f.res.emit('close');
    else f.req.emit(event);
    f.clean();
    assert.equal(f.res.writes, 0);
    f.ws.callback(new Error('late'));
    assert.equal(f.res.writes, 0);
  });
}

for (const mode of ['throw', 'callback']) {
  test(`send failure via ${mode} is handled`, t => {
    const f = fixture(t);
    f.ws.sendError = mode === 'throw';
    assert.doesNotThrow(f.start);
    if (mode === 'callback') f.ws.callback(new Error('send failed'));
    assert.equal(f.res.status, 502);
    assert.equal(JSON.parse(f.res.body).error, 'tunnel_send_failed');
    f.clean();
  });
}

test('normal reply survives normal request close and cleans up', t => {
  const f = fixture(t); f.start();
  f.req.complete = true;
  f.req.emit('close');
  const frame = { type: 'http_res', id: f.ws.frames[0].id, status: 201,
    headers: {}, bodyBase64: Buffer.from('ok').toString('base64') };
  f.ws.emit('message', JSON.stringify(frame));
  assert.equal(f.res.status, 201);
  assert.equal(String(f.res.body), 'ok');
  f.clean();
  f.ws.emit('message', JSON.stringify(frame));
  assert.equal(f.res.writes, 1);
});

test('socket error settles the request and clears timeout', t => {
  const f = fixture(t); f.start();
  assert.doesNotThrow(() => f.ws.emit('error', new Error('socket failed')));
  assert.equal(f.res.status, 502);
  assert.equal(JSON.parse(f.res.body).error, 'tunnel_disconnected');
  f.clean();
});

test('client destroyed during upload sends no frame or response', t => {
  const f = fixture(t, { uploading: true }); f.start();
  f.res.destroyed = true;
  f.res.emit('close');
  f.req.emit('end');
  assert.equal(f.ws.frames.length, 0);
  assert.equal(f.res.writes, 0);
  f.clean();
});

test('cleanup supports removeListener when off is absent', t => {
  const f = fixture(t);
  f.ws.off = undefined;
  f.start();
  f.ws.emit('close');
  assert.equal(f.res.status, 502);
  f.clean();
});

test('an already-started response is never written twice', t => {
  const f = fixture(t); f.start();
  f.res.headersSent = true;
  f.ws.emit('close');
  assert.equal(f.res.writes, 0);
  f.clean();
});

test('reply on old socket after reconnect cleans only that socket', t => {
  const f = fixture(t); f.start();
  const next = new FakeWs();
  const listener = () => {};
  next.on('message', listener);
  attachWs(f.id, next, f.token);
  f.ws.emit('message', JSON.stringify({ type: 'http_res', id: f.ws.frames[0].id, status: 200 }));
  assert.equal(f.res.status, 200);
  assert.equal(f.agent.ws, next);
  assert.deepEqual(next.listeners('message'), [listener]);
  assert.equal(next.listenerCount('close'), 0);
  f.clean();
});
