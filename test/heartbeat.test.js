import { it } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { startHeartbeat } from '../agent/heartbeat.js';
import { watchTunnel } from '../src/control/heartbeat.js';
import { registerAgent, attachWs, listAgents, _resetForTests } from '../src/control/tunnels.js';

class FakeSocket extends EventEmitter {
  readyState = 1;
  sent = [];
  send(data) { this.sent.push(JSON.parse(data)); }
  terminate() { this.readyState = 3; this.emit('close'); }
}

it('edge replies to ping and updates registered lastSeen', () => {
  _resetForTests();
  const { id } = registerAgent({ hostname: 'heartbeat.example', localUpstream: 'http://127.0.0.1:9', token: 'secret', expectedToken: 'secret' });
  const ws = new FakeSocket();
  assert.equal(attachWs(id, ws, 'secret'), true);
  const before = listAgents()[0].lastSeen;
  const stop = watchTunnel(ws, id);
  ws.emit('message', JSON.stringify({ type: 'ping' }));
  assert.deepEqual(ws.sent, [{ type: 'pong' }]);
  assert.ok(listAgents()[0].lastSeen >= before);
  stop(); _resetForTests();
});

it('agent terminates a connection after missed pongs', async (t) => {
  const ws = new FakeSocket();
  const stop = startHeartbeat(ws, { intervalMs: 5, maxMissed: 2 });
  t.after(stop);
  await new Promise((resolve, reject) => {
    const deadline = setTimeout(() => reject(new Error('heartbeat did not close the socket')), 2000);
    t.after(() => clearTimeout(deadline));
    ws.once('close', resolve);
  });
  assert.equal(ws.readyState, 3);
  assert.equal(ws.sent.length, 2);
  stop();
});
