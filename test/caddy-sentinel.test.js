import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
const request = (port, target, headers) => new Promise((resolve, reject) => {
  const req = http.request({ host: '127.0.0.1', port, path: target, method: 'POST', headers }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
  req.on('error', reject); req.end();
});
test('Caddy runtime sentinel gate: access and runtime error log redaction', async t => {
  const version = spawnSync('caddy', ['version'], { encoding: 'utf8' });
  if (version.error?.code === 'ENOENT') return t.skip('Caddy absent on PATH; runtime sentinel test MUST pass where Caddy is available before enablement');
  assert.equal(version.status, 0, version.stderr);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'caddy-sentinel-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const upstream = http.createServer((req, res) => { res.writeHead(req.headers['x-fixture-status'] === 'failure' ? 401 : 200); res.end(); });
  upstream.on('upgrade', (req, socket) => socket.end('HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'));
  const upstreamPort = await listen(upstream); t.after(() => upstream.close());
  const reserve = http.createServer(); const port = await listen(reserve); await new Promise(resolve => reserve.close(resolve));
  const snippet = fs.readFileSync(new URL('../deploy/caddy/access-logs.snippet', import.meta.url), 'utf8').replace('/var/log/caddy/', `${dir}/`);
  const deployment = fs.readFileSync(new URL('../deploy/caddy/on-demand-tls.snippet', import.meta.url), 'utf8');
  const runtimeFilter = deployment.slice(deployment.indexOf('    log {'), deployment.indexOf('    on_demand_tls'));
  const config = `{\n admin off\n auto_https off\n${runtimeFilter}}\n${snippet}\nhttp://127.0.0.1:${port} {\n bind 127.0.0.1\n import fdlog edge-catch-all\n reverse_proxy 127.0.0.1:${upstreamPort}\n}\n`;
  const file = path.join(dir, 'Caddyfile'); fs.writeFileSync(file, config);
  const adapted = spawnSync('caddy', ['adapt', '--config', file, '--adapter', 'caddyfile'], { encoding: 'utf8' });
  assert.equal(adapted.status, 0, adapted.stderr);
  let output = '';
  const child = spawn('caddy', ['run', '--config', file, '--adapter', 'caddyfile'], { env: { ...process.env, XDG_DATA_HOME: dir, XDG_CONFIG_HOME: dir }, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.on('data', chunk => output += chunk); child.stderr.on('data', chunk => output += chunk);
  t.after(() => child.kill());
  let ready = false;
  for (let i = 0; i < 100; i++) { try { await request(port, '/ready', {}); ready = true; break; } catch { await delay(20); } }
  assert.ok(ready, output);
  const sentinels = Array.from({ length: 4 }, () => randomBytes(24).toString('hex'));
  const headers = { authorization: `Bearer ${sentinels[0]}`, cookie: `session=${sentinels[1]}`, 'x-fastdog-agent-proof': sentinels[2] };
  for (const route of ['/_fastdog/agents/bootstrap/exchange', '/_fastdog/agents/register', '/_fastdog/tunnel']) {
    assert.equal(await request(port, `${route}?code=${sentinels[3]}`, headers), 200);
    assert.equal(await request(port, `${route}?token=${sentinels[3]}`, { ...headers, 'x-fixture-status': 'failure' }), 401);
  }
  assert.equal(await request(port, `/_fastdog/tunnel?token=${sentinels[3]}`, { ...headers, connection: 'Upgrade', upgrade: 'websocket' }), 401);
  upstream.closeIdleConnections?.();
  await new Promise(resolve => upstream.close(resolve));
  assert.equal(await request(port, `/_fastdog/agents/bootstrap/exchange?code=${sentinels[3]}`, headers), 502);
  child.kill(); await new Promise(resolve => child.once('exit', resolve));
  const access = fs.readFileSync(path.join(dir, ['edge-catch-all', 'log'].join('.')), 'utf8');
  assert.ok(access.includes('502')); assert.ok(output.includes(['http', 'log', 'error'].join('.')));
  for (const sentinel of sentinels) { assert.ok(!access.includes(sentinel)); assert.ok(!output.includes(sentinel)); }
});
