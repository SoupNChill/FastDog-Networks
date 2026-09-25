import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { generateInvite, listInvites, redeemInvite, inviteRequired } from '../src/onboard/invites.js';
import { createZone } from '../src/onboard/store.js';
import { readZone } from '../src/dns/store.js';

describe('invite codes', () => {
  let tmp;
  const previous = {};
  before(() => {
    for (const key of ['DATA_DIR', 'ZONES_DIR', 'INVITE_REQUIRED', 'NODE_ENV', 'AGENT_TOKEN']) previous[key] = process.env[key];
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fastdog-invites-'));
    process.env.DATA_DIR = path.join(tmp, 'data');
    process.env.ZONES_DIR = path.join(tmp, 'zones');
    delete process.env.INVITE_REQUIRED;
  });
  after(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it('defaults to required and saves private, unguessable codes', () => {
    assert.equal(inviteRequired(), true);
    const invite = generateInvite({ note: 'first dogfood' });
    assert.match(invite.code, /^fd-[0-9a-f]{48}$/);
    assert.equal(invite.remaining_uses, 1);
    assert.deepEqual(invite.redemptions, []);
    assert.deepEqual(listInvites(), [invite]);
    assert.equal(fs.statSync(path.join(tmp, 'data', 'invites.json')).mode & 0o777, 0o600);
    assert.throws(() => createZone({ zone: 'missing.example' }), /invite_code_required/);
    assert.throws(() => createZone({ zone: 'wrong.example', invite_code: 'bad' }), /invalid_invite_code/);
    assert.equal(readZone('missing.example'), null);
  });

  it('redeems only successful zone creation and tracks uses', () => {
    const invite = generateInvite({ max_uses: 2, expires_in_hours: 2 });
    assert.throws(() => createZone({ zone: 'bad.example', edge_ip: 'not-an-ip', invite_code: invite.code }), /invalid_edge_ip/);
    assert.equal(listInvites().at(-1).remaining_uses, 2);
    createZone({ zone: 'one.example', invite_code: invite.code });
    assert.equal(listInvites().at(-1).redemptions[0].redeemed_by, 'one.example');
    assert.ok(listInvites().at(-1).redemptions[0].redeemed_at);
    assert.throws(() => createZone({ zone: 'one.example', invite_code: invite.code }), /zone_exists/);
    assert.equal(listInvites().at(-1).remaining_uses, 1);
    createZone({ zone: 'two.example', invite_code: invite.code });
    assert.equal(listInvites().at(-1).remaining_uses, 0);
    assert.throws(() => createZone({ zone: 'three.example', invite_code: invite.code }), /invite_exhausted/);
    assert.equal(readZone('three.example'), null);
  });

  it('validates expiry and generation inputs', () => {
    for (const input of [{ max_uses: 0 }, { max_uses: 1.5 }, { expires_at: 'tomorrow' }, { expires_in_hours: -1 }, { expires_at: new Date(Date.now() + 60000).toISOString(), expires_in_hours: 1 }, { note: 123 }]) {
      assert.throws(() => generateInvite(input), { status: 400 });
    }
    assert.throws(() => generateInvite({ expires_at: '2020-01-01T00:00:00Z' }), /expired_invite/);
    const invite = generateInvite({ expires_at: new Date(Date.now() + 60000).toISOString() });
    assert.ok(invite.expires_at);
    const saved = listInvites();
    saved.at(-1).expires_at = '2020-01-01T00:00:00.000Z';
    fs.writeFileSync(path.join(tmp, 'data', 'invites.json'), JSON.stringify(saved));
    assert.throws(() => redeemInvite({ code: invite.code }), /invite_expired/);
  });

  it('supports disabling the gate and CLI commands', () => {
    process.env.INVITE_REQUIRED = 'false';
    assert.equal(inviteRequired(), false);
    createZone({ zone: 'open.example' });
    const cli = (...args) => spawnSync(process.execPath, ['scripts/onboard.js', ...args], { cwd: process.cwd(), env: process.env, encoding: 'utf8' });
    const generated = cli('generate-invite', '--max-uses', '2', '--note', 'cli');
    assert.equal(generated.status, 0, generated.stderr);
    const code = JSON.parse(generated.stdout).code;
    assert.ok(JSON.parse(cli('list-invites').stdout).some((item) => item.code === code));
    assert.equal(JSON.parse(cli('redeem-invite', code, '--redeemed-by', 'operator').stdout).redemptions[0].redeemed_by, 'operator');
    process.env.INVITE_REQUIRED = 'yes';
    const created = cli('create-zone', 'cli.example', '--invite', code);
    assert.equal(created.status, 0, created.stderr);
    assert.equal(listInvites().find((item) => item.code === code).remaining_uses, 0);
  });

  it('authenticates HTTP invite routes and gates zone creation', async () => {
    process.env.NODE_ENV = 'test';
    process.env.AGENT_TOKEN = 'invite-test-master';
    process.env.INVITE_REQUIRED = 'true';
    const { server } = await import('../src/edge/server.js');
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}/_fastdog/onboard`;
    const post = (route, body, token = 'invite-test-master') => fetch(`${base}${route}`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-fastdog-token': token }, body: JSON.stringify(body) });
    try {
      assert.equal((await post('/invites', {}, 'wrong')).status, 401);
      assert.equal((await fetch(`${base}/invites`)).status, 401);
      assert.equal((await post('/zones', { zone: 'http.example' })).status, 400);
      const response = await post('/invites', { max_uses: 1, note: 'http' });
      assert.equal(response.status, 201);
      const invite = await response.json();
      const listed = await fetch(`${base}/invites`, { headers: { 'x-fastdog-token': 'invite-test-master' } });
      assert.equal(listed.status, 200);
      assert.ok((await listed.json()).some((item) => item.code === invite.code));
      assert.equal((await post('/zones', { zone: 'http.example', invite_code: invite.code })).status, 201);
      assert.equal((await post('/invites/redeem', { code: invite.code })).status, 409);
      const second = await (await post('/invites', {})).json();
      assert.equal((await post('/invites/redeem', { code: second.code, redeemed_by: 'test-user' })).status, 201);
      assert.equal(listInvites().find((item) => item.code === second.code).redemptions[0].redeemed_by, 'test-user');
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
});
