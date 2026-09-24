import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getPlan, plans } from '../src/billing/plans.js';
import { recordSession, markPaidTest, getStatus } from '../src/billing/store.js';
import { createCheckoutSession, constructWebhookEvent, TestKeysError } from '../src/billing/stripe.js';

describe('billing test scaffold', () => {
  let tmp;
  let server;
  let base;
  before(async () => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fastdog-billing-'));
    process.env.DATA_DIR = tmp;
    process.env.NODE_ENV = 'test';
    process.env.AGENT_TOKEN = 'billing-test-token';
    delete process.env.STRIPE_SECRET_KEY;
    delete process.env.STRIPE_WEBHOOK_SECRET;
    const mod = await import('../src/edge/server.js');
    server = mod.server;
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${server.address().port}`;
  });
  after(async () => {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(tmp, { recursive: true, force: true });
    delete process.env.DATA_DIR;
    delete process.env.NODE_ENV;
    delete process.env.AGENT_TOKEN;
    delete process.env.STRIPE_SECRET_KEY;
  });

  it('defines placeholder monthly plans', () => {
    assert.equal(getPlan('starter').amount, 900);
    assert.equal(getPlan('pro').amount, 2900);
    assert.equal(getPlan('other'), null);
    assert.equal(getPlan('__proto__'), null);
    assert.equal(plans().starter.priceId, null);
  });

  it('records only known sessions as paid_test', () => {
    assert.equal(markPaidTest('unknown'), null);
    recordSession({ id: 'cs_test_store', zone: 'store.example', account_id: 'account-1', plan: 'pro' });
    const status = markPaidTest('cs_test_store');
    assert.equal(status.status, 'paid_test');
    assert.equal(status.plan, 'pro');
    assert.equal(getStatus('store.example').stripe_session_id, 'cs_test_store');
    assert.equal(getStatus('other.example'), null);
    assert.ok(fs.existsSync(path.join(tmp, 'billing-accounts.json')));
  });

  it('rejects missing and live secret keys before Stripe calls', async () => {
    const args = { planId: 'starter', plan: getPlan('starter'), accountId: 'test-account' };
    await assert.rejects(createCheckoutSession(args), (error) => error instanceof TestKeysError && error.code === 'set_test_keys');
    process.env.STRIPE_SECRET_KEY = 'sk_live_forbidden';
    await assert.rejects(createCheckoutSession(args), (error) => error instanceof TestKeysError);
    await assert.rejects(constructWebhookEvent(Buffer.from('{}'), 'bad'), (error) => error instanceof TestKeysError);
    delete process.env.STRIPE_SECRET_KEY;
  });

  it('serves public pricing and fails checkout gracefully without keys', async () => {
    const pricing = await fetch(`${base}/pricing`);
    assert.equal(pricing.status, 200);
    assert.match(await pricing.text(), /TEST MODE — not live/);
    const checkout = await fetch(`${base}/_fastdog/billing/checkout`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ plan: 'starter', zone: 'test.example' }) });
    assert.equal(checkout.status, 503);
    assert.equal((await checkout.json()).error, 'set_test_keys');
    assert.equal((await fetch(`${base}/_fastdog/billing/cancel`)).status, 200);
    assert.equal((await fetch(`${base}/_fastdog/billing/success?session_id=cs_test_any`)).status, 503);
  });

  it('protects status and keeps webhook body on its raw-parser path', async () => {
    const url = `${base}/_fastdog/billing/status?zone=store.example`;
    assert.equal((await fetch(url)).status, 401);
    const status = await fetch(url, { headers: { 'x-fastdog-token': 'billing-test-token' } });
    assert.equal((await status.json()).status.status, 'paid_test');
    const webhook = await fetch(`${base}/_fastdog/billing/webhook`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert.equal(webhook.status, 503);
    assert.equal((await webhook.json()).error, 'set_test_keys');
  });
});
