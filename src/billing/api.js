import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import { env } from '../lib/config.js';
import { domain } from '../onboard/store.js';
import { getPlan } from './plans.js';
import { recordSession, markPaidTest, getStatus } from './store.js';
import { createCheckoutSession, retrieveCheckoutSession, constructWebhookEvent, TestKeysError } from './stripe.js';

const page = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Fastdog pricing — test mode</title>
<style>body{font:16px system-ui,sans-serif;max-width:800px;margin:3rem auto;padding:0 1rem;color:#182331}h1{margin-bottom:.25rem}.notice{background:#fff3cd;padding:1rem;border-radius:8px}.plans{display:flex;gap:1rem;flex-wrap:wrap}.plan{border:1px solid #ccd5df;border-radius:8px;padding:1.5rem;flex:1;min-width:220px}button{background:#1366bf;color:white;border:0;border-radius:6px;padding:.7rem 1rem;cursor:pointer}input{padding:.5rem;width:90%;margin:.4rem 0 1rem}</style></head>
<body><h1>Fastdog pricing</h1><p class="notice"><strong>TEST MODE — not live / no real charges.</strong> Placeholder plans for Stripe test Checkout only.</p>
<label>Zone (optional)<br><input id="zone" placeholder="example.com" autocomplete="off"></label>
<label>Email (optional)<br><input id="email" type="email" placeholder="you@example.com"></label>
<div class="plans"><section class="plan"><h2>Starter</h2><p>$9/month — test price</p><button data-plan="starter">Try Starter in test mode</button></section>
<section class="plan"><h2>Pro</h2><p>$29/month — test price</p><button data-plan="pro">Try Pro in test mode</button></section></div><p id="message" role="status"></p>
<script>document.querySelectorAll('button[data-plan]').forEach(button=>button.addEventListener('click',async()=>{
  const message=document.getElementById('message');message.textContent='Creating test checkout…';
  try{const response=await fetch('/_fastdog/billing/checkout',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({plan:button.dataset.plan,zone:document.getElementById('zone').value,email:document.getElementById('email').value})});
  const result=await response.json();if(!response.ok)throw Error(result.message||result.error||'Checkout unavailable');window.location.assign(result.url);
  }catch(error){message.textContent=error.message;}
}));</script></body></html>`;

const errorResponse = (res, error) => {
  if (error instanceof TestKeysError) return res.status(503).json({ error: error.code, message: error.message });
  return res.status(error.status || 502).json({ error: error.status ? error.message : 'billing_unavailable', message: error.status ? error.message : 'Stripe test checkout is unavailable.' });
};

function validEmail(email) {
  return typeof email === 'string' && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export function billingRouter() {
  const router = Router();
  router.get('/pricing', (_req, res) => res.type('html').send(page));
  router.post('/_fastdog/billing/checkout', async (req, res) => {
    try {
      const planId = req.body?.plan;
      const plan = getPlan(planId);
      if (!plan) return res.status(400).json({ error: 'invalid_plan' });
      const zone = req.body?.zone ? domain(req.body.zone) : null;
      const email = req.body?.email || undefined;
      if (email && !validEmail(email)) return res.status(400).json({ error: 'invalid_email' });
      const accountId = randomUUID();
      const session = await createCheckoutSession({ planId, plan, zone, accountId, email });
      recordSession({ id: session.id, zone, account_id: accountId, plan: planId });
      res.json({ url: session.url });
    } catch (error) { errorResponse(res, error); }
  });
  router.get('/_fastdog/billing/success', async (req, res) => {
    const id = req.query.session_id;
    if (typeof id !== 'string' || !id.startsWith('cs_test_')) return res.status(400).type('text').send('Missing test checkout session ID.');
    try {
      const session = await retrieveCheckoutSession(id);
      if (session.livemode || session.status !== 'complete' || session.payment_status !== 'paid') return res.status(202).type('text').send('Test checkout is not paid yet.');
      if (!markPaidTest(session.id)) return res.status(404).type('text').send('Unknown test checkout session.');
      res.type('text').send('TEST MODE checkout complete. paid_test status recorded.');
    } catch (error) {
      if (error instanceof TestKeysError) return res.status(503).type('text').send(error.message);
      res.status(502).type('text').send('Could not verify the test checkout session.');
    }
  });
  router.get('/_fastdog/billing/cancel', (_req, res) => res.type('text').send('TEST MODE checkout canceled. No payment status was recorded.'));
  router.get('/_fastdog/billing/status', (req, res) => {
    if (req.headers['x-fastdog-token'] !== env('AGENT_TOKEN', 'fastdog-local-dev-token')) return res.status(401).json({ error: 'unauthorized' });
    const zone = req.query.zone;
    if (typeof zone !== 'string' || !zone) return res.status(400).json({ error: 'zone_required' });
    res.json({ zone, status: getStatus(zone) });
  });
  return router;
}

export async function billingWebhook(req, res) {
  try {
    const event = await constructWebhookEvent(req.body, req.headers['stripe-signature']);
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      if (session.livemode || session.status !== 'complete' || session.payment_status !== 'paid') return res.status(400).json({ error: 'not_paid_test_session' });
      markPaidTest(session.id);
    }
    res.json({ received: true });
  } catch (error) {
    if (error instanceof TestKeysError) return errorResponse(res, error);
    res.status(400).json({ error: 'invalid_signature' });
  }
}
