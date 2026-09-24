import { env } from '../lib/config.js';

export class TestKeysError extends Error {
  constructor(message = 'Set Stripe test keys (sk_test_, pk_test_, whsec_) in .env to use test billing.') {
    super(message);
    this.code = 'set_test_keys';
    this.status = 503;
  }
}

export async function testClient() {
  const key = env('STRIPE_SECRET_KEY');
  if (!key || !key.startsWith('sk_test_')) throw new TestKeysError();
  const { default: Stripe } = await import('stripe');
  return new Stripe(key);
}

export async function createCheckoutSession({ planId, plan, zone, accountId, email }) {
  const stripe = await testClient();
  const successUrl = env('STRIPE_SUCCESS_URL', 'http://localhost:8787/_fastdog/billing/success?session_id={CHECKOUT_SESSION_ID}');
  const cancelUrl = env('STRIPE_CANCEL_URL', 'http://localhost:8787/_fastdog/billing/cancel');
  return stripe.checkout.sessions.create({
    mode: 'subscription',
    line_items: [{ ...(plan.priceId ? { price: plan.priceId } : { price_data: { currency: 'usd', unit_amount: plan.amount, recurring: { interval: 'month' }, product_data: { name: `Fastdog ${plan.name} (TEST MODE)` } } }), quantity: 1 }],
    success_url: successUrl,
    cancel_url: cancelUrl,
    client_reference_id: accountId,
    metadata: { plan: planId, ...(zone ? { zone } : {}) },
    ...(email ? { customer_email: email } : {}),
  });
}

export async function retrieveCheckoutSession(id) {
  return (await testClient()).checkout.sessions.retrieve(id);
}

export async function constructWebhookEvent(rawBody, signature) {
  const stripe = await testClient();
  const secret = env('STRIPE_WEBHOOK_SECRET');
  if (!secret || !secret.startsWith('whsec_')) throw new TestKeysError();
  return stripe.webhooks.constructEvent(rawBody, signature, secret);
}
