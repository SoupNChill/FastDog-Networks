export function plans() {
  return {
    starter: { name: 'Starter', amount: 900, priceId: process.env.STRIPE_PRICE_STARTER || null },
    pro: { name: 'Pro', amount: 2900, priceId: process.env.STRIPE_PRICE_PRO || null },
  };
}

export function getPlan(id) {
  const available = plans();
  return Object.hasOwn(available, id) ? available[id] : null;
}
