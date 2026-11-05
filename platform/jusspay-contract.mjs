// Juss Protect Me — JussPay contract adapter.
//
// Entitlement activation validates through the canonical JussPay contract
// (jussray/JussPay, docs/DESIGN-MERGE.md) instead of trusting the raw
// webhook payload alone: JussPay is the source of truth for what a paid
// Protect plan is — its product, price, amount, currency, and origin.
//
// The plan fixtures below mirror TEST_PLANS in src/subscriptions.mjs on
// JussPay main (design-merge landed 2026-11-05). They are the test-mode
// contract: sandbox prices for the two Protect models. If these fixtures
// drift from JussPay's contract, validation fails closed and activation
// stops — that is deliberate. Live plans enter this file only when JussPay
// publishes them in its contract (the Stripe activation gate).
//
// Revocation paths (subscription deleted, payment failed) do not consult
// this adapter: removing an entitlement never needs proof of entitlement.

export const JUSSPAY_TEST_PLANS = Object.freeze({
  one: Object.freeze({
    id: 'one',
    name: 'Protect Model One',
    product_id: 'protect-one',
    merchant_id: 'jussco',
    stripe_product_id: 'prod_VZRcwIn9d0aHqX',
    price_id: 'price_1UYIjBRs4gw4sfJHThjLPcpS',
    amount: 499,
    currency: 'usd',
    origin: 'https://protect.jussco.company',
  }),
  two: Object.freeze({
    id: 'two',
    name: 'Protect Model Two',
    product_id: 'protect-two',
    merchant_id: 'jussco',
    stripe_product_id: 'prod_VZRc42RZZVrCS9',
    price_id: 'price_1UYIjDRs4gw4sfJHm94eRNsJ',
    amount: 1900,
    currency: 'usd',
    origin: 'https://protect2.jussco.company',
  }),
});

export function jusspayPlan(key) {
  return Object.hasOwn(JUSSPAY_TEST_PLANS, key) ? JUSSPAY_TEST_PLANS[key] : null;
}

// Mirror of JussPay's priceMatches: the provider price object must be the
// plan's own price, on the plan's product, active, recurring monthly, at
// the contract amount and currency, in the matching mode.
export function jusspayPriceMatches(price, plan) {
  return Boolean(price) && typeof price === 'object'
    && price.id === plan.price_id
    && price.product === plan.stripe_product_id
    && price.active === true
    && price.type === 'recurring'
    && price.recurring?.interval === 'month'
    && price.recurring?.interval_count === 1
    && price.unit_amount === plan.amount
    && price.currency === plan.currency
    && price.livemode === false;
}

// The session half of JussPay's subscriptionMatches, over the fields a
// Checkout completion event itself carries: a paid subscription session,
// in test mode, for exactly the contract amount, bound to this plan in
// its metadata, with real customer and subscription objects attached.
export function jusspaySessionMatches(session, plan) {
  return Boolean(session) && typeof session === 'object'
    && session.mode === 'subscription'
    && session.payment_status === 'paid'
    && session.livemode === false
    && session.amount_total === plan.amount
    && session.currency === plan.currency
    && typeof session.customer === 'string' && session.customer.startsWith('cus_')
    && typeof session.subscription === 'string' && session.subscription.startsWith('sub_')
    && session.metadata?.plan === plan.id;
}

// Full activation verdict for a checkout.session.completed object.
// Returns { ok: true, plan } or { ok: false, reason } — never throws on
// bad input, and every failure is closed (no activation).
export async function validateJusspayActivation({ env, session, fetchImpl = fetch }) {
  const plan = jusspayPlan(session?.metadata?.plan);
  if (!plan) return { ok: false, reason: 'plan_not_in_jusspay_contract' };
  if ((env.STRIPE_MODE || 'test') !== 'test') {
    // JussPay's published contract is test-mode today. In live mode there
    // is nothing canonical to validate against yet, so activation waits
    // for JussPay's live plan fixtures instead of trusting raw payloads.
    return { ok: false, reason: 'jusspay_live_plans_not_published' };
  }
  if (!jusspaySessionMatches(session, plan)) {
    return { ok: false, reason: 'session_does_not_match_jusspay_contract' };
  }
  let price;
  try {
    const res = await fetchImpl(`https://api.stripe.com/v1/prices/${plan.price_id}`, {
      headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}` },
    });
    if (!res || !res.ok) return { ok: false, reason: 'jusspay_price_unavailable' };
    price = await res.json();
  } catch {
    return { ok: false, reason: 'jusspay_price_unavailable' };
  }
  if (!jusspayPriceMatches(price, plan)) {
    return { ok: false, reason: 'price_does_not_match_jusspay_contract' };
  }
  return { ok: true, plan };
}
