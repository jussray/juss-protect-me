import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import test from 'node:test';
import {
  JUSSPAY_TEST_PLANS,
  jusspayPlan,
  jusspayPriceMatches,
  jusspaySessionMatches,
  validateJusspayActivation,
} from '../platform/jusspay-contract.mjs';
import { createPayments } from '../platform/payments.mjs';
import { createStore, getUserByEmail } from '../platform/store.mjs';

const WHSEC = ['whsec', 'fixture'].join('_');
const API_KEY = ['sk', 'test', 'fixture'].join('_');
const ONE = JUSSPAY_TEST_PLANS.one;
const TWO = JUSSPAY_TEST_PLANS.two;

function priceFixture(plan, patch = {}) {
  return {
    id: plan.price_id, product: plan.stripe_product_id, active: true,
    type: 'recurring', recurring: { interval: 'month', interval_count: 1 },
    unit_amount: plan.amount, currency: plan.currency, livemode: false, ...patch,
  };
}

function sessionFixture(plan, patch = {}) {
  return {
    id: 'cs_fixture', mode: 'subscription', payment_status: 'paid', livemode: false,
    amount_total: plan.amount, currency: plan.currency,
    customer: 'cus_fixture', subscription: 'sub_fixture',
    metadata: { email: 'buyer@example.com', plan: plan.id }, ...patch,
  };
}

const pricesFetch = (plan, patch) => async (url) => {
  assert.ok(String(url).endsWith(`/prices/${plan.price_id}`));
  return { ok: true, status: 200, json: async () => priceFixture(plan, patch) };
};

test('price validation mirrors the JussPay contract', () => {
  assert.equal(jusspayPriceMatches(priceFixture(TWO), TWO), true);
  assert.equal(jusspayPriceMatches(priceFixture(TWO, { unit_amount: 1 }), TWO), false);
  assert.equal(jusspayPriceMatches(priceFixture(TWO, { product: 'prod_other' }), TWO), false);
  assert.equal(jusspayPriceMatches(priceFixture(TWO, { livemode: true }), TWO), false);
  assert.equal(jusspayPriceMatches(priceFixture(TWO, { active: false }), TWO), false);
  assert.equal(jusspayPriceMatches(priceFixture(ONE), TWO), false);
});

test('session validation rejects anything off-contract', () => {
  assert.equal(jusspaySessionMatches(sessionFixture(TWO), TWO), true);
  assert.equal(jusspaySessionMatches(sessionFixture(TWO, { payment_status: 'unpaid' }), TWO), false);
  assert.equal(jusspaySessionMatches(sessionFixture(TWO, { mode: 'payment' }), TWO), false);
  assert.equal(jusspaySessionMatches(sessionFixture(TWO, { livemode: true }), TWO), false);
  assert.equal(jusspaySessionMatches(sessionFixture(TWO, { amount_total: 1 }), TWO), false);
  assert.equal(jusspaySessionMatches(sessionFixture(TWO, { subscription: null }), TWO), false);
  assert.equal(jusspaySessionMatches(sessionFixture(TWO, { metadata: { plan: 'one' } }), TWO), false);
});

test('activation verdict: unknown plan and live mode fail closed', async () => {
  const env = { STRIPE_MODE: 'test', STRIPE_SECRET_KEY: API_KEY };
  assert.deepEqual(
    await validateJusspayActivation({ env, session: sessionFixture(TWO, { metadata: { plan: 'gold' } }), fetchImpl: pricesFetch(TWO) }),
    { ok: false, reason: 'plan_not_in_jusspay_contract' },
  );
  assert.deepEqual(
    await validateJusspayActivation({ env: { ...env, STRIPE_MODE: 'live' }, session: sessionFixture(TWO), fetchImpl: pricesFetch(TWO) }),
    { ok: false, reason: 'jusspay_live_plans_not_published' },
  );
  const ok = await validateJusspayActivation({ env, session: sessionFixture(ONE), fetchImpl: pricesFetch(ONE) });
  assert.equal(ok.ok, true);
  assert.equal(ok.plan.id, 'one');
  assert.equal(jusspayPlan('gold'), null);
});

// ---- webhook integration through the real payments module ----

function signedPost(event, secret = WHSEC) {
  const body = JSON.stringify(event);
  const t = Math.floor(Date.now() / 1000);
  const v1 = createHmac('sha256', secret).update(`${t}.${body}`).digest('hex');
  return new Request('https://protect.example/webhooks/stripe', {
    method: 'POST', headers: { 'Stripe-Signature': `t=${t},v1=${v1}` }, body,
  });
}

function paymentsHarness(pricePatch) {
  const store = createStore({});
  const fetchImpl = async (url) => {
    const id = String(url).split('/prices/')[1];
    const plan = id === ONE.price_id ? ONE : TWO;
    return { ok: true, status: 200, json: async () => priceFixture(plan, pricePatch) };
  };
  const payments = createPayments({ store, fetchImpl });
  const env = {
    STRIPE_WEBHOOK_SECRET: WHSEC, STRIPE_SECRET_KEY: API_KEY,
    STRIPE_MODE: 'test', SESSION_SECRET: 'fixture-session',
  };
  return { store, payments, env };
}

let seq = 0;
const completedEvent = (plan, patch) => ({
  id: `evt_${++seq}`, type: 'checkout.session.completed',
  data: { object: sessionFixture(plan, patch) },
});

test('signed completion activates entitlement through the contract (plan two)', async () => {
  const { store, payments, env } = paymentsHarness();
  const res = await payments.fetch(signedPost(completedEvent(TWO)), env);
  assert.equal(res.status, 200);
  const user = await getUserByEmail(store, 'buyer@example.com');
  assert.ok(user);
  assert.equal(user.entitlement, 'active');
  assert.equal(user.plan, 'two');
  assert.ok(user.apiKeyHash);
  const ledger = await store.get('ledger');
  assert.equal(ledger.payments.length, 1);
  assert.equal(ledger.payments[0].validatedBy, 'jusspay-contract');
  assert.equal(ledger.payments[0].plan, 'two');
});

test('amount drift rejects activation and creates no account', async () => {
  const { store, payments, env } = paymentsHarness();
  const res = await payments.fetch(signedPost(completedEvent(TWO, { amount_total: 1 })), env);
  const body = await res.json();
  assert.equal(body.activation, 'rejected');
  assert.equal(body.reason, 'session_does_not_match_jusspay_contract');
  assert.equal(await getUserByEmail(store, 'buyer@example.com'), null);
});

test('provider price drift rejects activation and creates no account', async () => {
  const { store, payments, env } = paymentsHarness({ unit_amount: 5 });
  const res = await payments.fetch(signedPost(completedEvent(TWO)), env);
  const body = await res.json();
  assert.equal(body.activation, 'rejected');
  assert.equal(body.reason, 'price_does_not_match_jusspay_contract');
  assert.equal(await getUserByEmail(store, 'buyer@example.com'), null);
});

test('plan one activates without a gateway key', async () => {
  const { store, payments, env } = paymentsHarness();
  const res = await payments.fetch(signedPost(completedEvent(ONE)), env);
  assert.equal(res.status, 200);
  const user = await getUserByEmail(store, 'buyer@example.com');
  assert.equal(user.entitlement, 'active');
  assert.equal(user.plan, 'one');
  assert.equal(user.apiKeyHash, null);
});

test('revocation still works without contract validation', async () => {
  const { store, payments, env } = paymentsHarness();
  await payments.fetch(signedPost(completedEvent(TWO)), env);
  const del = {
    id: `evt_${++seq}`, type: 'customer.subscription.deleted',
    data: { object: { id: 'sub_fixture', customer: 'cus_fixture' } },
  };
  const res = await payments.fetch(signedPost(del), env);
  assert.equal(res.status, 200);
  const user = await getUserByEmail(store, 'buyer@example.com');
  assert.equal(user.entitlement, 'canceled');
});

test('buy fails fast when the configured price is off-contract (test mode)', async () => {
  const { payments, env } = paymentsHarness();
  const form = new URLSearchParams({ email: 'buyer@example.com', plan: 'two' });
  const bad = await payments.fetch(new Request('https://protect.example/buy', { method: 'POST', body: form }), {
    ...env, STRIPE_PRICE_TWO: 'price_some_other_price',
  });
  assert.equal(bad.status, 503);
});

test('buy passes with the contract price and in live mode', async () => {
  const store = createStore({});
  const fetchImpl = async () => ({ ok: true, status: 200, json: async () => ({ url: 'https://checkout.example/session' }) });
  const payments = createPayments({ store, fetchImpl });
  const form = () => new URLSearchParams({ email: 'buyer@example.com', plan: 'two' });
  const env = { STRIPE_SECRET_KEY: API_KEY, STRIPE_MODE: 'test', STRIPE_PRICE_TWO: TWO.price_id };
  const res = await payments.fetch(new Request('https://protect.example/buy', { method: 'POST', body: form() }), env);
  assert.equal(res.status, 303);
  const live = await payments.fetch(new Request('https://protect.example/buy', { method: 'POST', body: form() }), {
    ...env, STRIPE_MODE: 'live', STRIPE_PRICE_TWO: 'price_live_future',
  });
  assert.equal(live.status, 303);
});
