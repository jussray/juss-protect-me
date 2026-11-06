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

// ---- canonical JussPay owns billing. Legacy product Stripe paths fail closed. ----

test('product fixtures use canonical JussPay product identifiers', () => {
  assert.equal(ONE.product_id, 'protect-model-one');
  assert.equal(TWO.product_id, 'protect-model-two');
});

test('retired purchase route refuses payment even when configured with live Stripe credentials', async () => {
  let providerCalls = 0;
  const store = createStore({});
  const payments = createPayments({ store, fetchImpl: async () => { providerCalls++; throw Error('Provider must not be called'); } });
  for (const mode of ['test', 'live']) {
    const form = new URLSearchParams({ email: 'buyer@example.com', plan: 'two' });
    const response = await payments.fetch(new Request('https://protect.example/buy', { method: 'POST', body: form }), {
      STRIPE_MODE: mode, STRIPE_SECRET_KEY: 'sk_live_dummy', STRIPE_PRICE_TWO: TWO.price_id,
      STRIPE_WEBHOOK_SECRET: WHSEC,
    });
    assert.equal(response.status, 503);
    assert.match(await response.text(), /JussPay/);
  }
  assert.equal(providerCalls, 0);
  assert.equal(await getUserByEmail(store, 'buyer@example.com'), null);
});

test('retired webhook does not create entitlement or issue gateway key from a signed event', async () => {
  let providerCalls = 0;
  const store = createStore({});
  const payments = createPayments({ store, fetchImpl: async () => { providerCalls++; throw Error('Provider must not be called'); } });
  const plan = TWO;
  const body = JSON.stringify({ id: 'evt_synthetic_test', type: 'checkout.session.completed',
    data: { object: { id: 'cs_test_fake', mode: 'subscription', payment_status: 'paid',
      amount_total: plan.amount, currency: plan.currency, customer: 'cus_fake',
      subscription: 'sub_fake', metadata: { email: 'buyer@example.com', plan: plan.id } } } });
  const t = Math.floor(Date.now()/1000);
  const signature = createHmac('sha256', WHSEC).update(t + '.' + body).digest('hex');
  const response = await payments.fetch(new Request('https://protect.example/webhooks/stripe', {
    method: 'POST', headers: { 'Stripe-Signature': 't=' + t + ',v1=' + signature }, body,
  }), { STRIPE_SECRET_KEY: API_KEY, STRIPE_WEBHOOK_SECRET: WHSEC, STRIPE_MODE: 'test' });
  assert.equal(response.status, 503);
  assert.equal(providerCalls, 0);
  assert.equal(await getUserByEmail(store, 'buyer@example.com'), null);
  assert.equal(await store.get('ledger'), null);
  assert.equal(await store.get('index:users'), null);
});

test('checkout and success return stay closed even with payment secrets configured', async () => {
  const payments = createPayments({ store: createStore({}), fetchImpl: async () => { throw Error('Provider must not be called'); } });
  const env = { STRIPE_SECRET_KEY: 'sk_live_dummy', STRIPE_MODE: 'live', STRIPE_PRICE_TWO: TWO.price_id, SESSION_SECRET: 'dummy' };
  const checkout = await payments.fetch(new Request('https://protect.example/checkout'), env);
  assert.equal(checkout.status, 200);
  assert.match(await checkout.text(), /Enrollment opens at launch/);
  const success = await payments.fetch(new Request('https://protect.example/checkout/success?session_id=cs_fake'), env);
  assert.equal(success.status, 200);
  const html = await success.text();
  assert.match(html, /Account verification required/);
  assert.doesNotMatch(html, /protection is ON/i);
  assert.doesNotMatch(html, /jp2_[A-Za-z0-9]/);
});


test('GEO and AEO answers are visible and match homepage structured data', async () => {
  const { readFileSync } = await import('node:fs');
  const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.ok(html.includes('<meta name="description"'));
  assert.ok(html.includes('<link rel="canonical"'));
  assert.ok(html.includes('<section id="questions"'));
  const match = html.match(/<script type="application\/ld\+json">([^<]+)<\/script>/);
  assert.ok(match, 'structured data available');
  const data = JSON.parse(match[1]);
  const faq = data.find(x => x['@type'] === 'FAQPage');
  const page = data.find(x => x['@type'] === 'WebPage');
  assert.equal(page.url, "https://protect.jussco.company/");
  assert.equal(faq.mainEntity.length, 3);
  for (const answer of faq.mainEntity) {
    assert.ok(html.includes(answer.name));
    assert.ok(html.includes(answer.acceptedAnswer.text));
  }
  assert.ok(html.includes('Paid membership enrollment is not open yet'));
});
