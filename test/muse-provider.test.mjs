import assert from 'node:assert/strict';
import test from 'node:test';

import { createMuseProvider, invokeMuse, museProviderState } from '../src/muse-provider.mjs';

const KEY = 'TEST-KEY-NOT-A-REAL-SECRET';
const ENV = { MODEL_API_KEY: KEY, PROTECT_ME_MUSE_MODEL: 'muse-spark-1.3' };

function mockFetch(handler) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init });
    return handler(url, init);
  };
  impl.calls = calls;
  return impl;
}

const okFetch = () => mockFetch(async () => new Response(JSON.stringify({
  id: 'resp_123', status: 'completed', output_text: 'bounded answer',
}), { status: 200, headers: { 'content-type': 'application/json' } }));

test('not advertised when key or safe model is missing', async () => {
  assert.equal(createMuseProvider({}, okFetch()), undefined);
  assert.equal(createMuseProvider({ MODEL_API_KEY: KEY }, okFetch()), undefined);
  assert.equal(createMuseProvider({ MODEL_API_KEY: KEY, PROTECT_ME_MUSE_MODEL: 'muse-spark-9.9' }, okFetch()), undefined);
  assert.equal(museProviderState({}).state, 'ABSENT');
  assert.equal(museProviderState(ENV).state, 'PRESENT');
  const fetchImpl = okFetch();
  await assert.rejects(() => invokeMuse({}, { prompt: 'hi' }, fetchImpl), /muse_not_configured/);
  assert.equal(fetchImpl.calls.length, 0);
});

test('bounded call returns provider:meta evidence and never serializes the key', async () => {
  const fetchImpl = okFetch();
  const result = await invokeMuse(ENV, { prompt: 'challenge this claim' }, fetchImpl);
  assert.equal(result.state, 'INTEGRATED');
  assert.equal(result.authority, 'none');
  assert.equal(result.evidenceRef, 'provider:meta:resp_123');
  assert.equal(result.text, 'bounded answer');
  assert.equal(fetchImpl.calls.length, 1);
  const { url, init } = fetchImpl.calls[0];
  assert.equal(url, 'https://api.meta.ai/v1/responses');
  assert.equal(init.method, 'POST');
  const sent = JSON.parse(init.body);
  assert.deepEqual(sent, { model: 'muse-spark-1.3', input: 'challenge this claim', store: false, max_output_tokens: 2000 });
  assert.equal(JSON.stringify(sent).includes(KEY), false);
  assert.equal(JSON.stringify(result).includes(KEY), false);
});

test('restricted sensitivity is rejected before any network call', async () => {
  const fetchImpl = okFetch();
  await assert.rejects(
    () => invokeMuse(ENV, { prompt: 'hi', sensitivity: 'restricted' }, fetchImpl),
    /restricted_not_authorized/,
  );
  assert.equal(fetchImpl.calls.length, 0);
});

test('provider failures fail closed with sanitized errors', async () => {
  const httpFail = mockFetch(async () => new Response(`provider body mentioning ${KEY}`, { status: 500 }));
  await assert.rejects(() => invokeMuse(ENV, { prompt: 'hi' }, httpFail), (err) => {
    assert.equal(err.message, 'muse_http_500');
    assert.equal(err.message.includes(KEY), false);
    return true;
  });
  const nonCompleted = mockFetch(async () => new Response(JSON.stringify({
    id: 'resp_9', status: 'failed', output_text: 'should not surface',
  }), { status: 200 }));
  await assert.rejects(() => invokeMuse(ENV, { prompt: 'hi' }, nonCompleted), /muse_non_completed/);
});
