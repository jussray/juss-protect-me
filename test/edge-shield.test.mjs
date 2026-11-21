import assert from 'node:assert/strict';
import test from 'node:test';
import { createEdgeShield } from '../platform/edge-shield.mjs';

const upstream = { fetch: async () => new Response('upstream', { status: 200 }) };
const request = (path, method = 'GET') => new Request(`https://protect.example${path}`, { method });
const allow = { SHIELD_RATE_LIMITER: { limit: async () => ({ success: true }) } };

test('edge shield decoys probes and unsafe HTTP methods before the app', async () => {
  const shield = createEdgeShield(upstream);
  assert.equal((await shield.fetch(request('/%252eenv'))).status, 404);
  const trace = { method: 'TRACE', url: 'https://protect.example/anything', headers: new Headers() };
  assert.equal((await shield.fetch(trace)).status, 404);
});

test('edge shield fails closed when a sensitive-route limiter is unavailable', async () => {
  const shield = createEdgeShield(upstream);
  assert.equal((await shield.fetch(request('/founder'), {})).status, 503);
  assert.equal((await shield.fetch(request('/'), {})).status, 200);
});

test('edge shield limits every sensitive route and preserves safe traffic', async () => {
  const shield = createEdgeShield(upstream);
  assert.equal((await shield.fetch(request('/checkout/session'), allow)).status, 200);
  const denied = createEdgeShield(upstream);
  const env = { SHIELD_RATE_LIMITER: { limit: async () => ({ success: false }) } };
  const response = await denied.fetch(request('/account/rotate'), env);
  assert.equal(response.status, 429);
  assert.equal(response.headers.get('retry-after'), '60');
});
