import { createModelOneRoom } from './platform/model-one-room.mjs';
import { createPayments } from './platform/payments.mjs';
import { createStore, listUsers, statsFromStore } from './platform/store.mjs';

// Model One's first Worker entry (founder-gated decision, launch 2026-10-25):
// serves the static site plus the product platform routes — founder room,
// checkout, account. The public pages stay scriptless under _headers.
const app = {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    const store = createStore(env);
    if (pathname === '/founder' || pathname.startsWith('/founder/') || pathname === '/api/founder/state') {
      return createModelOneRoom({ statsProvider: () => statsFromStore(store), membersProvider: () => listUsers(store) }).fetch(request, env);
    }
    if (pathname === '/buy' || pathname === '/webhooks/stripe' || pathname === '/checkout' || pathname.startsWith('/checkout/') || pathname === '/account' || pathname === '/account/rotate' || pathname === '/account/policy') {
      return createPayments({ store }).fetch(request, env);
    }
    if (pathname === '/api/status') {
      return Response.json({
        service: 'juss-protect-me',
        component: 'site',
        scope: 'this-worker-only',
        state: 'serving',
        otherSystemsProtected: false,
      }, { headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
    }
    if (pathname === '/api' || pathname.startsWith('/api/')) {
      return new Response('Not found', { status: 404 });
    }
    return env.ASSETS.fetch(request);
  },
};

const RESPONSE_HEADERS = Object.freeze({
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Strict-Transport-Security': 'max-age=31536000',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'Content-Security-Policy': "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; upgrade-insecure-requests",
});

export default {
  async fetch(request, env, ctx) {
    const result = await app.fetch(request, env);
    const headers = new Headers(result.headers);
    const path = new URL(request.url).pathname;
    for (const [key, value] of Object.entries(RESPONSE_HEADERS)) headers.set(key, value);
    if (path === '/founder' || path.startsWith('/founder/') || path === '/checkout' || path.startsWith('/checkout/') || path === '/buy' || path === '/account' || path === '/account/rotate' || path === '/account/policy') {
      headers.set('Content-Security-Policy', "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; upgrade-insecure-requests");
    }
    if (path === '/api' || path.startsWith('/api/')) headers.set('Cache-Control', 'no-store');
    return new Response(result.body, { status: result.status, statusText: result.statusText, headers });
  },
};
