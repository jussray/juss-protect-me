// Juss Protect Me — payments + automatic entitlement.
// Flow: POST /buy (email, plan) -> Stripe Checkout (hosted by Stripe)
//   -> Stripe webhook (signature-verified) -> account + entitlement
//   switched on automatically, Model Two API key issued. No manual step.
// Prices live in Stripe; the Worker reads Price IDs from env:
//   STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET,
//   STRIPE_PRICE_ONE, STRIPE_PRICE_TWO, STRIPE_MODE ('test' | 'live')
import { addUser, getUserByEmail, listUsers, recordPayment, saveUser } from './store.mjs';

const enc = new TextEncoder();
function hex(bytes) { return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join(''); }
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, enc.encode(msg)));
}
async function sha256Hex(msg) {
  return hex(await crypto.subtle.digest('SHA-256', enc.encode(msg)));
}
function randomHex(bytes) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return hex(a);
}

export async function verifyStripeSignature(payload, header, secret, nowSec = Math.floor(Date.now() / 1000)) {
  if (!header) return false;
  const parts = Object.fromEntries(header.split(',').map((p) => p.split('=').map((s) => s.trim())));
  const t = Number(parts.t);
  if (!t || Math.abs(nowSec - t) > 300) return false;
  const expect = await hmacHex(secret, `${t}.${payload}`);
  return timingSafeEqual(parts.v1 || '', expect);
}

async function claimKey(env) {
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(`${env.SESSION_SECRET}:keyclaim`));
  return crypto.subtle.importKey('raw', digest, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
export async function encryptClaim(env, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await claimKey(env), enc.encode(plaintext));
  const pack = new Uint8Array(iv.length + ct.byteLength);
  pack.set(iv); pack.set(new Uint8Array(ct), iv.length);
  return btoa(String.fromCharCode(...pack));
}
export async function decryptClaim(env, packed) {
  const pack = Uint8Array.from(atob(packed), (c) => c.charCodeAt(0));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: pack.slice(0, 12) }, await claimKey(env), pack.slice(12));
  return new TextDecoder().decode(pt);
}

export async function accountToken(env, userId) {
  const sig = await hmacHex(env.SESSION_SECRET, `account:${userId}`);
  return `${userId}.${sig}`;
}
export async function readAccountToken(env, token) {
  if (!token || !token.includes('.')) return null;
  const cut = token.lastIndexOf('.');
  const userId = token.slice(0, cut);
  const sig = token.slice(cut + 1);
  const expect = await hmacHex(env.SESSION_SECRET, `account:${userId}`);
  return timingSafeEqual(sig, expect) ? userId : null;
}

export function createPayments({ store, fetchImpl = fetch }) {
  return {
    async fetch(request, env) {
      const url = new URL(request.url);
      const { pathname } = url;

      if (pathname === '/buy' && request.method === 'POST') {
        if (!env.STRIPE_SECRET_KEY) return new Response('Payments are not configured yet.', { status: 503 });
        const form = await request.formData();
        const email = String(form.get('email') || '').trim().toLowerCase();
        const plan = String(form.get('plan') || '');
        const price = plan === 'one' ? env.STRIPE_PRICE_ONE : plan === 'two' ? env.STRIPE_PRICE_TWO : null;
        if (!email || !price) return new Response('Choose a product and enter the email for the account.', { status: 400 });
        const origin = url.origin;
        const body = new URLSearchParams({
          mode: 'subscription',
          'line_items[0][price]': price,
          'line_items[0][quantity]': '1',
          customer_email: email,
          'metadata[email]': email,
          'metadata[plan]': plan,
          success_url: `${origin}/checkout/success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${origin}/checkout/cancel`,
        });
        const res = await fetchImpl('https://api.stripe.com/v1/checkout/sessions', {
          method: 'POST',
          headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`, 'Content-Type': 'application/x-www-form-urlencoded' },
          body,
        });
        const session = await res.json();
        if (!res.ok || !session.url) return new Response('Checkout could not be started. Nothing was charged.', { status: 502 });
        return new Response(null, { status: 303, headers: { Location: session.url } });
      }

      if (pathname === '/webhooks/stripe' && request.method === 'POST') {
        if (!env.STRIPE_WEBHOOK_SECRET) return new Response('Webhook not configured', { status: 503 });
        const payload = await request.text();
        const ok = await verifyStripeSignature(payload, request.headers.get('Stripe-Signature'), env.STRIPE_WEBHOOK_SECRET);
        if (!ok) return new Response('Invalid signature', { status: 400 });
        const event = JSON.parse(payload);
        if (await store.get(`event:${event.id}`)) return Response.json({ received: true, duplicate: true });
        await store.put(`event:${event.id}`, { at: Date.now(), type: event.type });

        if (event.type === 'checkout.session.completed') {
          const s = event.data.object;
          const email = (s.metadata?.email || s.customer_email || '').toLowerCase();
          const plan = s.metadata?.plan || 'two';
          if (email) {
            let user = await getUserByEmail(store, email);
            const apiKey = plan === 'two' ? `jp2_${randomHex(16)}` : null;
            if (!user) {
              user = {
                id: randomHex(8), email, plan, entitlement: 'active',
                stripeCustomerId: s.customer || null,
                apiKeyHash: apiKey ? await sha256Hex(apiKey) : null,
                apiKeyPrefix: apiKey ? apiKey.slice(0, 8) : null,
                createdAt: Date.now(), updatedAt: Date.now(),
              };
              await addUser(store, user);
            } else {
              user.entitlement = 'active';
              user.plan = plan;
              user.stripeCustomerId = s.customer || user.stripeCustomerId;
              if (apiKey) {
                if (user.apiKeyHash) await store.del(`keyhash:${user.apiKeyHash}`);
                user.apiKeyHash = await sha256Hex(apiKey); user.apiKeyPrefix = apiKey.slice(0, 8);
              }
              user.updatedAt = Date.now();
              await saveUser(store, user);
            }
            if (user.apiKeyHash) await store.put(`keyhash:${user.apiKeyHash}`, user.id);
            if (apiKey) await store.put(`keyclaim:${user.id}`, await encryptClaim(env, apiKey));
            if (s.id) await store.put(`session:${s.id}`, user.id);
            await recordPayment(store, {
              amount: s.amount_total || 0, currency: s.currency || 'usd',
              mode: env.STRIPE_MODE || 'test', at: Date.now(), email,
            });
          }
        }
        if (event.type === 'customer.subscription.deleted') {
          const sub = event.data.object;
          const users = await listUsers(store);
          const user = users.find((u) => u.stripeCustomerId === sub.customer);
          if (user) { user.entitlement = 'canceled'; user.updatedAt = Date.now(); await saveUser(store, user); }
        }
        if (event.type === 'invoice.payment_failed') {
          const inv = event.data.object;
          const users = await listUsers(store);
          const user = users.find((u) => u.stripeCustomerId === inv.customer);
          if (user && user.entitlement === 'active') { user.entitlement = 'past_due'; user.updatedAt = Date.now(); await saveUser(store, user); }
        }
        return Response.json({ received: true });
      }

      if (pathname === '/account' && request.method === 'GET') {
        const userId = await readAccountToken(env, url.searchParams.get('token') || '');
        const user = userId ? await store.get(`user:${userId}`) : null;
        if (!user) return new Response('Account link not recognized.', { status: 404 });
        const lines = [
          `Account: ${user.email}`,
          `Product: Juss Protect Me ${user.plan === 'one' ? 'One' : 'Two'}`,
          `Entitlement: ${user.entitlement.toUpperCase()}`,
          user.entitlement === 'active'
            ? (user.plan === 'two'
              ? 'Protection entitlement is ON. Your gateway API key was issued at checkout (shown once there); its prefix is ' + user.apiKeyPrefix + '…'
              : 'Protection entitlement is ON. Install step for Model One follows the founder\u2019s install-form decision (spec D1) — nothing is claimed before it exists.')
            : 'Protection entitlement is not active on this account.',
        ];
        return new Response(lines.join('\n'), { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });
      }

      const PAGE_STYLE = ':root{--bg:#07040d;--panel:#0e0918;--line:#3b2560;--ink:#f2ecfb;--muted:#b9a8d9;--accent:#b678ff;--gold:#e9c476}body{margin:0;background:radial-gradient(900px 500px at 85% -5%,#2a1650 0,transparent 60%),var(--bg);color:var(--ink);font:16px/1.55 system-ui,sans-serif;min-height:100vh}.wrap{max-width:640px;margin:auto;padding:36px 22px 70px}.brand{color:var(--muted);letter-spacing:.28em;font-size:12px;text-transform:uppercase}.brand b{color:var(--gold);font:600 20px Georgia,serif;letter-spacing:.06em}h1{font:clamp(28px,4.5vw,40px)/1.12 Georgia,serif;margin:14px 0 8px}.card{background:linear-gradient(165deg,var(--panel),#090613);border:1px solid var(--line);border-radius:18px;padding:24px;margin-top:20px}.sub{color:var(--muted)}label{display:block;margin:14px 0 6px;color:var(--muted);font-size:13px;letter-spacing:.12em;text-transform:uppercase}input,select{width:100%;padding:12px 14px;border-radius:12px;border:1px solid var(--line);background:#0a0614;color:var(--ink);font-size:16px}button{margin-top:20px;padding:13px 26px;border:0;border-radius:999px;background:linear-gradient(180deg,#e9c6ff,var(--accent));color:#1d0f33;font-weight:700;font-size:16px;cursor:pointer}.key{font:600 17px ui-monospace,monospace;background:#0a0614;border:1px dashed var(--gold);border-radius:12px;padding:14px;word-break:break-all;color:var(--gold)}.warn{background:#3a2c0f;border:1px solid #6b5a2a;color:#ffe1a3;border-radius:12px;padding:12px 16px;margin-top:16px}code{color:var(--gold)}';
      const pageShell = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} — Juss Protect Me</title><style>${PAGE_STYLE}</style></head><body><div class="wrap"><div class="brand"><b>JUSS &amp; CO.</b> · Protect</div>${body}</div></body></html>`;
      const html = (body, status = 200) => new Response(body, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });

      if (pathname === '/checkout' && request.method === 'GET') {
        const plan = url.searchParams.get('plan') === 'one' ? 'one' : 'two';
        if (!env.STRIPE_SECRET_KEY) return html(pageShell('Checkout', `<div class="card"><h1>Enrollment opens at launch</h1><p class="sub">Checkout is built and tested, and it switches on with the launch — nothing to pay today, and this page collects nothing.</p></div>`));
        return html(pageShell('Checkout', `<div class="card"><h1>Get protected</h1><p class="sub">One subscription. Your account is created and your protection switches on automatically the moment payment completes — no setup steps after.</p>${env.STRIPE_MODE === 'test' ? '<div class="warn">TEST MODE — practice money only, no real charge.</div>' : ''}<form method="post" action="/buy"><label for="email">Email for your account</label><input id="email" name="email" type="email" required><label for="plan">Product</label><select id="plan" name="plan"><option value="two" ${plan === 'two' ? 'selected' : ''}>Juss Protect Me 2 — AI agent security</option><option value="one" ${plan === 'one' ? 'selected' : ''}>Juss Protect Me — people, devices, everyday safety</option></select><button type="submit">Continue to secure payment</button></form><p class="sub" style="margin-top:14px">Payment is handled by Stripe. Juss &amp; Co. never sees your card.</p></div>`));
      }

      if (pathname === '/checkout/success' && request.method === 'GET') {
        const sid = url.searchParams.get('session_id') || '';
        const userId = sid ? await store.get(`session:${sid}`) : null;
        const user = userId ? await store.get(`user:${userId}`) : null;
        if (!user) return html(pageShell('Switching on', `<div class="card"><h1>Payment received — switching you on</h1><p class="sub">Your account is being created automatically. Refresh this page in a few seconds; if it does not appear, keep your Stripe receipt — it is the proof of this payment.</p></div>`));
        const token = await accountToken(env, user.id);
        let keyBlock = '';
        if (user.plan === 'two') {
          const claim = await store.get(`keyclaim:${user.id}`);
          if (claim) {
            const raw = await decryptClaim(env, claim);
            await store.put(`keyclaim:${user.id}`, null);
            keyBlock = `<div class="warn">Save this key now — it is shown once.</div><p style="margin-top:12px">Your gateway key:</p><div class="key">${raw}</div><p class="sub" style="margin-top:10px">Your agents send it as <code>Authorization: Bearer &lt;key&gt;</code> to the gateway check. Lost it? Rotate a fresh one from your account page — the old one stops working.</p>`;
          } else {
            keyBlock = `<p class="sub">Your gateway key was already claimed. If you lost it, rotate a fresh one from your <a href="/account?token=${encodeURIComponent(token)}">account page</a> — the old one stops working.</p>`;
          }
        } else {
          keyBlock = `<p class="sub">Your checkup app: <a href="/app.html">open it here</a> and choose "Install this app" (or Add to Home Screen) — that is the whole install. Your answers stay on your device.</p>`;
        }
        return html(pageShell('You are protected', `<div class="card"><h1>You&rsquo;re in — protection is ON</h1><p class="sub">Account <strong>${user.email}</strong> · Juss Protect Me ${user.plan === 'one' ? 'One' : 'Two'} · entitlement <strong>ACTIVE</strong>, switched on automatically by your payment${env.STRIPE_MODE === 'test' ? ' (TEST MODE — practice payment)' : ''}.</p>${keyBlock}<p style="margin-top:16px"><a href="/account?token=${encodeURIComponent(token)}">Open your account page</a></p></div>`));
      }

      if (pathname === '/checkout/cancel' && request.method === 'GET') {
        return html(pageShell('Checkout canceled', `<div class="card"><h1>No charge — checkout canceled</h1><p class="sub">Nothing was paid and no account was created. When you are ready, <a href="/checkout">start again</a>.</p></div>`));
      }

      if (pathname === '/account/rotate' && request.method === 'POST') {
        const form = await request.formData();
        const userId = await readAccountToken(env, String(form.get('token') || ''));
        const user = userId ? await store.get(`user:${userId}`) : null;
        if (!user || user.plan !== 'two') return new Response('Not available for this account.', { status: 403 });
        const raw = `jp2_${randomHex(16)}`;
        if (user.apiKeyHash) await store.del(`keyhash:${user.apiKeyHash}`);
        user.apiKeyHash = await sha256Hex(raw);
        user.apiKeyPrefix = raw.slice(0, 8);
        user.updatedAt = Date.now();
        await saveUser(store, user);
        await store.put(`keyhash:${user.apiKeyHash}`, user.id);
        return html(pageShell('New key', `<div class="card"><h1>Your new gateway key</h1><div class="warn">Save it now — shown once. Your previous key stops working immediately.</div><div class="key" style="margin-top:12px">${raw}</div><p style="margin-top:16px"><a href="/account?token=${encodeURIComponent(String(form.get('token')))}">Back to your account</a></p></div>`));
      }

      return new Response('Not found', { status: 404 });
    },
  };
}
