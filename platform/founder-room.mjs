// Juss Protect Me — Founder Room (standalone surface, FCR base).
// Slots into the product Worker behind the Shield. Zero client-side JS:
// pages are server-rendered, motion is CSS-first per the dynamic-builds
// standard, and every state shown follows the FCR canon —
// SOURCE IMPLEMENTED -> CONFIGURED -> ACTIVE -> PROVEN, never blurred.
//
// Required Worker secrets/vars (never hardcoded):
//   FOUNDER_EMAIL          founder login email
//   FOUNDER_PASSWORD_HASH  hex PBKDF2-SHA256 of the founder password, OR
//   FOUNDER_PASSWORD       the password itself as a Worker secret (hash is
//                          derived at login; plain secret = what a human
//                          sets in the Cloudflare dashboard)
//   FOUNDER_SALT           hex salt used for the hash
//   SESSION_SECRET         HMAC key for session cookies
// Optional: FOUNDER_ITERS (PBKDF2 iterations, default 100000),
//           STRIPE_SECRET_KEY (presence flips Payments to CONFIGURED)

const enc = new TextEncoder();

function hex(bytes) {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
function unhex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, enc.encode(msg)));
}
export async function hashPassword(password, saltHex, iters = 100000) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: unhex(saltHex), iterations: iters },
    key, 256,
  );
  return hex(bits);
}

const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours
async function makeSession(env) {
  const exp = Date.now() + SESSION_TTL_MS;
  const payload = `${env.FOUNDER_EMAIL}.${exp}`;
  const sig = await hmacHex(env.SESSION_SECRET, payload);
  return { value: `${btoa(payload)}.${sig}`, exp };
}
async function readSession(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)pf_session=([^;]+)/);
  if (!m) return null;
  const [b64, sig] = decodeURIComponent(m[1]).split('.');
  if (!b64 || !sig) return null;
  let payload;
  try { payload = atob(b64); } catch { return null; }
  const expect = await hmacHex(env.SESSION_SECRET, payload);
  if (!timingSafeEqual(sig, expect)) return null;
  const cut = payload.lastIndexOf('.');
  const email = payload.slice(0, cut);
  const expStr = payload.slice(cut + 1);
  if (email !== env.FOUNDER_EMAIL || Number(expStr) < Date.now()) return null;
  return { email, exp: Number(expStr) };
}

const attempts = new Map(); // ip -> [timestamps] (in-memory throttle; Shield rate-limits in production too)
function throttled(ip) {
  const now = Date.now();
  const list = (attempts.get(ip) || []).filter((t) => now - t < 60000);
  list.push(now);
  attempts.set(ip, list);
  return list.length > 5;
}

// State registry — FCR canon. Values are derived from real configuration
// where a signal exists; everything unbuilt says so out loud.
const TWO_SITE_ROWS = [
  { name: 'Edge Shield — Model Two', state: 'ACTIVE', note: 'Rate limiting + response hardening on this Worker\u2019s own routes.' },
];
function buildState(env, siteRows = TWO_SITE_ROWS, live = null) {
  if (!live) {
    live = env.STRIPE_SECRET_KEY
      ? { paymentsState: 'CONFIGURED', paymentsNote: 'Key present; checkout + webhook are built and tested locally, deploy pending.', usersState: 'NOT BUILT', usersNote: 'Accounts open when payments deploy. Users today: 0. Revenue today: $0.' }
      : { paymentsState: 'NOT BUILT', paymentsNote: 'Checkout + webhook are built and tested locally; Stripe keys land at deploy.', usersState: 'NOT BUILT', usersNote: 'Accounts open when payments deploy. Users today: 0. Revenue today: $0.' };
  }
  const configured = Boolean(env.FOUNDER_EMAIL && (env.FOUNDER_PASSWORD_HASH || env.FOUNDER_PASSWORD) && env.SESSION_SECRET);
  return [
    { name: 'Marketing pages (both models)', state: 'ACTIVE', note: 'Live builds matched to founder concepts; visual PROVEN pending founder device check.' },
    ...siteRows,
    { name: 'Founder account', state: configured ? 'CONFIGURED' : 'SOURCE IMPLEMENTED', note: configured ? 'Secrets present; login live on this Worker.' : 'Code built; founder secrets not yet set.' },
    { name: 'Control room', state: configured ? 'ACTIVE' : 'SOURCE IMPLEMENTED', note: 'This room. Standalone surface on the FCR base.' },
    { name: 'Payments & entitlements (Stripe)', state: live.paymentsState, note: live.paymentsNote },
    { name: 'User accounts & installs', state: live.usersState, note: live.usersNote },
    { name: 'Automatic protection — Model Two gateway', state: 'SOURCE IMPLEMENTED', note: 'Gateway built + tested locally (key auth, boundaries, content screen, action log). Flips ACTIVE at deploy; nothing is claimed live before then.' },
    { name: 'Automatic protection — Model One', state: 'SOURCE IMPLEMENTED', note: 'Installable checkup app built (PWA: guided checkup, offline, answers on-device). Flips ACTIVE at deploy; the app claims guidance only, never scanning.' },
  ];
}

const DEFAULT_BRAND = { bg: '#07040d', glow: '#2a1650', panel: '#0e0918', panel2: '#090613', line: '#3b2560', accent: '#b678ff', accentSoft: '#e9c6ff', btnInk: '#1d0f33' };
function styleFor(b) { return `
:root{--bg:${b.bg};--panel:${b.panel};--line:${b.line};--ink:#f2ecfb;--muted:#b9a8d9;--violet:${b.accent};--gold:#e9c476;--ok:#7be0a3;--warn:#ffd479;--off:#8d84a0}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(900px 500px at 85% -5%,${b.glow} 0,transparent 60%),var(--bg);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;min-height:100vh}
a{color:var(--violet)}
.wrap{max-width:1060px;margin:auto;padding:34px 22px 70px}
.brand{display:flex;align-items:center;gap:12px;color:var(--muted);letter-spacing:.28em;font-size:12px;text-transform:uppercase}
.brand b{color:var(--gold);font:600 20px Georgia,serif;letter-spacing:.06em}
h1{font:clamp(30px,4.6vw,46px)/1.1 Georgia,serif;margin:14px 0 8px}
.sub{color:var(--muted);max-width:60ch}
.card{background:linear-gradient(165deg,var(--panel),${b.panel2});border:1px solid var(--line);border-radius:18px;padding:24px;margin-top:22px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px;margin-top:22px}
.stat{background:linear-gradient(165deg,var(--panel),${b.panel2});border:1px solid var(--line);border-radius:16px;padding:18px}
.stat .k{color:var(--muted);font-size:12px;letter-spacing:.18em;text-transform:uppercase}
.stat .v{font:600 30px Georgia,serif;margin-top:6px}
table{width:100%;border-collapse:collapse;margin-top:8px}td,th{padding:11px 8px;border-bottom:1px solid #241743;text-align:left;vertical-align:top}th{color:var(--muted);font-size:12px;letter-spacing:.16em;text-transform:uppercase}
.pill{display:inline-block;padding:3px 11px;border-radius:999px;border:1px solid var(--line);font-size:12px;letter-spacing:.08em}
.pill.on{color:var(--ok);border-color:#2c5c40}.pill.mid{color:var(--warn);border-color:#6b5a2a}.pill.off{color:var(--off)}
.note{color:var(--muted);font-size:14px}
label{display:block;margin:16px 0 6px;color:var(--muted);font-size:13px;letter-spacing:.12em;text-transform:uppercase}
input{width:100%;padding:13px 14px;border-radius:12px;border:1px solid var(--line);background:#0a0614;color:var(--ink);font-size:16px}
button{margin-top:22px;padding:13px 26px;border:0;border-radius:999px;background:linear-gradient(180deg,${b.accentSoft},var(--violet));color:${b.btnInk};font-weight:700;font-size:16px;cursor:pointer}
.err{background:#3a0f1d;border:1px solid #7c2749;color:#ffb9cd;border-radius:12px;padding:12px 16px;margin-top:18px}
.foot{margin-top:30px;color:var(--off);font-size:13px}
@keyframes riseIn{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}
.rise{animation:riseIn .7s cubic-bezier(.2,.7,.2,1) both}.rise2{animation:riseIn .7s cubic-bezier(.2,.7,.2,1) .1s both}.rise3{animation:riseIn .7s cubic-bezier(.2,.7,.2,1) .2s both}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
`; }
function page(title, body, brand = DEFAULT_BRAND) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} — Juss Protect Me Control Room</title><style>${styleFor(brand)}</style></head><body><div class="wrap">${body}</div></body></html>`;
}
function loginPage(error, brand) {
  return page('Founder sign in', `
  <div class="brand rise"><b>JUSS &amp; CO.</b><span>Protect · Control Room</span></div>
  <div class="card rise2" style="max-width:520px">
    <h1>Founder sign in</h1>
    <p class="sub">This room is private — it runs the Protect products. Public pages stay open; this door is yours.</p>
    ${error ? `<div class="err">${error}</div>` : ''}
    <form method="post" action="/founder/login">
      <label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username" required>
      <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Enter the control room</button>
    </form>
  </div>
  <p class="foot rise3">Juss Protect Me · Founder access only · Attempts are rate-limited.</p>`, brand);
}
function pill(state) {
  const cls = state === 'ACTIVE' || state === 'PROVEN' ? 'on' : state === 'NOT BUILT' ? 'off' : 'mid';
  return `<span class="pill ${cls}">${state}</span>`;
}
function roomPage(env, session, cfg, live = null, stats = null, members = null) {
  const rows = buildState(env, cfg.siteRows, live).map((r) => `<tr><td>${r.name}</td><td>${pill(r.state)}</td><td class="note">${r.note}</td></tr>`).join('');
  const membersSection = members === null ? '' : `<div class="card rise3">
    <h2 style="font:600 22px Georgia,serif;margin:0 0 6px">Members</h2>
    ${members.length ? `<table><tr><th>Email</th><th>Product</th><th>Entitlement</th><th>Key</th><th>Member since</th></tr>${members.map((m) => `<tr><td>${escapeHtml(m.email)}</td><td>Protect Me ${m.plan === 'one' ? 'One' : 'Two'}</td><td>${pill(String(m.entitlement || '').toUpperCase())}</td><td class="note">${m.apiKeyPrefix ? escapeHtml(m.apiKeyPrefix) + '&hellip;' : '—'}</td><td class="note">${m.createdAt ? new Date(m.createdAt).toISOString().slice(0, 10) : '—'}</td></tr>`).join('')}</table>` : '<p class="note">No members yet — accounts appear here automatically the moment a checkout completes.</p>'}
  </div>`;
  return page('Control room', `
  <div class="brand rise"><b>JUSS &amp; CO.</b><span>Protect · Control Room</span></div>
  <h1 class="rise">Control room</h1>
  <p class="sub rise">Signed in as founder (${session.email}). Everything below is real state, FCR rules: a thing is only called ACTIVE when it is running, and PROVEN only when it has been verified on the real path.</p>
  <div class="grid rise2">
    <div class="stat"><div class="k">Users</div><div class="v">${stats ? stats.users : 0}</div><div class="note">${stats ? 'Real accounts, created by completed checkouts.' : 'Accounts open when payments deploy.'}</div></div>
    <div class="stat"><div class="k">Active protections</div><div class="v">${stats ? stats.activeProtections : 0}</div><div class="note">Entitlements switched on automatically by payment — nothing is claimed before it runs.</div></div>
    <div class="stat"><div class="k">Revenue</div><div class="v">$${stats ? (stats.revenueCents / 100).toFixed(2) : '0'}</div><div class="note">${stats ? `From ${stats.paymentsCount} recorded payment(s)${env.STRIPE_MODE === 'test' ? ' — TEST MODE, no real charges' : ''}.` : 'Stripe lands when payments deploy.'}</div></div>
    <div class="stat"><div class="k">${cfg.shieldStat.k}</div><div class="v">${cfg.shieldStat.v}</div><div class="note">${cfg.shieldStat.note}</div></div>
  </div>
  <div class="card rise3">
    <h2 style="font:600 22px Georgia,serif;margin:0 0 6px">Systems — state canon</h2>
    <table><tr><th>System</th><th>State</th><th>Receipt</th></tr>${rows}</table>
  </div>
  ${membersSection}
  <form method="post" action="/founder/logout" class="rise3"><button type="submit" style="background:none;border:1px solid var(--line);color:var(--muted)">Sign out</button></form>
  <p class="foot">Standalone room on the FCR base · Session expires ${new Date(session.exp).toISOString()} · Zero data is invented here — empty means empty.</p>`, cfg.brand);
}

const TWO_SHIELD_STAT = { k: 'Edge Shield', v: 'On', note: 'Guarding this Worker\u2019s routes now.' };
export function createFounderRoom(opts = {}) {
  const cfg = {
    brand: { ...DEFAULT_BRAND, ...(opts.brand || {}) },
    siteRows: opts.siteRows || TWO_SITE_ROWS,
    shieldStat: opts.shieldStat || TWO_SHIELD_STAT,
    statsProvider: opts.statsProvider || null,
    membersProvider: opts.membersProvider || null,
  };
  async function liveAndStats(env) {
    const members = cfg.membersProvider ? await cfg.membersProvider(env) : null;
    if (!cfg.statsProvider) return { live: null, stats: null, members };
    const stats = await cfg.statsProvider(env);
    const modeNote = env.STRIPE_MODE === 'test' ? ' TEST MODE — no real charges.' : '';
    const live = {
      paymentsState: stats.paymentsCount > 0 ? 'ACTIVE' : (env.STRIPE_SECRET_KEY ? 'CONFIGURED' : 'NOT BUILT'),
      paymentsNote: stats.paymentsCount > 0
        ? `${stats.paymentsCount} completed payment(s) processed by the signed webhook.${modeNote}`
        : 'Checkout + signed webhook entitlement, built and tested; first payment flips this to ACTIVE.',
      usersState: stats.users > 0 ? 'ACTIVE' : 'NOT BUILT',
      usersNote: stats.users > 0 ? `${stats.users} account(s); ${stats.activeProtections} entitlement(s) active — switched on automatically at payment.` : 'Accounts are created automatically by completed checkouts.',
    };
    return { live, stats, members };
  }
  return {
    async fetch(request, env) {
      const { pathname } = new URL(request.url);
      const configured = Boolean(env.FOUNDER_EMAIL && (env.FOUNDER_PASSWORD_HASH || env.FOUNDER_PASSWORD) && env.SESSION_SECRET);
      if (pathname === '/founder' && request.method === 'GET') {
        const s = configured && (await readSession(request, env));
        if (s) return new Response(null, { status: 302, headers: { Location: '/founder/room' } });
        return new Response(loginPage(undefined, cfg.brand), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }
      if (pathname === '/founder/login' && request.method === 'POST') {
        if (!configured) return new Response(loginPage('Founder access is not configured on this Worker yet.', cfg.brand), { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
        const ip = request.headers.get('CF-Connecting-IP') || 'local';
        if (throttled(ip)) return new Response(loginPage('Too many attempts — wait a minute and try again.', cfg.brand), { status: 429, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
        const form = await request.formData();
        const email = String(form.get('email') || '');
        const password = String(form.get('password') || '');
        const iters = Number(env.FOUNDER_ITERS || 100000);
        const hash = await hashPassword(password, env.FOUNDER_SALT || '', iters);
        const expected = env.FOUNDER_PASSWORD_HASH || (env.FOUNDER_PASSWORD ? await hashPassword(env.FOUNDER_PASSWORD, env.FOUNDER_SALT || '', iters) : '');
        if (email !== env.FOUNDER_EMAIL || !timingSafeEqual(hash, expected)) {
          return new Response(loginPage('Email or password did not match.', cfg.brand), { status: 401, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
        }
        const s = await makeSession(env);
        return new Response(null, {
          status: 302,
          headers: {
            Location: '/founder/room',
            'Set-Cookie': `pf_session=${encodeURIComponent(s.value)}; Path=/founder; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_MS / 1000}`,
          },
        });
      }
      if (pathname === '/founder/room' && request.method === 'GET') {
        const s = configured && (await readSession(request, env));
        if (!s) return new Response(null, { status: 302, headers: { Location: '/founder' } });
        const { live, stats, members } = await liveAndStats(env);
        return new Response(roomPage(env, s, cfg, live, stats, members), { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
      }
      if (pathname === '/api/founder/state' && request.method === 'GET') {
        const s = configured && (await readSession(request, env));
        if (!s) return Response.json({ error: 'unauthorized' }, { status: 401 });
        const { live, members } = await liveAndStats(env);
        const body = { founder: s.email, systems: buildState(env, cfg.siteRows, live) };
        if (members !== null) body.members = members.map((m) => ({ email: m.email, plan: m.plan, entitlement: m.entitlement, apiKeyPrefix: m.apiKeyPrefix || null, createdAt: m.createdAt || null }));
        return Response.json(body, { headers: { 'Cache-Control': 'no-store' } });
      }
      if (pathname === '/founder/logout' && request.method === 'POST') {
        return new Response(null, {
          status: 302,
          headers: { Location: '/founder', 'Set-Cookie': 'pf_session=; Path=/founder; HttpOnly; Secure; SameSite=Strict; Max-Age=0' },
        });
      }
      return new Response('Not found', { status: 404 });
    },
  };
}
