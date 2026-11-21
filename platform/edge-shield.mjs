// Minimal Worker edge guard for Model One's own sensitive routes. It deliberately
// does not claim to protect devices or other Juss systems.
const PROBES = Object.freeze([
  '/.env', '/.git', '/.aws', '/.ssh', '/wp-admin', '/wp-login.php',
  '/xmlrpc.php', '/phpmyadmin', '/server-status', '/etc/passwd', '/actuator',
]);

const SENSITIVE_PATHS = Object.freeze([
  '/api', '/api/*', '/founder', '/founder/*', '/buy', '/checkout', '/checkout/*',
  '/account', '/account/*', '/webhooks/stripe',
]);

function canonicalPath(pathname) {
  let path = String(pathname ?? '/');
  for (let i = 0; i < 3; i += 1) {
    try {
      const decoded = decodeURIComponent(path);
      if (decoded === path) break;
      path = decoded;
    } catch { break; }
  }
  path = path.replace(/\\/g, '/').replace(/\/{2,}/g, '/').toLowerCase();
  return path.startsWith('/') ? path : `/${path}`;
}

function matches(pathname, patterns) {
  const path = canonicalPath(pathname);
  return patterns.some((pattern) => {
    const value = pattern.toLowerCase();
    return value.endsWith('/*') ? path.startsWith(value.slice(0, -1)) : path === value || path === `${value}/`;
  });
}

function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...headers,
  } });
}

export function createEdgeShield(upstream, { limiterBinding = 'SHIELD_RATE_LIMITER', retryAfterSeconds = 60 } = {}) {
  return {
    ...upstream,
    async fetch(request, env, ctx) {
      const { pathname } = new URL(request.url);
      const path = canonicalPath(pathname);
      if (request.method === 'TRACE' || request.method === 'CONNECT' || PROBES.some((probe) => path === probe || path.startsWith(`${probe}/`))) {
        return json(404, { error: 'not_found' });
      }
      if (matches(path, SENSITIVE_PATHS)) {
        const limiter = env?.[limiterBinding];
        if (!limiter || typeof limiter.limit !== 'function') return json(503, { ok: false, error: 'rate_limit_unavailable' });
        let outcome;
        try {
          const ip = request.headers.get('cf-connecting-ip');
          outcome = await limiter.limit({ key: ip ? `ip:${ip}` : 'ip:unknown' });
        } catch { return json(503, { ok: false, error: 'rate_limit_unavailable' }); }
        if (!outcome || typeof outcome.success !== 'boolean') return json(503, { ok: false, error: 'rate_limit_unavailable' });
        if (!outcome.success) return json(429, { ok: false, error: 'rate_limit_exceeded' }, { 'retry-after': String(retryAfterSeconds) });
      }
      return upstream.fetch.call(upstream, request, env, ctx);
    },
  };
}
