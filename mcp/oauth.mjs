// OAuth 2.1 resource-server token validation for independent Protect Me MCP Workers.
// Supabase FCR is the identity issuer only. No database grants or service role are used.
export const FCR_ISSUER = 'https://oojzfmmywbvficgybaxd.supabase.co/auth/v1';
const JWKS_URL = FCR_ISSUER + '/.well-known/jwks.json';
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_JWT_LENGTH = 8192;
const MAX_JWKS_BYTES = 65536;

function decodeSegment(value) {
  if (!BASE64URL.test(value)) throw new Error('invalid token encoding');
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}
function decodeJson(value) {
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(decodeSegment(value)));
}
function record(value) { return Boolean(value) && typeof value === 'object' && !Array.isArray(value); }
function configuredClients(env) {
  const raw = String(env.MCP_OAUTH_CLIENT_IDS ?? '');
  const ids = raw.split(',').map(s => s.trim()).filter(Boolean);
  if (!ids.length || ids.length > 16 || ids.some(s => s.length > 256)) throw new Error('OAuth client allowlist missing');
  return new Set(ids);
}
export function oauthConfiguration(env) {
  if (env?.MCP_AUTH_MODE !== 'oauth') throw new Error('OAuth mode required');
  if (env?.MCP_OAUTH_ISSUER !== FCR_ISSUER) throw new Error('Unexpected issuer');
  const clients = configuredClients(env);
  const resource = new URL(env.MCP_RESOURCE_URL);
  if (resource.protocol !== 'https:' || resource.pathname !== '/mcp' || resource.search || resource.hash ||
      resource.username || resource.password || resource.hostname === 'localhost') {
    throw new Error('Invalid MCP resource');
  }
  return { resource, clients };
}
export function protectedResourceMetadata(env) {
  const { resource } = oauthConfiguration(env);
  return {
    resource: resource.href,
    authorization_servers: [FCR_ISSUER],
    bearer_methods_supported: ['header'],
  };
}
export function challengeHeader(env) {
  const { resource } = oauthConfiguration(env);
  return 'Bearer resource_metadata="' + resource.origin + '/.well-known/oauth-protected-resource/mcp"';
}
// Validation uses only pinned, HTTPS JWKS, not the untrusted token's jku/x5u URL.
export async function verifyFcrAccessToken(jwt, env, deps = {}) {
  const { clients } = oauthConfiguration(env);
  if (typeof jwt !== 'string' || jwt.length > MAX_JWT_LENGTH || jwt.length < 80) throw new Error('Invalid token');
  const parts = jwt.split('.');
  if (parts.length !== 3 || parts.some(p => !p)) throw new Error('Invalid token');
  const header = decodeJson(parts[0]);
  const claims = decodeJson(parts[1]);
  if (!record(header) || !record(claims) || !['RS256', 'ES256'].includes(header.alg) ||
      typeof header.kid !== 'string' || !header.kid || header.kid.length > 128) throw new Error('Unsupported signing key');
  const now = Math.floor((deps.now?.() ?? Date.now()) / 1000);
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (claims.iss !== FCR_ISSUER || !audiences.includes('authenticated') ||
      claims.role !== 'authenticated' || claims.is_anonymous === true ||
      typeof claims.client_id !== 'string' || !clients.has(claims.client_id) ||
      typeof claims.sub !== 'string' || !UUID.test(claims.sub) ||
      (claims.user_id != null && claims.user_id !== claims.sub) ||
      !Number.isInteger(claims.exp) || claims.exp <= now ||
      !Number.isInteger(claims.iat) || claims.iat > now + 30 ||
      (claims.nbf != null && (!Number.isInteger(claims.nbf) || claims.nbf > now + 30))) {
    throw new Error('Invalid token claims');
  }
  const fetcher = deps.fetcher ?? fetch;
  const res = await fetcher(JWKS_URL, { redirect: 'error', cache: 'no-store', headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error('Signing keys unavailable');
  const bytes = await res.text();
  if (bytes.length > MAX_JWKS_BYTES) throw new Error('Signing keys unavailable');
  const jwks = JSON.parse(bytes);
  if (!record(jwks) || !Array.isArray(jwks.keys) || jwks.keys.length > 32) throw new Error('Signing keys invalid');
  const candidates = jwks.keys.filter(k => record(k) && k.kid === header.kid &&
    k.alg === header.alg && (!k.use || k.use === 'sig') &&
    (k.key_ops == null || (Array.isArray(k.key_ops) && k.key_ops.includes('verify'))) &&
    (header.alg === 'RS256' ? k.kty === 'RSA' : (k.kty === 'EC' && k.crv === 'P-256')));
  if (candidates.length !== 1) throw new Error('Signing key not found');
  const crypt = deps.crypto ?? crypto;
  const algorithm = header.alg === 'RS256'
    ? { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
    : { name: 'ECDSA', namedCurve: 'P-256' };
  const key = await crypt.subtle.importKey('jwk', candidates[0], algorithm, false, ['verify']);
  const signatureAlgorithm = header.alg === 'RS256' ? 'RSASSA-PKCS1-v1_5' : { name:'ECDSA', hash:'SHA-256' };
  const data = new TextEncoder().encode(parts[0] + '.' + parts[1]);
  const verified = await crypt.subtle.verify(signatureAlgorithm, key, decodeSegment(parts[2]), data);
  if (!verified) throw new Error('Signature invalid');
  return { subject: claims.sub, clientId: claims.client_id };
}
