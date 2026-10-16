// Separate opt-in, read-only MCP Worker. Never change the existing production site.
// OAuth mode requires signed FCR user tokens and an exact per-product client allowlist.
import { handleMcpEnvelope } from './protocol.mjs';
import { mcpApplication } from './tools.mjs';
import { oauthConfiguration, protectedResourceMetadata, challengeHeader, verifyFcrAccessToken } from './oauth.mjs';

const MAX_BODY_BYTES = 8_192;
async function readBounded(request) {
  if (Number(request.headers.get('content-length') || 0) > MAX_BODY_BYTES) return null;
  const reader = request.body?.getReader();
  if (!reader) return '';
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let result = '', seen = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      seen += value.byteLength;
      if (seen > MAX_BODY_BYTES) { await reader.cancel(); return null; }
      result += decoder.decode(value, { stream: true });
    }
    return result + decoder.decode();
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (env?.MCP_ENABLED !== 'true') return new Response(null, {status:404});
    if (!['static','oauth'].includes(env.MCP_AUTH_MODE)) return new Response(null, {status:503});
    let runtimeEnv = env;
    if (env.MCP_AUTH_MODE === 'oauth') {
      let configured;
      try { configured = oauthConfiguration(env); } catch { return new Response(null, {status:503}); }
      if (url.origin !== configured.resource.origin || url.search) return new Response(null,{status:404});
      const metadataPath = '/.well-known/oauth-protected-resource/mcp';
      if (url.pathname === metadataPath && request.method === 'GET') {
        return Response.json(protectedResourceMetadata(env), {headers:{
          'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
        }});
      }
      if (url.pathname !== '/mcp') return new Response(null,{status:404});
      if (request.method !== 'POST') return new Response(null,{status:405,headers:{Allow:'POST'}});
      const origin = request.headers.get('origin');
      const allowed = (env.MCP_ALLOWED_ORIGINS ?? '').split(',').map(x=>x.trim()).filter(Boolean);
      if (origin && (!origin.startsWith('https://') || !allowed.includes(origin))) {
        return new Response(null,{status:403});
      }
      const bearer = /^Bearer ([^\s]{80,8192})$/.exec(request.headers.get('authorization') ?? '');
      const challenged = () => new Response(null,{status:401,headers:{
        'WWW-Authenticate':challengeHeader(env),'Cache-Control':'no-store',
      }});
      if (!bearer) return challenged();
      try { await verifyFcrAccessToken(bearer[1],env); } catch { return challenged(); }
      // Only after independently verifying the OAuth JWT may the existing
      // JSON-RPC guard compare the exact token. Never persist it.
      runtimeEnv = {...env,MCP_BEARER_TOKEN:bearer[1]};
    } else if (url.pathname !== '/mcp' || url.search) {
      return new Response(null,{status:404});
    }
    // Do not consume the request body before authentication and origin checks.
    const common = {
      path: url.pathname,
      method: request.method,
      origin: request.headers.get('origin'),
      authorization: request.headers.get('authorization'),
      contentType: request.headers.get('content-type'),
      accept: request.headers.get('accept'),
    };
    const preflight = handleMcpEnvelope({ ...common, body: '' }, runtimeEnv, mcpApplication);
    if (preflight.status === 404 || preflight.status === 401 ||
        preflight.status === 403 || preflight.status === 405 || preflight.status === 503 ||
        preflight.status === 415 || preflight.status === 400) {
      return new Response(preflight.body || null, { status: preflight.status, headers: preflight.headers });
    }
    const body = await readBounded(request);
    if (body === null) return new Response(null, { status: 413, headers: { 'Cache-Control': 'no-store' } });
    const response = handleMcpEnvelope({ ...common, body }, runtimeEnv, mcpApplication);
    return new Response(response.body || null, { status: response.status, headers: response.headers });
  },
};
