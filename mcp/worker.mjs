// Deploy separately using wrangler.mcp.jsonc. Does not modify the existing site.
// Disabled until MCP_ENABLED=true and MCP_BEARER_TOKEN is configured.
import { handleMcpEnvelope } from './protocol.mjs';
import { mcpApplication } from './tools.mjs';

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
    if (url.pathname !== '/mcp' || url.search) return new Response(null, { status: 404 });
    // Do not consume the request body before authentication and origin checks.
    const common = {
      path: url.pathname,
      method: request.method,
      origin: request.headers.get('origin'),
      authorization: request.headers.get('authorization'),
      contentType: request.headers.get('content-type'),
      accept: request.headers.get('accept'),
    };
    const preflight = handleMcpEnvelope({ ...common, body: '' }, env, mcpApplication);
    if (preflight.status === 404 || preflight.status === 401 ||
        preflight.status === 403 || preflight.status === 405 || preflight.status === 503 ||
        preflight.status === 415 || preflight.status === 400) {
      return new Response(preflight.body || null, { status: preflight.status, headers: preflight.headers });
    }
    const body = await readBounded(request);
    if (body === null) return new Response(null, { status: 413, headers: { 'Cache-Control': 'no-store' } });
    const response = handleMcpEnvelope({ ...common, body }, env, mcpApplication);
    return new Response(response.body || null, { status: response.status, headers: response.headers });
  },
};
