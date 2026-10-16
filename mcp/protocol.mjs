// Stateless, read-only MCP Streamable HTTP core.
// No chat history, credentials, or submitted payloads are persisted or logged.
export const MCP_VERSION = '2025-06-18';
const MAX_BODY = 8_192;
const JSON_HEADERS = Object.freeze({
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
});
function result(status, body = '', extra = {}) {
  return { status, headers: { ...JSON_HEADERS, ...extra }, body };
}
function reply(id, payload) {
  return result(200, JSON.stringify({ jsonrpc: '2.0', id, ...payload }));
}
function error(id, code, message) {
  return reply(id, { error: { code, message } });
}
function equalConstantTime(left, right) {
  const a = String(left), b = String(right);
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}
function hasOriginPermission(origin, allowed) {
  if (!origin) return true;
  if (typeof allowed !== 'string' || !allowed.trim()) return false;
  return allowed.split(',').some((x) => x.trim() === origin && /^https:\/\//.test(origin));
}
function emptyObject(value) {
  return value === undefined || (value !== null && typeof value === 'object' &&
    !Array.isArray(value) && Object.keys(value).length === 0);
}
function toolError(id, reason = 'Invalid or unsupported tool arguments') {
  return reply(id, { result: { content: [{ type: 'text', text: reason }], isError: true } });
}
export function handleMcpEnvelope(input, env, app) {
  // Explicit opt-in and long server-side bearer secret are both mandatory.
  if (env?.MCP_ENABLED !== 'true') return result(404);
  if (typeof env?.MCP_BEARER_TOKEN !== 'string' || env.MCP_BEARER_TOKEN.length < 32) return result(503);
  if (input.path !== '/mcp') return result(404);
  if (!hasOriginPermission(input.origin, env.MCP_ALLOWED_ORIGINS)) return result(403);
  if (input.method !== 'POST') return result(405, '', { Allow: 'POST' });
  const match = /^Bearer ([^\s]{1,8192})$/.exec(input.authorization ?? '');
  if (!match || !equalConstantTime(match[1], env.MCP_BEARER_TOKEN)) {
    return result(401, '', { 'WWW-Authenticate': 'Bearer' });
  }
  if (!/^application\/json(?:\s*;|$)/i.test(input.contentType ?? '')) return result(415);
  const accept = input.accept ?? '';
  if (!accept.includes('application/json') || !accept.includes('text/event-stream')) return result(400);
  if (typeof input.body !== 'string' || input.body.length > MAX_BODY) return result(413);
  let packet;
  try { packet = JSON.parse(input.body); } catch { return error(null, -32700, 'Parse error'); }
  if (!packet || Array.isArray(packet) || typeof packet !== 'object' ||
      packet.jsonrpc !== '2.0' || typeof packet.method !== 'string') {
    return error(null, -32600, 'Invalid Request');
  }
  if (!Object.hasOwn(packet, 'id')) {
    return packet.method === 'notifications/initialized' ? result(202) : result(400);
  }
  if (typeof packet.id !== 'number' && typeof packet.id !== 'string') {
    return error(null, -32600, 'Invalid Request');
  }
  const id = packet.id;
  switch (packet.method) {
    case 'ping': return reply(id, { result: {} });
    case 'initialize': {
      const version = packet.params?.protocolVersion;
      if (typeof version !== 'string') return error(id, -32602, 'Invalid initialize parameters');
      return reply(id, { result: {
        protocolVersion: MCP_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: app.name, version: '0.1.0' },
        instructions: 'Read-only on demand. Do not send credentials, raw conversations, or identifying personal data. Tool outputs are not authorization or independent runtime proof.',
      } });
    }
    case 'tools/list':
      if (!emptyObject(packet.params)) return error(id, -32602, 'Invalid list parameters');
      return reply(id, { result: { tools: app.tools } });
    case 'tools/call': {
      const params = packet.params;
      if (!params || typeof params !== 'object' || Array.isArray(params) ||
          typeof params.name !== 'string' || !Object.hasOwn(app.handlers, params.name)) {
        return error(id, -32602, 'Unknown or invalid tool');
      }
      try {
        const response = app.handlers[params.name](params.arguments ?? {});
        return reply(id, { result: {
          content: [{ type: 'text', text: JSON.stringify(response) }],
          structuredContent: response,
          isError: false,
        } });
      } catch {
        // No reflection of input values or exception messages.
        return toolError(id);
      }
    }
    default: return error(id, -32601, 'Method not found');
  }
}
