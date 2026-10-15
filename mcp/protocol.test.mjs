import assert from 'node:assert/strict';
import test from 'node:test';
import { handleMcpEnvelope } from './protocol.mjs';
import { mcpApplication as app } from './tools.mjs';

const env = { MCP_ENABLED:'true', MCP_BEARER_TOKEN:'TEST-ONLY-MCP-TOKEN-32-CHARACTERS-LONG-EXAMPLE', MCP_ALLOWED_ORIGINS:'https://trusted.example' };
const headers = {
  method:'POST',path:'/mcp',origin:null,
  authorization:'Bearer '+env.MCP_BEARER_TOKEN,contentType:'application/json',
  accept:'application/json, text/event-stream',
};
const request = (method, params, patch={}) => handleMcpEnvelope({
  ...headers,body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}), ...patch },env,app);
const packet = r => JSON.parse(r.body);
test('disabled, unconfigured, and wrong secret fail closed',()=>{
  assert.equal(handleMcpEnvelope({...headers,body:'{}'},{...env,MCP_ENABLED:'false'},app).status,404);
  assert.equal(handleMcpEnvelope({...headers,body:'{}'},{...env,MCP_BEARER_TOKEN:''},app).status,503);
  assert.equal(request('initialize',{protocolVersion:'2025-06-18'},{authorization:'Bearer invalid'}).status,401);
});
test('origin, method, and mime headers are enforced',()=>{
  assert.equal(request('ping',{}, {origin:'https://attacker.example'}).status,403);
  assert.equal(request('ping',{}, {origin:'https://trusted.example'}).status,200);
  assert.equal(request('ping',{}, {method:'GET'}).status,405);
  assert.equal(request('ping',{}, {accept:'application/json'}).status,400);
  assert.equal(request('ping',{}, {contentType:'text/plain'}).status,415);
});
test('JSON-RPC initialize and discovery expose read-only tools',()=>{
  const i=packet(request('initialize',{protocolVersion:'2025-06-18'}));
  assert.equal(i.result.protocolVersion,'2025-06-18');
  assert.equal(i.result.serverInfo.name,app.name);
  const listing=packet(request('tools/list',{})).result.tools;
  assert.equal(listing.length,3);
  assert.ok(listing.every(t=>t.annotations.readOnlyHint===true));
});
test('notification is acknowledged and request errors do not echo payloads',()=>{
  const notification=handleMcpEnvelope({...headers,body:JSON.stringify({jsonrpc:'2.0',method:'notifications/initialized'})},env,app);
  assert.equal(notification.status,202);
  assert.equal(request('tools/call',{name:'fake',arguments:{secret:'CONFIDENTIAL'}}).status,200);
  assert.equal(request('tools/call',{name:'fake',arguments:{secret:'CONFIDENTIAL'}}).body.includes('CONFIDENTIAL'),false);
  assert.equal(request('tools/call',{name:app.tools[0].name,arguments:{unexpected:'CONFIDENTIAL'}}).body.includes('CONFIDENTIAL'),false);
});
test('tool can be called without external IO or human-private content',()=>{
  const out=packet(request('tools/call',{name:app.tools[0].name,arguments:{}})).result;
  assert.equal(out.isError,false);
  assert.equal(out.structuredContent.chatHistoryAccess,false);
});
test('payload limits and bad JSON fail safely',()=>{
  assert.equal(handleMcpEnvelope({...headers,body:' '.repeat(8193)},env,app).status,413);
  assert.equal(handleMcpEnvelope({...headers,body:'not-json'},env,app).status,200);
  assert.equal(packet(handleMcpEnvelope({...headers,body:'not-json'},env,app)).error.code,-32700);
});
