import test from 'node:test';
import assert from 'node:assert/strict';
import worker from './worker.mjs';

const TOKEN = 'synthetic-test-token-over-thirty-two-characters';
const env = Object.freeze({
  MCP_ENABLED: 'true',
  MCP_BEARER_TOKEN: TOKEN,
  MCP_ALLOWED_ORIGINS: 'https://app.example.test',
});
const headers = Object.freeze({
  'Authorization': 'Bearer ' + TOKEN,
  'Content-Type': 'application/json',
  'Accept': 'application/json, text/event-stream',
});
const packet = (method, params) => JSON.stringify({ jsonrpc:'2.0', id:1, method, params });
function request(body, customHeaders = headers, url = 'https://mcp.example.test/mcp', method = 'POST') {
  return new Request(url, {method, headers: customHeaders, ...(body !== undefined ? {body} : {})});
}
async function call(body, customHeaders, customEnv=env) {
  return worker.fetch(request(body,customHeaders), customEnv);
}

test('worker is disabled by default and does not expose tool metadata', async()=>{
  const r=await call(packet('tools/list',{}),headers,{...env,MCP_ENABLED:'false'});
  assert.equal(r.status,404);
  assert.equal(await r.text(),'');
});

test('worker fails closed for missing token and unexpected origin', async()=>{
  const unauthorized=await call(packet('tools/list',{}),{...headers,Authorization:'Bearer invalid'});
  assert.equal(unauthorized.status,401);
  const originDenied=await call(packet('ping',{}),{...headers,Origin:'https://malicious.example'});
  assert.equal(originDenied.status,403);
  const unconfigured=await call(packet('ping',{}),headers,{...env,MCP_BEARER_TOKEN:''});
  assert.equal(unconfigured.status,503);
});

test('worker serves MCP discovery only after authentication', async()=>{
  const response=await call(packet('tools/list',{}));
  assert.equal(response.status,200);
  assert.equal(response.headers.get('cache-control'),'no-store');
  const output=await response.json();
  assert.equal(output.result.tools.length,3);
  for (const t of output.result.tools) {
    assert.equal(t.annotations.readOnlyHint,true);
    assert.equal(t.annotations.destructiveHint,false);
  }
});

test('worker invokes status tool without chat history access', async()=>{
  const list=await (await call(packet('tools/list',{}))).json();
  const name=list.result.tools[0].name;
  const response=await call(packet('tools/call',{name, arguments:{}}));
  assert.equal(response.status,200);
  const output=await response.json();
  assert.equal(output.result.isError,false);
  assert.equal(output.result.structuredContent.chatHistoryAccess,false);
});

test('worker rejects oversized bodies without leaking content', async()=>{
  const response=await call('x'.repeat(8193));
  assert.equal(response.status,413);
  assert.equal((await response.text()).includes('x'.repeat(32)),false);
});

test('worker does not reflect rejected confidential values', async()=>{
  const list=await (await call(packet('tools/list',{}))).json();
  const name=list.result.tools.find(t=>t.name.endsWith('evidence_keys')).name;
  const response=await call(packet('tools/call',{
    name,arguments:{keys:['status'],transcript:'SYNTHETIC-PRIVATE-NEVER-REFLECT'},
  }));
  assert.equal(response.status,200);
  const output=await response.text();
  assert.equal(output.includes('SYNTHETIC-PRIVATE-NEVER-REFLECT'),false);
  assert.equal(JSON.parse(output).result.isError,true);
});
