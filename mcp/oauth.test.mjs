import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { FCR_ISSUER, verifyFcrAccessToken, oauthConfiguration, protectedResourceMetadata } from './oauth.mjs';
import worker from './worker.mjs';

const env = {
  MCP_ENABLED:'true', MCP_AUTH_MODE:'oauth', MCP_OAUTH_ISSUER:FCR_ISSUER,
  MCP_OAUTH_CLIENT_IDS:'mcp-client-one', MCP_RESOURCE_URL:'https://mcp.example.test/mcp',
  MCP_ALLOWED_ORIGINS:'https://client.example.test',
};
const subject='00000000-0000-4000-8000-000000000001';
const encoder = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const now = Math.floor(Date.now()/1000);
let publicKey;
let privateKey;
let jwks;
function token(claims={}, header={}) {
  const head=encoder({alg:'RS256',kid:'test-key',typ:'JWT',...header});
  const body=encoder({iss:FCR_ISSUER,aud:'authenticated',role:'authenticated',client_id:'mcp-client-one',
    sub:subject,iat:now-30,exp:now+600,...claims});
  return webcrypto.subtle.sign('RSASSA-PKCS1-v1_5',privateKey,Buffer.from(head+'.'+body))
    .then(sig=>head+'.'+body+'.'+Buffer.from(sig).toString('base64url'));
}
function fetcher(url) {
  assert.equal(url,FCR_ISSUER+'/.well-known/jwks.json');
  return Promise.resolve({ok:true,text:async()=>JSON.stringify(jwks)});
}
function mcpPacket() { return JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list',params:{}}); }
function mcpRequest(tkn,origin) {
  return new Request(env.MCP_RESOURCE_URL,{method:'POST',headers:{
    'Authorization': 'Bearer '+tkn, 'Accept':'application/json, text/event-stream',
    'Content-Type':'application/json',...(origin?{Origin:origin}:{})
  },body:mcpPacket()});
}
test('FCR OAuth credentials are cryptographically verified and separated per product',async(t)=>{
  const pair=await webcrypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,
    publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
  privateKey=pair.privateKey;publicKey=pair.publicKey;
  jwks={keys:[{...(await webcrypto.subtle.exportKey('jwk',publicKey)),kid:'test-key',alg:'RS256',use:'sig'}]};
  const good=await token();
  const valid=await verifyFcrAccessToken(good,env,{fetcher,crypto:webcrypto});
  assert.deepEqual(valid,{subject,clientId:'mcp-client-one'});
  const failures=[
    {name:'wrong issuer',jwt:await token({iss:'https://untrusted.example/auth/v1'})},
    {name:'wrong client',jwt:await token({client_id:'other-client'})},
    {name:'expired',jwt:await token({exp:now-3})},
    {name:'premature',jwt:await token({nbf:now+600})},
    {name:'wrong audience',jwt:await token({aud:'other'})},
    {name:'anonymous',jwt:await token({is_anonymous:true})},
    {name:'wrong subject',jwt:await token({sub:'user-1'})},
    {name:'wrong role',jwt:await token({role:'service_role'})},
    {name:'wrong algorithm',jwt:await token({}, {alg:'HS256'})},
    {name:'tampered',jwt:good.slice(0,-2)+'AA'},
  ];
  for(const item of failures) await t.test(item.name,async()=> {
    await assert.rejects(verifyFcrAccessToken(item.jwt,env,{fetcher,crypto:webcrypto}));
  });
  await t.test('wrong signing key and untrusted JWKS fail closed',async()=>{
    await assert.rejects(verifyFcrAccessToken(good,env,{fetcher:async()=>({ok:true,text:async()=>JSON.stringify({keys:[]})}),crypto:webcrypto}));
  });
  await t.test('missing per-product client allowlist or resource fails closed',()=>{
    assert.throws(()=>oauthConfiguration({...env,MCP_OAUTH_CLIENT_IDS:''}));
    assert.throws(()=>oauthConfiguration({...env,MCP_RESOURCE_URL:'http://mcp.example.test/mcp'}));
    assert.throws(()=>oauthConfiguration({...env,MCP_OAUTH_ISSUER:'https://other.example'}));
  });
  await t.test('metadata identifies FCR only as authorization server',()=>{
    const metadata=protectedResourceMetadata(env);
    assert.deepEqual(metadata.authorization_servers,[FCR_ISSUER]);
    assert.equal(metadata.resource,env.MCP_RESOURCE_URL);
    assert.equal(JSON.stringify(metadata).includes('mcp-client-one'),false);
  });
  await t.test('Worker challenges without echoing tokens, then serves verified read-only tools',async()=>{
    const oldFetch=globalThis.fetch;
    globalThis.fetch=fetcher;
    try {
      const noAuth=await worker.fetch(new Request(env.MCP_RESOURCE_URL,{
        method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json, text/event-stream'},
        body:mcpPacket(),
      }),env);
      assert.equal(noAuth.status,401);
      assert.match(noAuth.headers.get('www-authenticate'),/oauth-protected-resource\/mcp/);
      const accepted=await worker.fetch(mcpRequest(good),env);
      assert.equal(accepted.status,200);
      const content=await accepted.json();
      assert.equal(content.result.tools.length,3);
      assert.equal(JSON.stringify(content).includes(good),false);
      const rejected=await worker.fetch(mcpRequest(await token({client_id:'other-client'})),env);
      assert.equal(rejected.status,401);
      const originRejected=await worker.fetch(mcpRequest(good,'https://untrusted.example'),env);
      assert.equal(originRejected.status,403);
      const metadata=await worker.fetch(new Request('https://mcp.example.test/.well-known/oauth-protected-resource/mcp'),env);
      assert.equal(metadata.status,200);
      assert.equal((await metadata.json()).resource,env.MCP_RESOURCE_URL);
    } finally {globalThis.fetch=oldFetch;}
  });
  await t.test('disabled OAuth worker does not disclose metadata',async()=>{
    const r=await worker.fetch(new Request('https://mcp.example.test/.well-known/oauth-protected-resource/mcp'),{...env,MCP_ENABLED:'false'});
    assert.equal(r.status,404);
  });
});
