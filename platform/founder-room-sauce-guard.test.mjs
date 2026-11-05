import test from 'node:test';
import assert from 'node:assert/strict';
import { createModelOneRoom } from './model-one-room.mjs';

const app = createModelOneRoom();
const origin = 'https://protect.example.test';
const env = {
  FOUNDER_EMAIL: 'founder@example.test',
  FOUNDER_PASSWORD: 'test-only-password',
  FOUNDER_SALT: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  SESSION_SECRET: 'test-only-cookie-key-not-for-deploy',
  FOUNDER_ITERS: '1000',
};
const req = (path, init) => new Request(origin + path, init);
async function founderCookie() {
  const response = await app.fetch(req('/founder/login', {
    method: 'POST',
    body: new URLSearchParams({ email: env.FOUNDER_EMAIL, password: env.FOUNDER_PASSWORD }),
  }), env);
  assert.equal(response.status, 302);
  return response.headers.get('set-cookie').split(';')[0];
}
test('anonymous visitors cannot inspect Sauce Guard', async () => {
  const get = await app.fetch(req('/founder/sauce-guard'), env);
  assert.equal(get.status, 302);
  assert.equal(get.headers.get('location'), '/founder');
  const post = await app.fetch(req('/founder/sauce-guard/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Origin': origin },
    body: new URLSearchParams({ content: 'test' }),
  }), env);
  assert.equal(post.status, 401);
});
test('authenticated founder sees correct branded private route and no fake telemetry', async () => {
  const cookie = await founderCookie();
  const response = await app.fetch(req('/founder/sauce-guard', { headers: { Cookie: cookie } }), env);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const html = await response.text();
  assert.match(html, /JUSS &amp; CO./);
  assert.match(html, /Live telemetry/);
  assert.match(html, /Unknown/);
  assert.match(html, /PERSONAL SECURITY/);
  assert.match(html, /#c9973f/);
  assert.match(html, /form class="sg-check"/);
});
test('review action requires same-origin request, checks without echoing secrets or publishing', async () => {
  const cookie = await founderCookie();
  const send = (content, claimedState = 'CURRENT', originHeader = origin) => app.fetch(req('/founder/sauce-guard/check', {
    method: 'POST',
    headers: {
      Cookie: cookie, Origin: originHeader,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      content, state: claimedState, evidence_ref: 'proof://approved/public/123',
    }),
  }), env);
  const good = await send('We improved user-facing safety.');
  assert.equal(good.status, 200);
  assert.match(await good.text(), /Review result · REVIEW/);
  const secret = 'ghp_' + 'Z'.repeat(30);
  const blocked = await send('Public: ' + secret);
  assert.equal(blocked.status, 200);
  const html = await blocked.text();
  assert.match(html, /Review result · BLOCK/);
  assert.match(html, /credential/);
  assert.ok(!html.includes(secret));
  assert.equal((await send('synthetic text', 'CURRENT', 'https://untrusted.example')).status, 403);
  assert.equal((await send('synthetic text', 'UNKNOWN')).status, 200);
});
test('founder room exposes the private security console entry point', async () => {
  const cookie = await founderCookie();
  const res = await app.fetch(req('/founder/room', { headers: { Cookie: cookie } }), env);
  assert.equal(res.status, 200);
  assert.ok((await res.text()).includes('href="/founder/sauce-guard"'));
});
