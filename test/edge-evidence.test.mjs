import test from 'node:test';
import assert from 'node:assert/strict';
import { acceptProtectTwoEvidence } from '../src/edge-evidence.mjs';
import { createDeviceObservation } from '../src/device-evidence.mjs';

const source = {
  schema: 'protect-me/shield-inspection@v1',
  action: 'pass',
  verdict: 'VERIFIED_BOT',
  receiptKind: 'hmac-sha256',
  receipt: 'a'.repeat(64),
};
const verified = { consent: true, verifyReceipt: async () => true };

test('verified and consented edge evidence remains site-scoped and non-authorizing', async () => {
  const result = await acceptProtectTwoEvidence(source, verified);
  assert.equal(result.schema, 'protect-me/edge-evidence@v1');
  assert.equal(result.scope, 'site_traffic');
  assert.equal(result.authority.canAuthorize, false);
  assert.equal(result.evidenceRef, 'shield:hmac-sha256:' + source.receipt);
  assert.equal('deviceRef' in result, false);
  assert.equal('userAgent' in result, false);
});

test('missing consent, verifier or failed cryptographic verification is rejected', async () => {
  await assert.rejects(() => acceptProtectTwoEvidence(source, { verifyReceipt: async () => true }), /consent/);
  await assert.rejects(() => acceptProtectTwoEvidence(source, { consent: true }), /cryptographically verified/);
  await assert.rejects(() => acceptProtectTwoEvidence(source, { consent: true, verifyReceipt: async () => false }), /cryptographically verified/);
});

test('extra personal fields, unsigned receipts and conflicting verdicts are rejected', async () => {
  for (const candidate of [
    { ...source, ip: '203.0.113.1' },
    { ...source, deviceRef: 'some-device' },
    { ...source, receiptKind: 'none' },
    { ...source, receipt: 'not-a-signature' },
    { ...source, action: 'deny', verdict: 'VERIFIED_BOT' },
    { ...source, action: 'pass', verdict: 'PROBE' },
  ]) {
    await assert.rejects(() => acceptProtectTwoEvidence(candidate, verified), /invalid or excessive/);
  }
});

test('edge evidence cannot be fed directly into device observations', async () => {
  const edge = await acceptProtectTwoEvidence(source, verified);
  assert.throws(() => createDeviceObservation(edge), /unsupported fields/);
});
