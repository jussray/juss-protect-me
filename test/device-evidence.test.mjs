import assert from 'node:assert/strict';
import test from 'node:test';

import {
  assessDeviceRisk,
  createDeviceObservation,
  derivePseudonymousDeviceRef,
} from '../src/device-evidence.mjs';

const secret = 'server-held-test-secret';
const deviceRef = derivePseudonymousDeviceRef({
  provider: 'fingerprint',
  externalId: 'visitor-raw-id-never-persisted',
  secret,
});

function observation(provider, signals = {}, evidenceRef = `${provider}://event/1`) {
  return createDeviceObservation({
    provider,
    observedAt: '2026-10-06T04:10:00.000Z',
    evidenceRef,
    deviceRef,
    signals,
  });
}

test('device references are deterministic, provider-scoped, and do not expose raw identifiers', () => {
  const same = derivePseudonymousDeviceRef({ provider: 'fingerprint', externalId: 'visitor-raw-id-never-persisted', secret });
  const otherProvider = derivePseudonymousDeviceRef({ provider: 'cloudflare', externalId: 'visitor-raw-id-never-persisted', secret });
  assert.equal(same, deviceRef);
  assert.notEqual(otherProvider, deviceRef);
  assert.equal(deviceRef.includes('visitor-raw-id-never-persisted'), false);
});

test('observation rejects raw provider payload fields instead of silently persisting them', () => {
  assert.throws(() => createDeviceObservation({
    provider: 'fingerprint',
    observedAt: '2026-10-06T04:10:00.000Z',
    evidenceRef: 'fingerprint://event/2',
    deviceRef,
    visitorId: 'raw-id',
    signals: {},
  }), /unsupported fields: visitorId/);
});

test('high-risk evidence recommends containment without granting authority', () => {
  const result = assessDeviceRisk([
    observation('fingerprint', { tampering: true, confidence: 0.98 }),
    observation('cloudflare', { automation: 'bad', confidence: 0.93 }, 'cloudflare://security-event/7'),
  ]);
  assert.equal(result.risk, 'high');
  assert.equal(result.recommendation, 'contain_or_step_up');
  assert.equal(result.authority.canAuthorize, false);
  assert.deepEqual(result.providers, ['cloudflare', 'fingerprint']);
});

test('vpn or incognito alone causes step-up, not an automatic block', () => {
  const result = assessDeviceRisk([
    observation('cloudflare', { vpn: true, confidence: 0.8 }),
    observation('app', { incognito: true, sessionAuthenticated: true, confidence: 0.7 }, 'app://session/derived/4'),
  ]);
  assert.equal(result.risk, 'medium');
  assert.equal(result.recommendation, 'step_up');
  assert.equal(result.reasons.includes('vpn_observed'), true);
  assert.equal(result.reasons.includes('incognito_observed'), true);
});

test('clean known signals remain low risk and evidence-only', () => {
  const result = assessDeviceRisk([
    observation('supabase', { sessionAuthenticated: true, automation: 'not_detected', velocity: 'normal', confidence: 0.91 }, 'supabase://session/derived/9'),
  ]);
  assert.equal(result.risk, 'low');
  assert.equal(result.recommendation, 'continue');
  assert.equal(result.authority.canAuthorize, false);
});

test('different pseudonymous device scopes cannot be merged into one assessment', () => {
  const otherRef = derivePseudonymousDeviceRef({ provider: 'fingerprint', externalId: 'other-device', secret });
  const other = createDeviceObservation({
    provider: 'fingerprint',
    observedAt: '2026-10-06T04:10:00.000Z',
    evidenceRef: 'fingerprint://event/3',
    deviceRef: otherRef,
    signals: { tampering: true },
  });
  assert.throws(() => assessDeviceRisk([observation('fingerprint'), other]), /different device scopes/);
});
