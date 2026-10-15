import assert from 'node:assert/strict';
import test from 'node:test';

import {
  authorizeRecommendedAction,
  createEvidenceReceipt,
  evaluateReceiptStaleness,
  evaluateThreat,
  verifyEvidenceReceipt,
} from '../src/model-one.mjs';

const identity = Object.freeze({
  modelVersion: 'model-one@0.1.0',
  policyVersion: 'personal-policy@1',
  deviceScope: 'device:pseudonymous-demo',
  sourceSha: 'a'.repeat(40),
  sensorVersions: { browser: '1', endpoint: '1', identity: '1' },
});

const event = Object.freeze({
  kind: 'phishing',
  severity: 'high',
  confidence: 0.97,
  summary: 'Navigation target matched independently reviewable phishing evidence.',
});

const secret = 'test-only-secret-never-production';

test('signed receipt verifies and cannot self-authorize', () => {
  const receipt = createEvidenceReceipt({
    id: 'PM1-001',
    event,
    identity,
    evidenceRefs: ['sensor://browser/verdict/123'],
    observedAt: '2026-10-05T18:00:00.000Z',
    secret,
  });
  assert.equal(receipt.state, 'verified');
  assert.equal(receipt.authority.canAuthorize, false);
  assert.equal(verifyEvidenceReceipt(receipt, secret), true);
});

test('tampering invalidates a signed receipt', () => {
  const receipt = createEvidenceReceipt({
    id: 'PM1-002',
    event,
    identity,
    evidenceRefs: ['sensor://browser/verdict/124'],
    observedAt: '2026-10-05T18:00:00.000Z',
    secret,
  });
  assert.equal(verifyEvidenceReceipt({ ...receipt, state: 'unknown' }, secret), false);
});

test('unsigned receipt never upgrades itself to verified', () => {
  const receipt = createEvidenceReceipt({
    id: 'PM1-003',
    event,
    identity,
    evidenceRefs: ['sensor://browser/verdict/125'],
    observedAt: '2026-10-05T18:00:00.000Z',
  });
  assert.equal(receipt.state, 'inferred');
  assert.equal(receipt.receiptKind, 'sha256-unauthenticated');
});

test('identity change makes prior proof stale', () => {
  const receipt = createEvidenceReceipt({
    id: 'PM1-004',
    event,
    identity,
    evidenceRefs: ['sensor://browser/verdict/126'],
    observedAt: '2026-10-05T18:00:00.000Z',
    secret,
  });
  const result = evaluateReceiptStaleness(receipt, {
    ...identity,
    sourceSha: 'b'.repeat(40),
    sensorVersions: { ...identity.sensorVersions, browser: '2' },
  });
  assert.equal(result.state, 'stale');
  assert.deepEqual(result.invalidatedBy, ['sourceSha_changed', 'sensor_versions_changed']);
});

test('high confidence phishing recommends blocking but separate policy decides automation', () => {
  const recommendation = evaluateThreat(event);
  assert.equal(recommendation.action, 'block_navigation');
  assert.equal(authorizeRecommendedAction(recommendation, { autoActions: [] }).authorized, false);
  assert.equal(authorizeRecommendedAction(recommendation, {
    autoActions: ['block_navigation'],
    minConfidence: 0.95,
  }).authorized, true);
});

test('uncertain attribution falls back to manual review', () => {
  const recommendation = evaluateThreat({
    kind: 'scam',
    severity: 'critical',
    confidence: 0.51,
    summary: 'Suspicious but not sufficiently attributed.',
  });
  assert.equal(recommendation.action, 'manual_review');
});

test('raw sensitive values are rejected from evidence', () => {
  assert.throws(() => createEvidenceReceipt({
    id: 'PM1-005',
    event: { ...event, password: 'must-not-enter-ledger' },
    identity,
    evidenceRefs: ['sensor://browser/verdict/127'],
    observedAt: '2026-10-05T18:00:00.000Z',
    secret,
  }), /raw sensitive field is forbidden/);
});

test('unsupported destructive actions cannot be authorized', () => {
  const result = authorizeRecommendedAction({ action: 'wipe_device', confidence: 1 }, {
    autoActions: ['wipe_device'],
    minConfidence: 0,
  });
  assert.equal(result.authorized, false);
});


test('privacy guard blocks raw conversation, identity, and credentials in security receipts', () => {
  const base = {
    id: 'PM1-PRIVACY-001', event, identity,
    evidenceRefs: ['sensor://browser/verdict/128'],
    observedAt: '2026-10-05T18:00:00.000Z', secret,
  };
  for (const summary of ['user: private message\nassistant: reply', 'member@example.org', '"role":"user"']) {
    assert.throws(() => createEvidenceReceipt({
      ...base, event: { ...event, summary },
    }), /private (?:conversation )?content is forbidden in evidence/);
  }
  assert.throws(() => createEvidenceReceipt({
    ...base, evidenceRefs: ['Authorization: Bearer abcdefghijklmno'],
  }), /private content is forbidden in evidence/);
  assert.throws(() => createEvidenceReceipt({
    ...base, identity: { ...identity, metadata: { cookie: 'sensitive' } },
  }), /raw sensitive field is forbidden in evidence/);
});


test('redteam evidence aliases and transcript keys never reach receipts', () => {
  const sensitiveFieldNames = ['client_secret', 'private_key', 'accessToken', 'refresh_token', 'api_key', 'set_cookie', 'chat_history'];
  const sensitiveStrings = [
    'client_secret=SYNTHETIC_SECRET_VALUE',
    'private_key=SYNTHETIC_SECRET_VALUE',
    'set-cookie: session=sampletoken123',
  ];
  for (const field of sensitiveFieldNames) {
    assert.throws(() => ({metadata, summary}) => createEvidenceReceipt({id:'PM1-REDACT-001',event:{...event,summary:summary??event.summary,metadata},identity,evidenceRefs:['sensor://browser/verdict/129'],observedAt:'2026-10-05T18:00:00.000Z',secret})({ metadata: { [field]: 'SYNTHETIC_VALUE' } }), /sensitive|private/);
  }
  for (const summary of sensitiveStrings) {
    assert.throws(() => ({metadata, summary}) => createEvidenceReceipt({id:'PM1-REDACT-001',event:{...event,summary:summary??event.summary,metadata},identity,evidenceRefs:['sensor://browser/verdict/129'],observedAt:'2026-10-05T18:00:00.000Z',secret})({ summary }), /private content is forbidden/);
  }
});
