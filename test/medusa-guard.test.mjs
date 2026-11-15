import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { evaluateMedusaBoundThreat, authorizeWithMedusaReview } from '../src/medusa-guard.mjs';
import { createEvidenceReceipt } from '../src/model-one.mjs';

const threat = { kind: 'phishing', severity: 'high', confidence: 0.96,
  summary: 'Synthetic suspicious link report, not a live verdict.' };
const target = 'juss-protect-me';
const exportDoc = {
  assessment: { target: { name: target, version: 'demo', date: '2026-11-15' } },
  checker: { gate: 'Proceed', exit: 0, errors: [],
    authority: 'evidence_only', can_authorize: false,
    independent_truth_verified: false, manual_privacy_review_required: true },
  warning: 'Evidence-only advisory; not release authority',
};
function evaluate(document = exportDoc, overrides = {}) {
  const rawExport = JSON.stringify(document);
  const expectedSha256 = createHash('sha256').update(rawExport).digest('hex');
  return evaluateMedusaBoundThreat({
    threat, rawExport, expectedSha256, expectedTarget: target, ...overrides,
  });
}

test('valid pinned report yields advice, never automatic action', () => {
  const result = evaluate();
  assert.equal(result.state, 'REVIEWED_EVIDENCE');
  assert.equal(result.recommendation.action, 'block_navigation');
  assert.equal(result.canAuthorize, false);
  assert.equal(result.effectExecuted, false);
  assert.equal(result.nextGate, 'separate_privacy_and_authority_review');
});

test('a report cannot pin its own digest', () => {
  assert.equal(evaluate(exportDoc, { expectedSha256: undefined }).state, 'HOLD');
  assert.equal(evaluate(exportDoc, { expectedSha256: '0'.repeat(64) }).state, 'HOLD');
});

test('modified report cannot bypass integrity check', () => {
  const original = JSON.stringify(exportDoc);
  const digest = createHash('sha256').update(original).digest('hex');
  const modified = original.replace('"Proceed"', '"Stop"');
  const state = evaluate(exportDoc, { rawExport: modified, expectedSha256: digest });
  assert.equal(state.state, 'HOLD');
  assert.equal(state.recommendation.action, 'manual_review');
});

test('Hold, Stop, blocked and incomplete reviews never promote actions', () => {
  for (const gate of ['Hold', 'Stop', 'BLOCKED', 'Proceed with named changes',
    'Pass 1 only (advisory)']) {
    const doc = structuredClone(exportDoc);
    doc.checker.gate = gate;
    assert.equal(evaluate(doc).state, 'HOLD', gate);
  }
});

test('forged authority and scope mismatch fail closed', () => {
  const doc = structuredClone(exportDoc);
  doc.checker.can_authorize = true;
  assert.equal(evaluate(doc).state, 'HOLD');
  assert.equal(evaluate(exportDoc, { expectedTarget: 'other-model' }).state, 'HOLD');
});

test('oversize export and raw sensitive threat fields are rejected', () => {
  assert.equal(evaluate(exportDoc, { rawExport: 'x'.repeat(300000) }).state, 'HOLD');
  assert.throws(() => evaluateMedusaBoundThreat({
    threat: { ...threat, token: 'synthetic-secret' },
    rawExport: '{}',
    expectedSha256: '0'.repeat(64),
    expectedTarget: target,
  }), /raw sensitive field/);
});


test('integrated Medusa veto and independent evidence/policy must both pass', () => {
  const rawExport = JSON.stringify(exportDoc);
  const expectedSha256 = createHash('sha256').update(rawExport).digest('hex');
  const secret = 'synthetic-evidence-secret-32-chars-only';
  const identity = { modelVersion: 'model-one-test', policyVersion: 'policy-test',
    deviceScope: 'device:test-only', sourceSha: 'a'.repeat(40),
    sensorVersions: { browser: 'synthetic-v1' } };
  const evidenceReceipt = createEvidenceReceipt({
    id: 'MEDUSA-MODEL-ONE-1', event: threat, identity,
    evidenceRefs: ['synthetic://device-evidence/1'],
    observedAt: new Date().toISOString(), secret,
  });
  const args = {
    threat, rawExport, expectedSha256, expectedTarget: target,
    policy: { autoActions: ['block_navigation'], minConfidence: 0.95,
      evidenceReceipt, evidenceSecret: secret, currentIdentity: identity },
  };
  const approved = authorizeWithMedusaReview(args);
  assert.equal(approved.authorized, true, 'policy may authorize after both evidence checks');
  assert.equal(approved.medusaConferredAuthority, false);
  assert.equal(approved.canExecute, false, 'decision is not an actuator');

  assert.equal(authorizeWithMedusaReview({
    ...args, policy: { autoActions: ['block_navigation'], minConfidence: 0.95 },
  }).authorized, false, 'Medusa is not a replacement for signed evidence');
  assert.equal(authorizeWithMedusaReview({
    ...args, expectedTarget: 'wrong-target',
  }).reason, 'medusa_review_hold', 'Medusa may veto a fully permitted action');
  assert.equal(authorizeWithMedusaReview({
    ...args, policy: { ...args.policy, autoActions: [] },
  }).authorized, false, 'policy can veto a reviewed recommendation');
});
