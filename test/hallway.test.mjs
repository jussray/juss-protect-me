import assert from 'node:assert/strict';
import test from 'node:test';
import {
  EXPANSION_BASE,
  createHallwayEnvelope,
  deriveExpansionBudget,
  identificationDisposition,
  verifyHallwayEnvelope,
} from '../src/hallway.mjs';

const secret = 'test-only-hallway-secret';
const sender = Object.freeze({
  system: 'protect-me-model-one',
  repository: 'jussray/juss-protect-me',
  commitSha: 'a'.repeat(40),
});
const receiver = Object.freeze({
  system: 'protect-me-model-two',
  repository: 'jussray/juss-protect-me-2',
  commitSha: 'b'.repeat(40),
});

test('EXPAND always starts at 48,000 logical observation units and stays bounded', () => {
  const expansion = deriveExpansionBudget({ sessionKey: 'device-a', eventKey: 'event-a', step: 1, secret });
  assert.equal(expansion.fixed, 48_000);
  assert.equal(expansion.observationUnits >= EXPANSION_BASE, true);
  assert.equal(expansion.observationUnits <= EXPANSION_BASE + 16_000, true);
  assert.equal(expansion.materialization, 'logical-first');
});

test('EXPAND is deterministic for reconstruction but varies by suspicious step', () => {
  const a = deriveExpansionBudget({ sessionKey: 'device-a', eventKey: 'event-a', step: 1, secret });
  const a2 = deriveExpansionBudget({ sessionKey: 'device-a', eventKey: 'event-a', step: 1, secret });
  const b = deriveExpansionBudget({ sessionKey: 'device-a', eventKey: 'event-a', step: 2, secret });
  assert.deepEqual(a, a2);
  assert.notEqual(a.boundedRandom, b.boundedRandom);
});

test('danger can be contained while identity remains UNKNOWN', () => {
  const expansion = deriveExpansionBudget({ sessionKey: 'device-a', eventKey: 'event-a', step: 1, secret });
  const decision = identificationDisposition({ verdict: 'PHISHING', confidence: 0.99, corroboratingSignals: 1, expansion });
  assert.equal(decision.action, 'CONTAIN');
  assert.equal(decision.attribution, 'UNKNOWN');
});

test('uncertain behavior stays in observation instead of being over-attributed', () => {
  const expansion = deriveExpansionBudget({ sessionKey: 'device-a', eventKey: 'event-a', step: 1, secret });
  assert.deepEqual(
    identificationDisposition({ verdict: 'SCAM', confidence: 0.6, corroboratingSignals: 2, expansion }),
    { attribution: 'UNKNOWN', action: 'OBSERVE', reason: 'insufficient-convergence' },
  );
});

test('Model One can sign evidence-only hallway envelopes for Model Two', () => {
  const envelope = createHallwayEnvelope({
    id: 'HALLWAY-001',
    sender,
    receiver,
    evidence: {
      receiptId: 'PM1-001',
      state: 'verified',
      authority: { level: 'evidence_only', canAuthorize: false },
    },
    expansion: deriveExpansionBudget({ sessionKey: 'device-a', eventKey: 'event-a', step: 1, secret }),
    issuedAt: '2026-10-05T20:00:00.000Z',
    expiresAt: '2026-10-05T20:05:00.000Z',
    nonce: 'nonce-001',
    secret,
  });
  const result = verifyHallwayEnvelope(envelope, {
    secret,
    expectedReceiver: receiver,
    now: '2026-10-05T20:01:00.000Z',
  });
  assert.equal(result.ok, true);
  assert.equal(envelope.transportAuthority.canAuthorize, false);
});

test('hallway refuses expired or replayed evidence', () => {
  const envelope = createHallwayEnvelope({
    id: 'HALLWAY-002',
    sender,
    receiver,
    evidence: {
      receiptId: 'PM1-002',
      state: 'verified',
      authority: { level: 'evidence_only', canAuthorize: false },
    },
    expansion: deriveExpansionBudget({ sessionKey: 'device-b', eventKey: 'event-b', step: 1, secret }),
    issuedAt: '2026-10-05T20:00:00.000Z',
    expiresAt: '2026-10-05T20:05:00.000Z',
    nonce: 'nonce-002',
    secret,
  });
  assert.equal(verifyHallwayEnvelope(envelope, {
    secret,
    expectedReceiver: receiver,
    now: '2026-10-05T20:06:00.000Z',
  }).reasons.includes('expired'), true);
  assert.equal(verifyHallwayEnvelope(envelope, {
    secret,
    expectedReceiver: receiver,
    now: '2026-10-05T20:01:00.000Z',
    seenNonces: new Set(['nonce-002']),
  }).reasons.includes('replay_detected'), true);
});
