import assert from 'node:assert/strict';
import test from 'node:test';

import { authorizeIntentAction } from '../src/authority.mjs';

const target = Object.freeze({
  system: 'protect-me-model-one',
  repository: 'jussray/juss-protect-me',
  commitSha: 'a'.repeat(40),
});

const intent = Object.freeze({
  schema: 'protect-me/founder-intent@v1',
  id: 'INTENT-001',
  goal: 'Protect the user while preserving founder control over consequential actions.',
  target,
  allowedCapabilities: ['observe', 'classify', 'notify', 'block_navigation', 'isolate_device'],
  deniedCapabilities: ['wipe_device'],
  issuedAt: '2026-10-05T22:00:00.000Z',
});

function grant(overrides = {}) {
  return {
    schema: 'protect-me/authority-grant@v1',
    id: 'GRANT-001',
    intentId: intent.id,
    mode: 'explicit_current_turn',
    target,
    capabilities: ['observe', 'classify', 'notify', 'block_navigation', 'isolate_device'],
    proofRef: 'founder-auth://current-turn/001',
    issuedAt: '2026-10-05T22:00:00.000Z',
    expiresAt: '2026-10-05T22:15:00.000Z',
    revoked: false,
    ...overrides,
  };
}

const verifiedProof = async () => true;

test('intent is not authority by itself', async () => {
  const result = await authorizeIntentAction({
    intent,
    grant: grant(),
    requestedAction: 'isolate_device',
    currentTarget: target,
    now: '2026-10-05T22:01:00.000Z',
    consequence: 'consequential',
  });
  assert.equal(result.authorized, false);
  assert.equal(result.reasons.includes('authority_proof_verifier_missing'), true);
});

test('consequential action requires explicit current-turn founder authority', async () => {
  const result = await authorizeIntentAction({
    intent,
    grant: grant({ mode: 'standing_policy' }),
    requestedAction: 'isolate_device',
    currentTarget: target,
    now: '2026-10-05T22:01:00.000Z',
    consequence: 'consequential',
    verifyAuthorityProof: verifiedProof,
  });
  assert.equal(result.authorized, false);
  assert.equal(result.reasons.includes('current_turn_founder_approval_required'), true);
});

test('standing policy may authorize only safe declared capabilities', async () => {
  const standingIntent = { ...intent, allowedCapabilities: ['observe', 'classify'] };
  const standingGrant = grant({
    mode: 'standing_policy',
    capabilities: ['observe', 'classify'],
    proofRef: 'founder-policy://protect-me-one/safe-observation',
  });
  const result = await authorizeIntentAction({
    intent: standingIntent,
    grant: standingGrant,
    requestedAction: 'classify',
    currentTarget: target,
    now: '2026-10-05T22:01:00.000Z',
    consequence: 'low_risk',
    verifyAuthorityProof: verifiedProof,
  });
  assert.equal(result.authorized, true);
});

test('authority does not jump SHA changes', async () => {
  const result = await authorizeIntentAction({
    intent,
    grant: grant(),
    requestedAction: 'block_navigation',
    currentTarget: { ...target, commitSha: 'b'.repeat(40) },
    now: '2026-10-05T22:01:00.000Z',
    consequence: 'consequential',
    verifyAuthorityProof: verifiedProof,
  });
  assert.equal(result.authorized, false);
  assert.equal(result.reasons.includes('intent_target_stale'), true);
  assert.equal(result.reasons.includes('grant_target_stale'), true);
});

test('intent denial beats a grant', async () => {
  const result = await authorizeIntentAction({
    intent,
    grant: grant({ capabilities: [...grant().capabilities, 'wipe_device'] }),
    requestedAction: 'wipe_device',
    currentTarget: target,
    now: '2026-10-05T22:01:00.000Z',
    consequence: 'consequential',
    verifyAuthorityProof: verifiedProof,
  });
  assert.equal(result.authorized, false);
  assert.equal(result.reasons.includes('intent_explicitly_denies_action'), true);
});

test('expired or revoked authority fails closed', async () => {
  const expired = await authorizeIntentAction({
    intent,
    grant: grant(),
    requestedAction: 'notify',
    currentTarget: target,
    now: '2026-10-05T22:16:00.000Z',
    consequence: 'low_risk',
    verifyAuthorityProof: verifiedProof,
  });
  assert.equal(expired.reasons.includes('grant_expired'), true);

  const revoked = await authorizeIntentAction({
    intent,
    grant: grant({ revoked: true }),
    requestedAction: 'notify',
    currentTarget: target,
    now: '2026-10-05T22:01:00.000Z',
    consequence: 'low_risk',
    verifyAuthorityProof: verifiedProof,
  });
  assert.equal(revoked.reasons.includes('grant_revoked'), true);
});
