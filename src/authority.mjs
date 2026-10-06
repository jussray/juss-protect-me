export const SAFE_STANDING_CAPABILITIES = Object.freeze([
  'observe', 'retrieve', 'analyze', 'classify', 'reason', 'recommend', 'draft', 'test', 'measure'
]);

const FULL_SHA = /^[0-9a-f]{40}$/i;
const STABLE_ID = /^[A-Z][A-Z0-9_-]{2,127}$/;

function assertIso(value, name) {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) {
    throw new Error(`${name} must be an ISO-compatible timestamp`);
  }
}

function sameTarget(left, right) {
  return Boolean(left && right
    && left.system === right.system
    && left.repository === right.repository
    && String(left.commitSha).toLowerCase() === String(right.commitSha).toLowerCase());
}

export function assertFounderIntent(intent) {
  if (!intent || intent.schema !== 'protect-me/founder-intent@v1') throw new Error('invalid founder intent schema');
  if (!STABLE_ID.test(String(intent.id ?? ''))) throw new Error('intent.id must be an uppercase stable identifier');
  if (!String(intent.goal ?? '').trim()) throw new Error('intent.goal is required');
  if (!intent.target || !String(intent.target.system ?? '').trim() || !String(intent.target.repository ?? '').trim()) {
    throw new Error('intent.target system and repository are required');
  }
  if (!FULL_SHA.test(String(intent.target.commitSha ?? ''))) throw new Error('intent.target.commitSha must be a full 40-character Git SHA');
  if (!Array.isArray(intent.allowedCapabilities) || !intent.allowedCapabilities.every((x) => typeof x === 'string' && x.trim())) {
    throw new Error('intent.allowedCapabilities must be a list of capabilities');
  }
  if (!Array.isArray(intent.deniedCapabilities) || !intent.deniedCapabilities.every((x) => typeof x === 'string' && x.trim())) {
    throw new Error('intent.deniedCapabilities must be a list of capabilities');
  }
  assertIso(intent.issuedAt, 'intent.issuedAt');
}

export function assertAuthorityGrant(grant) {
  if (!grant || grant.schema !== 'protect-me/authority-grant@v1') throw new Error('invalid authority grant schema');
  if (!STABLE_ID.test(String(grant.id ?? ''))) throw new Error('grant.id must be an uppercase stable identifier');
  if (!STABLE_ID.test(String(grant.intentId ?? ''))) throw new Error('grant.intentId must be an uppercase stable identifier');
  if (!['explicit_current_turn', 'standing_policy'].includes(grant.mode)) throw new Error('grant.mode is invalid');
  if (!grant.target || !String(grant.target.system ?? '').trim() || !String(grant.target.repository ?? '').trim()) {
    throw new Error('grant.target system and repository are required');
  }
  if (!FULL_SHA.test(String(grant.target.commitSha ?? ''))) throw new Error('grant.target.commitSha must be a full 40-character Git SHA');
  if (!Array.isArray(grant.capabilities) || !grant.capabilities.every((x) => typeof x === 'string' && x.trim())) {
    throw new Error('grant.capabilities must be a list of capabilities');
  }
  if (!String(grant.proofRef ?? '').trim()) throw new Error('grant.proofRef is required');
  assertIso(grant.issuedAt, 'grant.issuedAt');
  assertIso(grant.expiresAt, 'grant.expiresAt');
  if (Date.parse(grant.expiresAt) <= Date.parse(grant.issuedAt)) throw new Error('grant.expiresAt must be after grant.issuedAt');
}

export async function authorizeIntentAction({
  intent,
  grant,
  requestedAction,
  currentTarget,
  now,
  consequence = 'low_risk',
  verifyAuthorityProof,
}) {
  assertFounderIntent(intent);
  assertAuthorityGrant(grant);
  assertIso(now, 'now');

  const reasons = [];
  if (!String(requestedAction ?? '').trim()) reasons.push('requested_action_missing');
  if (grant.intentId !== intent.id) reasons.push('intent_grant_mismatch');
  if (!sameTarget(intent.target, currentTarget)) reasons.push('intent_target_stale');
  if (!sameTarget(grant.target, currentTarget)) reasons.push('grant_target_stale');
  if (Date.parse(now) >= Date.parse(grant.expiresAt)) reasons.push('grant_expired');
  if (grant.revoked === true) reasons.push('grant_revoked');
  if (intent.deniedCapabilities.includes(requestedAction)) reasons.push('intent_explicitly_denies_action');
  if (!intent.allowedCapabilities.includes(requestedAction)) reasons.push('action_outside_intent');
  if (!grant.capabilities.includes(requestedAction)) reasons.push('action_outside_grant');

  const consequential = consequence === 'consequential';
  if (consequential && grant.mode !== 'explicit_current_turn') {
    reasons.push('current_turn_founder_approval_required');
  }
  if (grant.mode === 'standing_policy' && !SAFE_STANDING_CAPABILITIES.includes(requestedAction)) {
    reasons.push('standing_policy_cannot_authorize_this_action');
  }

  if (typeof verifyAuthorityProof !== 'function') {
    reasons.push('authority_proof_verifier_missing');
  } else {
    let verified = false;
    try {
      verified = await verifyAuthorityProof({
        proofRef: grant.proofRef,
        intentId: intent.id,
        grantId: grant.id,
        target: currentTarget,
        requestedAction,
        mode: grant.mode,
      });
    } catch {
      verified = false;
    }
    if (verified !== true) reasons.push('authority_proof_unverified');
  }

  return Object.freeze({
    authorized: reasons.length === 0,
    state: reasons.length === 0 ? 'AUTHORIZED' : 'DENIED',
    reasons,
    intentId: intent.id,
    grantId: grant.id,
    requestedAction,
    target: currentTarget,
  });
}
