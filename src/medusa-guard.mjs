// Model One Medusa boundary: bounded, pinned offline review evidence.
//
// The separate Medusa A-D checker is evidence-only; its "Proceed" does not
// establish human consent, a trustworthy sensor, or authorization to contain.
// This module deliberately never uploads customer material, runs a detector,
// opens files, or invokes containment.
import { createHash } from 'node:crypto';
import { assertThreatEvent, evaluateThreat, authorizeRecommendedAction } from './model-one.mjs';

const HEX64 = /^[0-9a-f]{64}$/;
const MAX_EXPORT_BYTES = 256 * 1024;
const ACCEPTED_GATES = new Set(['Proceed']);

function hold(reason) {
  return Object.freeze({
    state: 'HOLD',
    reason,
    recommendation: Object.freeze({
      action: 'manual_review',
      reason: 'medusa-review-required',
    }),
    canAuthorize: false,
    effectExecuted: false,
  });
}

export function evaluateMedusaBoundThreat({
  threat,
  rawExport,
  expectedSha256,
  expectedTarget,
} = {}) {
  // Model One's existing privacy-safe event validator always runs first.
  assertThreatEvent(threat);

  if (typeof rawExport !== 'string' || Buffer.byteLength(rawExport, 'utf8') > MAX_EXPORT_BYTES ||
      rawExport.length === 0) return hold('missing_or_oversized_export');
  // Trust comes from an expected digest supplied independently of the
  // untrusted report. Never accept a digest embedded by its own author.
  if (typeof expectedSha256 !== 'string' || !HEX64.test(expectedSha256)) {
    return hold('independent_digest_required');
  }
  const actual = createHash('sha256').update(rawExport, 'utf8').digest('hex');
  if (actual !== expectedSha256) return hold('export_digest_mismatch');

  let exported;
  try {
    exported = JSON.parse(rawExport);
  } catch {
    return hold('invalid_export_json');
  }
  if (!exported || typeof exported !== 'object' || Array.isArray(exported)) return hold('invalid_export_shape');
  const checker = exported.checker;
  const assessment = exported.assessment;
  if (!checker || !assessment || typeof assessment !== 'object' ||
      checker.authority !== 'evidence_only' ||
      checker.can_authorize !== false ||
      checker.independent_truth_verified !== false ||
      checker.manual_privacy_review_required !== true ||
      !Array.isArray(checker.errors) || checker.errors.length !== 0 ||
      !ACCEPTED_GATES.has(checker.gate) ||
      checker.exit !== 0) {
    return hold('medusa_gate_not_eligible');
  }
  if (typeof expectedTarget !== 'string' || expectedTarget.length < 1 ||
      expectedTarget.length > 128 || assessment.target?.name !== expectedTarget) {
    return hold('medusa_scope_mismatch');
  }
  // A checker output copied into JSON is not independently authenticated.
  // Even with a matching independently pinned digest, the report is advisory.
  const recommendation = evaluateThreat(threat);
  return Object.freeze({
    state: 'REVIEWED_EVIDENCE',
    reason: 'pinned_review_advisory_only',
    recommendation,
    reportSha256: actual,
    reportGate: checker.gate,
    canAuthorize: false,
    effectExecuted: false,
    nextGate: 'separate_privacy_and_authority_review',
  });
}


/**
 * Real Model One decision composition: Medusa may VETO an action, never grant
 * one. Only the independent signed-receipt + member-policy authority kernel
 * can return authorized=true. This function performs no action itself.
 */
export function authorizeWithMedusaReview({ threat, rawExport, expectedSha256,
  expectedTarget, policy = {} } = {}) {
  const reviewed = evaluateMedusaBoundThreat({
    threat, rawExport, expectedSha256, expectedTarget,
  });
  if (reviewed.state !== 'REVIEWED_EVIDENCE') {
    return Object.freeze({
      authorized: false,
      reason: 'medusa_review_hold',
      medusaReason: reviewed.reason,
      canExecute: false,
      effectExecuted: false,
    });
  }
  const policyGate = authorizeRecommendedAction(reviewed.recommendation, policy);
  return Object.freeze({
    ...policyGate,
    medusaReviewState: reviewed.state,
    medusaReportSha256: reviewed.reportSha256,
    medusaConferredAuthority: false,
    canExecute: false,
    effectExecuted: false,
  });
}
