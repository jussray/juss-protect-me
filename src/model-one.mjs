import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export const THREAT_KINDS = Object.freeze([
  'malware',
  'ransomware',
  'phishing',
  'scam',
  'deepfake',
  'credential_exposure',
  'account_takeover',
  'privacy_exposure',
  'unsafe_network',
  'device_tamper',
  'unknown',
]);

export const REVERSIBLE_ACTIONS = Object.freeze([
  'notify',
  'block_navigation',
  'quarantine_file',
  'isolate_device',
  'revoke_session',
  'manual_review',
]);

const FULL_SHA = /^[0-9a-f]{40}$/i;
const SENSITIVE_KEY = /^(password|passcode|secret|token|cookie|authorization|ssn|social_security_number|raw_ip|ip_address|email)$/i;

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
}

function canonical(value) {
  return JSON.stringify(stable(value));
}

function digest(kind, material, secret = null) {
  return kind === 'hmac-sha256'
    ? createHmac('sha256', secret).update(material).digest('hex')
    : createHash('sha256').update(material).digest('hex');
}

function assertIso(value, name) {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) {
    throw new Error(`${name} must be an ISO-compatible timestamp`);
  }
}

function walkKeys(value, path = '$') {
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if (SENSITIVE_KEY.test(key)) {
      throw new Error(`raw sensitive field is forbidden in evidence: ${path}.${key}`);
    }
    walkKeys(child, `${path}.${key}`);
  }
}

export function assertModelIdentity(identity) {
  if (!identity || typeof identity !== 'object') throw new Error('identity is required');
  if (!String(identity.modelVersion ?? '').trim()) throw new Error('identity.modelVersion is required');
  if (!String(identity.policyVersion ?? '').trim()) throw new Error('identity.policyVersion is required');
  if (!String(identity.deviceScope ?? '').trim()) throw new Error('identity.deviceScope is required');
  if (identity.sourceSha !== undefined && !FULL_SHA.test(String(identity.sourceSha))) {
    throw new Error('identity.sourceSha must be a full 40-character Git SHA when present');
  }
  if (identity.sensorVersions !== undefined && (typeof identity.sensorVersions !== 'object' || Array.isArray(identity.sensorVersions))) {
    throw new Error('identity.sensorVersions must be an object when present');
  }
}

export function assertThreatEvent(event) {
  if (!event || typeof event !== 'object') throw new Error('event is required');
  if (!THREAT_KINDS.includes(event.kind)) throw new Error(`unsupported threat kind: ${event.kind}`);
  if (!['low', 'medium', 'high', 'critical'].includes(event.severity)) throw new Error('event.severity is invalid');
  if (!(Number.isFinite(event.confidence) && event.confidence >= 0 && event.confidence <= 1)) {
    throw new Error('event.confidence must be between 0 and 1');
  }
  if (!String(event.summary ?? '').trim()) throw new Error('event.summary is required');
  walkKeys(event);
}

export function evaluateThreat(event) {
  assertThreatEvent(event);
  const { kind, severity, confidence } = event;
  const lowConfidence = confidence < 0.75;
  if (lowConfidence || kind === 'unknown') {
    return Object.freeze({ action: 'manual_review', confidence, reason: 'insufficient-confidence-or-attribution' });
  }

  if (kind === 'phishing' || kind === 'scam' || kind === 'deepfake') {
    return Object.freeze({ action: severity === 'low' ? 'notify' : 'block_navigation', confidence, reason: `${kind}-content-risk` });
  }
  if (kind === 'malware' || kind === 'ransomware') {
    return Object.freeze({ action: severity === 'critical' ? 'isolate_device' : 'quarantine_file', confidence, reason: `${kind}-execution-risk` });
  }
  if (kind === 'account_takeover' || kind === 'credential_exposure') {
    return Object.freeze({ action: severity === 'low' ? 'notify' : 'revoke_session', confidence, reason: `${kind}-identity-risk` });
  }
  if (kind === 'device_tamper') {
    return Object.freeze({ action: severity === 'high' || severity === 'critical' ? 'isolate_device' : 'notify', confidence, reason: 'device-integrity-risk' });
  }
  return Object.freeze({ action: 'notify', confidence, reason: `${kind}-user-attention` });
}

export function authorizeRecommendedAction(recommendation, policy = {}) {
  if (!recommendation || !REVERSIBLE_ACTIONS.includes(recommendation.action)) {
    return Object.freeze({ authorized: false, reason: 'unsupported-or-destructive-action' });
  }
  if (recommendation.action === 'manual_review' || recommendation.action === 'notify') {
    return Object.freeze({ authorized: true, reason: 'non-destructive-user-safety-action' });
  }
  const minConfidence = Number.isFinite(policy.minConfidence) ? policy.minConfidence : 0.9;
  const allowed = Array.isArray(policy.autoActions) ? new Set(policy.autoActions) : new Set();
  if (recommendation.confidence < minConfidence) {
    return Object.freeze({ authorized: false, reason: 'below-policy-confidence-threshold' });
  }
  if (!allowed.has(recommendation.action)) {
    return Object.freeze({ authorized: false, reason: 'separate-policy-approval-required' });
  }
  return Object.freeze({ authorized: true, reason: 'separate-policy-authorized-reversible-action' });
}

export function createEvidenceReceipt({ id, event, identity, evidenceRefs = [], observedAt, secret = null }) {
  if (!/^[A-Z][A-Z0-9_-]{2,127}$/.test(String(id ?? ''))) {
    throw new Error('receipt id must be an uppercase stable identifier');
  }
  assertThreatEvent(event);
  assertModelIdentity(identity);
  assertIso(observedAt, 'observedAt');
  if (!Array.isArray(evidenceRefs) || !evidenceRefs.every((ref) => typeof ref === 'string' && ref.trim())) {
    throw new Error('evidenceRefs must contain non-empty strings');
  }

  const receiptKind = secret ? 'hmac-sha256' : 'sha256-unauthenticated';
  const state = evidenceRefs.length === 0 ? 'unknown' : secret ? 'verified' : 'inferred';
  const core = {
    schema: 'juss-protect-me/model-one-evidence@v1',
    id,
    state,
    observedAt,
    identity: stable(identity),
    event: stable(event),
    evidenceRefs: [...evidenceRefs],
    invalidatedBy: [],
    authority: { level: 'evidence_only', canAuthorize: false },
    receiptKind,
  };
  return Object.freeze({ ...core, receipt: digest(receiptKind, canonical(core), secret) });
}

export function verifyEvidenceReceipt(receipt, secret = null) {
  if (!receipt?.receipt || !receipt?.receiptKind) return false;
  if (receipt.receiptKind === 'hmac-sha256' && !secret) return false;
  const { receipt: supplied, ...core } = receipt;
  const expected = digest(receipt.receiptKind, canonical(core), secret);
  const a = Buffer.from(String(supplied), 'hex');
  const b = Buffer.from(expected, 'hex');
  return a.length === b.length && a.length > 0 && timingSafeEqual(a, b);
}

export function evaluateReceiptStaleness(receipt, currentIdentity) {
  assertModelIdentity(currentIdentity);
  const previous = receipt?.identity;
  if (!previous) return Object.freeze({ state: 'stale', invalidatedBy: ['missing_receipt_identity'] });
  const invalidatedBy = [];
  for (const key of ['modelVersion', 'policyVersion', 'deviceScope', 'sourceSha']) {
    if ((previous[key] ?? null) !== (currentIdentity[key] ?? null)) invalidatedBy.push(`${key}_changed`);
  }
  if (canonical(previous.sensorVersions ?? {}) !== canonical(currentIdentity.sensorVersions ?? {})) {
    invalidatedBy.push('sensor_versions_changed');
  }
  return Object.freeze({
    state: invalidatedBy.length ? 'stale' : receipt.state,
    invalidatedBy,
  });
}
