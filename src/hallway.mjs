import { createHmac, timingSafeEqual } from 'node:crypto';

export const HALLWAY_SCHEMA = 'protect-me/hallway-envelope@v1';
export const EXPANSION_BASE = 48_000;
export const EXPANSION_RANDOM_MAX = 16_000;

const FULL_SHA = /^[0-9a-f]{40}$/i;
const ENVELOPE_ID = /^[A-Z][A-Z0-9_-]{2,127}$/;

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
}
function canonical(value) { return JSON.stringify(stable(value)); }
function hmacHex(secret, value) { return createHmac('sha256', secret).update(value).digest('hex'); }
function assertIso(value, name) {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) throw new Error(`${name} must be an ISO-compatible timestamp`);
}

export function deriveExpansionBudget({ sessionKey, eventKey, step, secret, randomMax = EXPANSION_RANDOM_MAX }) {
  if (!String(sessionKey ?? '').trim()) throw new Error('sessionKey is required');
  if (!String(eventKey ?? '').trim()) throw new Error('eventKey is required');
  if (!(Number.isInteger(step) && step >= 1)) throw new Error('step must be an integer >= 1');
  if (!String(secret ?? '').trim()) throw new Error('secret is required');
  if (!(Number.isInteger(randomMax) && randomMax >= 0 && randomMax <= 1_000_000)) throw new Error('randomMax must be an integer between 0 and 1000000');
  const seed = hmacHex(secret, `${sessionKey}\n${eventKey}\n${step}\nexpand-v1`);
  const sample = BigInt(`0x${seed.slice(0, 16)}`);
  const boundedRandom = Number(sample % BigInt(randomMax + 1));
  return Object.freeze({
    schema: 'protect-me/expansion-budget@v1',
    step,
    fixed: EXPANSION_BASE,
    boundedRandom,
    observationUnits: EXPANSION_BASE + boundedRandom,
    materialization: 'logical-first',
    authority: 'none',
  });
}

export function createHallwayEnvelope({ id, sender, receiver, evidence, expansion, issuedAt, expiresAt, nonce, secret }) {
  if (!ENVELOPE_ID.test(String(id ?? ''))) throw new Error('id must be an uppercase stable identifier');
  if (!sender || !receiver) throw new Error('sender and receiver are required');
  for (const [name, identity] of [['sender', sender], ['receiver', receiver]]) {
    if (!String(identity.system ?? '').trim()) throw new Error(`${name}.system is required`);
    if (!String(identity.repository ?? '').trim()) throw new Error(`${name}.repository is required`);
    if (!FULL_SHA.test(String(identity.commitSha ?? ''))) throw new Error(`${name}.commitSha must be a full 40-character Git SHA`);
  }
  if (!evidence || typeof evidence !== 'object') throw new Error('evidence is required');
  if (!String(evidence.receiptId ?? '').trim()) throw new Error('evidence.receiptId is required');
  if (!String(evidence.state ?? '').trim()) throw new Error('evidence.state is required');
  if (evidence.authority?.canAuthorize !== false) throw new Error('hallway evidence must explicitly carry canAuthorize=false');
  assertIso(issuedAt, 'issuedAt');
  assertIso(expiresAt, 'expiresAt');
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)) throw new Error('expiresAt must be after issuedAt');
  if (!String(nonce ?? '').trim()) throw new Error('nonce is required');
  if (!String(secret ?? '').trim()) throw new Error('secret is required');
  const core = {
    schema: HALLWAY_SCHEMA,
    id,
    sender: stable(sender),
    receiver: stable(receiver),
    evidence: stable(evidence),
    expansion: expansion ? stable(expansion) : null,
    issuedAt,
    expiresAt,
    nonce,
    transportAuthority: { level: 'evidence_only', canAuthorize: false },
  };
  return Object.freeze({ ...core, signature: hmacHex(secret, canonical(core)) });
}

export function verifyHallwayEnvelope(envelope, { secret, expectedReceiver, now, seenNonces = new Set() }) {
  if (!envelope?.signature || envelope.schema !== HALLWAY_SCHEMA) return Object.freeze({ ok: false, state: 'rejected', reasons: ['invalid_shape'] });
  if (!String(secret ?? '').trim()) return Object.freeze({ ok: false, state: 'rejected', reasons: ['missing_verification_secret'] });
  assertIso(now, 'now');
  const { signature, ...core } = envelope;
  const expected = hmacHex(secret, canonical(core));
  const suppliedBuffer = Buffer.from(String(signature), 'hex');
  const expectedBuffer = Buffer.from(expected, 'hex');
  const signatureOk = suppliedBuffer.length === expectedBuffer.length && suppliedBuffer.length > 0 && timingSafeEqual(suppliedBuffer, expectedBuffer);
  const reasons = [];
  if (!signatureOk) reasons.push('signature_invalid');
  if (Date.parse(now) >= Date.parse(envelope.expiresAt)) reasons.push('expired');
  if (seenNonces.has(envelope.nonce)) reasons.push('replay_detected');
  if (expectedReceiver) {
    if (envelope.receiver.system !== expectedReceiver.system) reasons.push('receiver_system_mismatch');
    if (envelope.receiver.repository !== expectedReceiver.repository) reasons.push('receiver_repository_mismatch');
    if (String(envelope.receiver.commitSha).toLowerCase() !== String(expectedReceiver.commitSha).toLowerCase()) reasons.push('receiver_identity_changed');
  }
  if (envelope.transportAuthority?.canAuthorize !== false || envelope.evidence?.authority?.canAuthorize !== false) reasons.push('authority_escalation_attempt');
  return Object.freeze({ ok: reasons.length === 0, state: reasons.length === 0 ? 'accepted_evidence' : 'rejected', reasons, nonce: envelope.nonce });
}

export function identificationDisposition({ verdict, confidence, corroboratingSignals, expansion }) {
  if (!expansion || expansion.observationUnits < EXPANSION_BASE) return Object.freeze({ attribution: 'UNKNOWN', action: 'OBSERVE', reason: 'expansion_budget_missing' });
  const knownDanger = ['MALWARE', 'RANSOMWARE', 'PHISHING', 'ACCOUNT_TAKEOVER'].includes(String(verdict).toUpperCase()) && Number(confidence) >= 0.95;
  if (knownDanger) {
    return Object.freeze({ attribution: 'UNKNOWN', action: 'CONTAIN', reason: 'known-danger-contained-while-attribution-remains-open' });
  }
  const signalCount = Number.isInteger(corroboratingSignals) ? corroboratingSignals : 0;
  if (Number(confidence) >= 0.9 && signalCount >= 3) {
    return Object.freeze({ attribution: 'TECHNICAL_SESSION_IDENTIFIED', action: 'REVIEW', reason: 'evidence-converged-after-expansion' });
  }
  return Object.freeze({ attribution: 'UNKNOWN', action: 'OBSERVE', reason: 'insufficient-convergence' });
}
