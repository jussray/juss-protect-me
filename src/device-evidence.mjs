import { createHmac } from 'node:crypto';

export const DEVICE_OBSERVATION_SCHEMA = 'protect-me/device-observation@v1';
export const DEVICE_ASSESSMENT_SCHEMA = 'protect-me/device-risk-assessment@v1';

const PROVIDER = /^[a-z0-9][a-z0-9._-]{1,63}$/;
const DEVICE_REF = /^device:hmac-sha256:[0-9a-f]{64}$/;
const AUTOMATION = new Set(['bad', 'good', 'not_detected', 'unknown']);
const VELOCITY = new Set(['normal', 'elevated', 'high', 'unknown']);
const TOP_LEVEL_KEYS = new Set(['provider', 'observedAt', 'evidenceRef', 'deviceRef', 'signals']);
const SIGNAL_KEYS = new Set([
  'automation',
  'vpn',
  'proxy',
  'tampering',
  'incognito',
  'maliciousIp',
  'velocity',
  'sessionAuthenticated',
  'confidence',
]);

function assertIso(value, name) {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) {
    throw new Error(`${name} must be an ISO-compatible timestamp`);
  }
}

function assertAllowedKeys(value, allowed, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  const unexpected = Object.keys(value).filter((key) => !allowed.has(key));
  if (unexpected.length) {
    throw new Error(`${name} contains unsupported fields: ${unexpected.sort().join(', ')}`);
  }
}

function optionalBoolean(value, name) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'boolean') throw new Error(`${name} must be boolean when present`);
  return value;
}

function normalizeSignals(signals = {}) {
  assertAllowedKeys(signals, SIGNAL_KEYS, 'signals');
  const automation = signals.automation ?? 'unknown';
  if (!AUTOMATION.has(automation)) throw new Error('signals.automation is invalid');
  const velocity = signals.velocity ?? 'unknown';
  if (!VELOCITY.has(velocity)) throw new Error('signals.velocity is invalid');
  const confidence = signals.confidence ?? null;
  if (confidence !== null && !(Number.isFinite(confidence) && confidence >= 0 && confidence <= 1)) {
    throw new Error('signals.confidence must be between 0 and 1 when present');
  }
  return Object.freeze({
    automation,
    vpn: optionalBoolean(signals.vpn, 'signals.vpn'),
    proxy: optionalBoolean(signals.proxy, 'signals.proxy'),
    tampering: optionalBoolean(signals.tampering, 'signals.tampering'),
    incognito: optionalBoolean(signals.incognito, 'signals.incognito'),
    maliciousIp: optionalBoolean(signals.maliciousIp, 'signals.maliciousIp'),
    velocity,
    sessionAuthenticated: optionalBoolean(signals.sessionAuthenticated, 'signals.sessionAuthenticated'),
    confidence,
  });
}

export function derivePseudonymousDeviceRef({ provider, externalId, secret }) {
  if (!PROVIDER.test(String(provider ?? ''))) throw new Error('provider is invalid');
  if (!String(externalId ?? '').trim()) throw new Error('externalId is required');
  if (!String(secret ?? '').trim()) throw new Error('secret is required');
  const digest = createHmac('sha256', secret)
    .update(`${provider}\n${externalId}`)
    .digest('hex');
  return `device:hmac-sha256:${digest}`;
}

export function createDeviceObservation(input) {
  assertAllowedKeys(input, TOP_LEVEL_KEYS, 'observation');
  if (!PROVIDER.test(String(input.provider ?? ''))) throw new Error('provider is invalid');
  assertIso(input.observedAt, 'observedAt');
  if (!String(input.evidenceRef ?? '').trim()) throw new Error('evidenceRef is required');
  if (!DEVICE_REF.test(String(input.deviceRef ?? ''))) {
    throw new Error('deviceRef must be a server-derived HMAC device reference');
  }
  return Object.freeze({
    schema: DEVICE_OBSERVATION_SCHEMA,
    provider: input.provider,
    observedAt: input.observedAt,
    evidenceRef: input.evidenceRef,
    deviceRef: input.deviceRef,
    signals: normalizeSignals(input.signals),
    authority: Object.freeze({ level: 'evidence_only', canAuthorize: false }),
  });
}

export function assessDeviceRisk(observations) {
  if (!Array.isArray(observations) || observations.length === 0) {
    throw new Error('at least one device observation is required');
  }
  for (const observation of observations) {
    if (observation?.schema !== DEVICE_OBSERVATION_SCHEMA) throw new Error('invalid device observation schema');
    if (observation.authority?.canAuthorize !== false) throw new Error('device observations cannot carry authority');
  }

  const deviceRefs = new Set(observations.map((observation) => observation.deviceRef));
  if (deviceRefs.size !== 1) throw new Error('observations from different device scopes cannot be merged');

  const reasons = new Set();
  const confidences = [];
  for (const { signals } of observations) {
    if (signals.confidence !== null) confidences.push(signals.confidence);
    if (signals.tampering === true) reasons.add('device_tampering_detected');
    if (signals.automation === 'bad') reasons.add('bad_automation_detected');
    if (signals.maliciousIp === true) reasons.add('malicious_ip_reputation');
    if (signals.velocity === 'high') reasons.add('high_velocity');
    if (signals.velocity === 'elevated') reasons.add('elevated_velocity');
    if (signals.vpn === true) reasons.add('vpn_observed');
    if (signals.proxy === true) reasons.add('proxy_observed');
    if (signals.incognito === true) reasons.add('incognito_observed');
  }

  const highReasons = ['device_tampering_detected', 'bad_automation_detected', 'malicious_ip_reputation', 'high_velocity'];
  const mediumReasons = ['elevated_velocity', 'vpn_observed', 'proxy_observed', 'incognito_observed'];
  const hasHigh = highReasons.some((reason) => reasons.has(reason));
  const hasMedium = mediumReasons.some((reason) => reasons.has(reason));
  const hasKnownSignal = observations.some(({ signals }) => Object.entries(signals).some(([key, value]) => (
    key === 'automation' ? value !== 'unknown' : key === 'velocity' ? value !== 'unknown' : value !== null
  )));

  const risk = hasHigh ? 'high' : hasMedium ? 'medium' : hasKnownSignal ? 'low' : 'unknown';
  const recommendation = risk === 'high'
    ? 'contain_or_step_up'
    : risk === 'medium'
      ? 'step_up'
      : risk === 'low'
        ? 'continue'
        : 'manual_review';

  return Object.freeze({
    schema: DEVICE_ASSESSMENT_SCHEMA,
    deviceRef: observations[0].deviceRef,
    risk,
    recommendation,
    reasons: Object.freeze([...reasons].sort()),
    providers: Object.freeze([...new Set(observations.map((observation) => observation.provider))].sort()),
    evidenceRefs: Object.freeze([...new Set(observations.map((observation) => observation.evidenceRef))].sort()),
    confidence: confidences.length ? Math.max(...confidences) : null,
    authority: Object.freeze({ level: 'recommendation_only', canAuthorize: false }),
  });
}
