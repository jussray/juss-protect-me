export const PRESSURE_LEVELS = Object.freeze([
  'WATCH',
  'HARDEN',
  'CHALLENGE',
  'DECEIVE',
  'CONTAIN',
  'LOCKDOWN',
]);

const LEVEL_CAPABILITIES = Object.freeze({
  WATCH: ['observe', 'classify'],
  HARDEN: ['observe', 'classify', 'rate_limit', 'require_reauth'],
  CHALLENGE: ['observe', 'classify', 'rate_limit', 'require_reauth', 'active_challenge'],
  DECEIVE: ['observe', 'classify', 'rate_limit', 'require_reauth', 'active_challenge', 'adaptive_decoy', 'canary_activate'],
  CONTAIN: ['observe', 'classify', 'rate_limit', 'active_challenge', 'adaptive_decoy', 'canary_activate', 'block_session', 'isolate_session', 'rotate_session_keys'],
  LOCKDOWN: ['observe', 'classify', 'rate_limit', 'active_challenge', 'adaptive_decoy', 'canary_activate', 'block_session', 'isolate_session', 'rotate_session_keys', 'sinkhole_owned_route'],
});

const FORBIDDEN = Object.freeze([
  'exploit_remote_host',
  'steal_credentials',
  'damage_remote_system',
  'ddos_remote_system',
  'deploy_malware',
  'exfiltrate_remote_data',
]);

function clamp(n, min, max) {
  return Math.min(max, Math.max(min, n));
}

export function calculatePressure({
  pushes,
  confidence,
  automationLikelihood = 0,
  repeatedRouteAbuse = 0,
  evidenceCorroboration = 0,
}) {
  const p = Number.isInteger(pushes) ? pushes : 0;
  const c = clamp(Number(confidence) || 0, 0, 1);
  const automation = clamp(Number(automationLikelihood) || 0, 0, 1);
  const route = clamp(Number(repeatedRouteAbuse) || 0, 0, 1);
  const corroboration = clamp(Number(evidenceCorroboration) || 0, 0, 1);

  const score = (p * 0.9) + (c * 2.0) + (automation * 1.2) + (route * 1.2) + (corroboration * 1.4);
  const index = clamp(Math.floor(score), 0, PRESSURE_LEVELS.length - 1);
  return Object.freeze({ score, level: PRESSURE_LEVELS[index], pushes: p });
}

export function buildCounterPressurePlan({
  pressure,
  expansion,
  authorizationByCapability = {},
  ownedBoundary = true,
}) {
  if (!pressure || !PRESSURE_LEVELS.includes(pressure.level)) throw new Error('valid pressure level is required');
  if (!expansion || !Number.isInteger(expansion.observationUnits) || expansion.observationUnits < 48_000) {
    throw new Error('valid EXPAND budget is required');
  }

  const requested = LEVEL_CAPABILITIES[pressure.level];
  const permitted = [];
  const denied = [];

  for (const capability of requested) {
    const auth = authorizationByCapability[capability];
    if (auth?.authorized === true) permitted.push(capability);
    else denied.push({ capability, reason: auth?.reasons?.[0] ?? 'missing_intent_authority' });
  }

  const active = permitted.filter((capability) => !['observe', 'classify'].includes(capability));
  const attributionGoal = pressure.level === 'WATCH'
    ? 'PRESERVE_UNKNOWN'
    : 'IDENTIFY_TECHNICAL_SESSION';

  return Object.freeze({
    schema: 'protect-me/counter-pressure-plan@v1',
    pressure: pressure.level,
    expansionUnits: expansion.observationUnits,
    attributionGoal,
    ownedBoundaryRequired: true,
    boundarySatisfied: ownedBoundary === true,
    defensivePressure: permitted.filter((c) => ['observe', 'classify', 'rate_limit', 'require_reauth', 'block_session', 'isolate_session', 'rotate_session_keys'].includes(c)),
    activeCounterPressure: ownedBoundary === true ? active.filter((c) => ['active_challenge', 'adaptive_decoy', 'canary_activate', 'sinkhole_owned_route'].includes(c)) : [],
    denied,
    forbiddenRemoteRetaliation: FORBIDDEN,
    state: ownedBoundary === true ? 'READY_WITHIN_AUTHORITY' : 'BOUNDARY_DENIED',
  });
}

export function classifyTechnicalActor({
  botScore = null,
  verifiedAutomation = false,
  interactionSignals = 0,
  corroboratingSignals = 0,
  confidence = 0,
}) {
  const c = clamp(Number(confidence) || 0, 0, 1);
  if (verifiedAutomation === true) {
    return Object.freeze({ actorClass: 'ROBOT_OR_AUTOMATION', confidence: Math.max(c, 0.95), realWorldIdentity: 'UNKNOWN' });
  }
  if (Number.isFinite(botScore) && botScore <= 10 && c >= 0.8) {
    return Object.freeze({ actorClass: 'LIKELY_AUTOMATION', confidence: c, realWorldIdentity: 'UNKNOWN' });
  }
  if (interactionSignals >= 3 && corroboratingSignals >= 3 && c >= 0.9) {
    return Object.freeze({ actorClass: 'LIKELY_HUMAN_OPERATOR', confidence: c, realWorldIdentity: 'UNKNOWN' });
  }
  return Object.freeze({ actorClass: 'UNKNOWN', confidence: c, realWorldIdentity: 'UNKNOWN' });
}
