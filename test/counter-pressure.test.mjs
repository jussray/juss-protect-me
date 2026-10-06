import assert from 'node:assert/strict';
import test from 'node:test';

import { buildCounterPressurePlan, calculatePressure, classifyTechnicalActor } from '../src/counter-pressure.mjs';

const expansion = { observationUnits: 48_777 };
const yes = { authorized: true };
const no = { authorized: false, reasons: ['action_outside_intent'] };

test('pressure rises as attacker pushes and evidence converges', () => {
  const low = calculatePressure({ pushes: 0, confidence: 0.2 });
  const high = calculatePressure({
    pushes: 4,
    confidence: 0.98,
    automationLikelihood: 0.9,
    repeatedRouteAbuse: 1,
    evidenceCorroboration: 1,
  });
  assert.equal(low.level, 'WATCH');
  assert.equal(['CONTAIN', 'LOCKDOWN'].includes(high.level), true);
  assert.equal(high.score > low.score, true);
});

test('active counter-pressure requires intent-bound authority per capability', () => {
  const pressure = { level: 'DECEIVE' };
  const plan = buildCounterPressurePlan({
    pressure,
    expansion,
    authorizationByCapability: {
      observe: yes,
      classify: yes,
      rate_limit: yes,
      require_reauth: yes,
      active_challenge: yes,
      adaptive_decoy: yes,
      canary_activate: no,
    },
  });
  assert.equal(plan.activeCounterPressure.includes('active_challenge'), true);
  assert.equal(plan.activeCounterPressure.includes('adaptive_decoy'), true);
  assert.equal(plan.activeCounterPressure.includes('canary_activate'), false);
  assert.equal(plan.denied.some((x) => x.capability === 'canary_activate'), true);
});

test('counter-pressure cannot leave the owned boundary', () => {
  const pressure = { level: 'LOCKDOWN' };
  const auth = Object.fromEntries([
    'observe','classify','rate_limit','active_challenge','adaptive_decoy','canary_activate',
    'block_session','isolate_session','rotate_session_keys','sinkhole_owned_route',
  ].map((x) => [x, yes]));
  const plan = buildCounterPressurePlan({
    pressure,
    expansion,
    authorizationByCapability: auth,
    ownedBoundary: false,
  });
  assert.equal(plan.state, 'BOUNDARY_DENIED');
  assert.deepEqual(plan.activeCounterPressure, []);
  assert.equal(plan.forbiddenRemoteRetaliation.includes('exploit_remote_host'), true);
});

test('identification distinguishes technical actor class without inventing a real-world identity', () => {
  const robot = classifyTechnicalActor({ verifiedAutomation: true, confidence: 0.7 });
  assert.equal(robot.actorClass, 'ROBOT_OR_AUTOMATION');
  assert.equal(robot.realWorldIdentity, 'UNKNOWN');

  const human = classifyTechnicalActor({
    interactionSignals: 5,
    corroboratingSignals: 4,
    confidence: 0.95,
  });
  assert.equal(human.actorClass, 'LIKELY_HUMAN_OPERATOR');
  assert.equal(human.realWorldIdentity, 'UNKNOWN');
});
