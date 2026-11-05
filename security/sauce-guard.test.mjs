import test from 'node:test';
import assert from 'node:assert/strict';
import { assessSauceGuard, securityCapabilities } from './sauce-guard.mjs';

const review = (scope, overrides = {}) => assessSauceGuard({
  scope, audience: 'public', content: 'We improved user-facing safety.',
  claims: [{ state: 'CURRENT', evidenceRef: 'proof://approved/public/123' }], ...overrides,
});
for (const scope of ['personal', 'infrastructure']) {
  test(scope + ': proven public claim is reviewable, never publication authorization', () => {
    const out = review(scope);
    assert.equal(out.disposition, 'REVIEW');
    assert.equal(out.permittedToPublish, false);
    assert.equal(out.requiresProviderReadback, true);
    assert.deepEqual(out.findings, []);
  });
  test(scope + ': credential pattern is blocked and content is never reflected', () => {
    const secret = 'ghp_' + 'Z'.repeat(30);
    const out = review(scope, { content: 'Publish this: ' + secret });
    assert.equal(out.disposition, 'BLOCK');
    assert.ok(out.findings.includes('credential'));
    assert.equal(JSON.stringify(out).includes(secret), false);
  });
  test(scope + ': personal customer data and private implementation blocked', () => {
    const out = review(scope, { content: 'Customer: alice@example.org', flags: { privateImplementation: true } });
    assert.deepEqual(out.findings, ['private_email', 'private_implementation']);
  });
  test(scope + ': stale unknown and invalid claims fail closed', () => {
    for (const state of ['STALE', 'UNKNOWN', 'SUPERSEDED', 'bogus']) {
      assert.equal(review(scope, { claims: [{ state }] }).disposition, 'BLOCK');
    }
  });
  test(scope + ': CURRENT requires evidence; HISTORICAL requires date', () => {
    assert.ok(review(scope, { claims: [{ state: 'CURRENT' }] }).findings.includes('claim_missing_evidence'));
    assert.ok(review(scope, { claims: [{ state: 'HISTORICAL' }] }).findings.includes('historical_date_missing'));
  });
  test(scope + ': unclassified publication and oversized input fail closed', () => {
    assert.ok(review(scope, { claims: [] }).findings.includes('claims_unreviewed'));
    assert.ok(review(scope, { content: 'x'.repeat(40_000) }).findings.includes('content_too_large'));
  });
  test(scope + ': private input still screens obvious secrets', () => {
    assert.equal(assessSauceGuard({ scope, audience: 'private', content: 'A normal private note.' }).disposition, 'REVIEW');
    assert.equal(assessSauceGuard({ scope, audience: 'private', content: 'password=not-for-display' }).disposition, 'BLOCK');
  });
  test(scope + ': no fabricated live telemetry', () => {
    assert.equal(securityCapabilities(scope).liveThreatTelemetry, 'UNKNOWN');
  });
}
test('invalid scope and audience fail closed', () => {
  assert.ok(assessSauceGuard({ scope: 'both', audience: 'public', content: 'test' }).findings.includes('invalid_scope'));
  assert.ok(assessSauceGuard({ scope: 'personal', audience: 'worldwide', content: 'test' }).findings.includes('invalid_audience'));
});
