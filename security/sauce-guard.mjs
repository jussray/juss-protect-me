// Sauce Guard Security v1: a non-authorizing outbound-content security boundary.
// Shared policy contract for Protect Me Model One (personal) and Model Two (infrastructure).
// The canonical founder publication policy remains FCR's sauce-guard SKILL.md.
export const SAUCE_GUARD_VERSION = 'sauce-guard/security@1';
export const SAUCE_SCOPES = Object.freeze(['personal', 'infrastructure']);
const STATES = new Set(['CURRENT', 'HISTORICAL', 'STALE', 'SUPERSEDED', 'UNKNOWN']);
const PUBLIC = new Set(['public', 'external']);
const MAX_CONTENT = 32_768;

// Pattern screening is one layer. It never proves that arbitrary text is safe.
const SENSITIVE_PATTERNS = Object.freeze([
  ['private_key', /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/i],
  ['credential', /\b(?:github_pat_[a-z0-9_]{16,}|gh[pousr]_[a-z0-9_]{20,}|(?:sk|rk)_(?:live|test)_[a-z0-9]{12,}|AKIA[A-Z0-9]{16})\b/i],
  ['credential_assignment', /\b(?:api[_-]?key|client[_-]?secret|password|passwd|authorization|access[_-]?token|bearer)\s*[:=]\s*["']?[^\s"']{8,}/i],
]);
const PII_PATTERNS = Object.freeze([
  ['private_email', /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i],
  ['social_security_number', /\b\d{3}-\d{2}-\d{4}\b/],
]);

function normalize(value) {
  return String(value ?? '').normalize('NFKC').replace(/[\u200b-\u200d\u2060\ufeff]/g, '');
}
function codesFor(content, patterns) {
  return patterns.filter(([, pattern]) => pattern.test(content)).map(([code]) => code);
}

/**
 * Source-level inspection, not publication authorization, antivirus, DLP completeness,
 * independent proof, or a live monitoring claim. Never returns raw content.
 */
export function assessSauceGuard({ scope, audience = 'internal', content, claims = [], flags = {} } = {}) {
  const reasons = [];
  if (!SAUCE_SCOPES.includes(scope)) reasons.push('invalid_scope');
  if (!['internal', 'private', 'public', 'external'].includes(audience)) reasons.push('invalid_audience');
  if (typeof content !== 'string' || !content.trim()) reasons.push('missing_content');
  const normalized = normalize(content);
  if (normalized.length > MAX_CONTENT) reasons.push('content_too_large');
  reasons.push(...codesFor(normalized, SENSITIVE_PATTERNS));
  const isExternal = PUBLIC.has(audience);
  if (isExternal) {
    reasons.push(...codesFor(normalized, PII_PATTERNS));
    if (flags.privateImplementation === true) reasons.push('private_implementation');
    if (flags.privateMetrics === true) reasons.push('private_metrics');
    if (flags.customerData === true) reasons.push('customer_data');
    if (!Array.isArray(claims)) reasons.push('invalid_claims');
    else {
      for (const claim of claims) {
        if (!claim || !STATES.has(claim.state)) { reasons.push('unclassified_claim'); continue; }
        if (['UNKNOWN', 'STALE', 'SUPERSEDED'].includes(claim.state)) reasons.push('claim_not_current');
        if (claim.state === 'CURRENT' && !(typeof claim.evidenceRef === 'string' && claim.evidenceRef.trim())) reasons.push('claim_missing_evidence');
        if (claim.state === 'HISTORICAL' && !(typeof claim.asOf === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(claim.asOf) && Number.isFinite(Date.parse(claim.asOf)))) reasons.push('historical_date_missing');
      }
    }
    if (!claims.length) reasons.push('claims_unreviewed');
  }
  const findings = Object.freeze([...new Set(reasons)].sort());
  return Object.freeze({
    schema: SAUCE_GUARD_VERSION,
    scope: SAUCE_SCOPES.includes(scope) ? scope : 'unknown',
    audience: ['internal', 'private', 'public', 'external'].includes(audience) ? audience : 'unknown',
    disposition: findings.length ? 'BLOCK' : 'REVIEW',
    findings,
    permittedToPublish: false,
    requiresIndependentApproval: isExternal,
    requiresProviderReadback: isExternal,
  });
}

export function securityCapabilities(scope) {
  if (!SAUCE_SCOPES.includes(scope)) throw new TypeError('unknown protection scope');
  return Object.freeze({
    schema: SAUCE_GUARD_VERSION,
    scope,
    contentEgress: 'SOURCE_IMPLEMENTED',
    secretPatternScreen: 'SOURCE_IMPLEMENTED',
    evidenceClassification: 'SOURCE_IMPLEMENTED',
    liveThreatTelemetry: 'UNKNOWN',
    productionProtection: 'UNKNOWN',
    isolation: 'independent-per-product',
  });
}
