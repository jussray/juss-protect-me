// Model One receives site-level evidence only, never a device observation.
// Protect Me 2 does not supply consent or device identity. Its classification
// must not silently become a person-level risk score or enforcement authority.
export const EDGE_EVIDENCE_SCHEMA = 'protect-me/edge-evidence@v1';
const SOURCE_SCHEMA = 'protect-me/shield-inspection@v1';
const VERDICTS = new Set(['NORMAL', 'AUTOMATION', 'CLAIMED_CRAWLER', 'VERIFIED_BOT', 'PROBE']);
const ACTIONS = new Set(['pass', 'deny']);
const RECEIPT = /^[0-9a-f]{64}$/;
const KEYS = new Set(['schema', 'action', 'verdict', 'receipt', 'receiptKind']);
const SOURCE = 'juss-protect-me-2';

export async function acceptProtectTwoEvidence(payload, { verifyReceipt, consent } = {}) {
  if (consent !== true) throw new Error('explicit evidence-sharing consent required');
  if (!payload || typeof payload !== 'object' || Array.isArray(payload) ||
      Object.keys(payload).some((key) => !KEYS.has(key)) ||
      payload.schema !== SOURCE_SCHEMA ||
      !ACTIONS.has(payload.action) ||
      !VERDICTS.has(payload.verdict) ||
      payload.receiptKind !== 'hmac-sha256' ||
      !RECEIPT.test(payload.receipt ?? '') ||
      (payload.action === 'deny') !== (payload.verdict === 'PROBE')) {
    throw new Error('invalid or excessive Protect Me 2 evidence');
  }
  // An HMAC-shaped string is not verification. The caller must supply an
  // authenticated verifier bound to the Protect Me 2 signing key.
  if (typeof verifyReceipt !== 'function' || await verifyReceipt(payload) !== true) {
    throw new Error('Protect Me 2 evidence not cryptographically verified');
  }
  return Object.freeze({
    schema: EDGE_EVIDENCE_SCHEMA,
    source: SOURCE,
    verdict: payload.verdict,
    action: payload.action,
    evidenceRef: `shield:hmac-sha256:${payload.receipt}`,
    scope: 'site_traffic',
    authority: Object.freeze({ level: 'evidence_only', canAuthorize: false }),
  });
}
