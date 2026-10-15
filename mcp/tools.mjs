import { evaluateThreat, authorizeRecommendedAction, THREAT_KINDS } from '../src/model-one.mjs';
import { assertPrivateContentAbsent } from '../src/evidence-privacy.mjs';
const annot = Object.freeze({ readOnlyHint: true, destructiveHint: false, openWorldHint: false });
function keysOnly(args) {
  if (!args || !Array.isArray(args.keys) || args.keys.length > 32) throw new Error('invalid input');
  let blocked = 0;
  for (const key of args.keys) {
    if (typeof key !== 'string' || !/^[a-zA-Z][a-zA-Z0-9_]{0,63}$/.test(key)) throw new Error('invalid key');
    try { assertPrivateContentAbsent({ [key]: 'placeholder' }); }
    catch { blocked++; }
  }
  return { state: blocked ? 'BLOCKED' : 'NO_KNOWN_SENSITIVE_FIELD', checked: args.keys.length,
    blockedCount: blocked, guarantee: false, inputReflected: false };
}
export const mcpApplication = Object.freeze({
  name: 'juss-protect-me-model-one',
  tools: [
    { name: 'protect_me_status', title: 'Protect Me status',
      description: 'Report Model One capability boundaries. No device monitoring or chat access.',
      annotations: annot, inputSchema: { type: 'object', additionalProperties: false, properties: {} } },
    { name: 'protect_me_assess_threat', title: 'Threat recommendation',
      description: 'Evaluate structured threat metadata only. Do not send raw text, identities, or credentials. This does not take action.',
      annotations: annot, inputSchema: { type: 'object', additionalProperties: false, required: ['kind','severity','confidence'],
        properties: { kind: { type:'string', enum: THREAT_KINDS }, severity: { type:'string', enum:['low','medium','high','critical'] }, confidence:{type:'number',minimum:0,maximum:1} } } },
    { name: 'protect_me_evidence_keys', title: 'Evidence field-name screening',
      description: 'Screen field NAMES only (never field values) for known sensitive data labels.',
      annotations: annot, inputSchema: { type:'object', additionalProperties:false, required:['keys'],
        properties: { keys:{type:'array',maxItems:32,items:{type:'string',maxLength:64}} } } },
  ],
  handlers: {
    protect_me_status(args) {
      if (!args || typeof args !== 'object' || Array.isArray(args) || Object.keys(args).length) throw new Error('bad input');
      return { system:'Model One', status:'KERNEL_ONLY', chatHistoryAccess:false,
        deviceSensorConnected:false, automaticProtection:false, evidenceIsAuthority:false };
    },
    protect_me_assess_threat(args) {
      if (!args || typeof args !== 'object' || Array.isArray(args) ||
          Object.keys(args).sort().join(',') !== 'confidence,kind,severity') throw new Error('bad input');
      const e = {kind:args.kind,severity:args.severity,confidence:args.confidence,summary:'Structured threat metadata only.'};
      const recommendation = evaluateThreat(e);
      const authorization = authorizeRecommendedAction(recommendation, {autoActions:[]});
      return {recommendation:recommendation.action, reason:recommendation.reason,confidence:recommendation.confidence,
        mayAutomaticallyContain:false, requiresSeparateAuthorization:true,
        policyPermitsAction:authorization.authorized && ['notify','manual_review'].includes(recommendation.action)};
    },
    protect_me_evidence_keys: keysOnly,
  },
});
