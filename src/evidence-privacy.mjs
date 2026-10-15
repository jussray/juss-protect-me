const PRIVATE_TEXT_PATTERNS = Object.freeze([
  /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/i,
  /\b(?:bearer\s+[A-Z0-9._~+/-]{8,}|(?:password|passcode|(?:api|client|app|consumer)[_-]?(?:secret|key|token)|private[_-]?key|access[_-]?(?:token|key)|refresh[_-]?token|authorization|set[_-]?cookie|cookie|session[_-]?(?:token|key)|secret|credential)\s*[:=]\s*["']?\S{4,})/i,
  /\b(?:sk-(?:proj-)?[A-Z0-9_-]{12,}|gh[pousr]_[A-Z0-9_]{12,}|github_pat_[A-Z0-9_]{12,}|xox[baprs]-[A-Z0-9-]{8,})\b/i,
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i,
  /\b(?:\d{1,3}\.){3}\d{1,3}\b/,
  /(?:^|\n)\s*(?:system|developer|user|assistant)\s*:/i,
  /["']role["']\s*:\s*["'](?:system|developer|user|assistant)["']/i,
  /\b\d{3}-\d{2}-\d{4}\b/,
]);
const SENSITIVE_FIELD_KEY = /(?:^|_)(?:password|passcode|secret|token|cookie|authorization|credential|api_key|private_key|access_key|session_key|email|raw_ip|ip_address|ssn|social_security_number|birth_date|dob|chat_history|conversation|transcript|private_message)(?:_|$)/;
function isSensitiveKey(key) {
  const normalized = key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[-.\s]+/g, '_').toLowerCase();
  return SENSITIVE_FIELD_KEY.test(normalized);
}

/**
 * Reject obvious private content before it is copied into a durable evidence receipt.
 * This is defense in depth, not a full PII classifier or chat storage control.
 * Never include rejected values in errors, logs, or receipt metadata.
 */
export function assertPrivateContentAbsent(value) {
  if (typeof value === 'string') {
    if (PRIVATE_TEXT_PATTERNS.some((pattern) => pattern.test(value))) {
      throw new Error('private content is forbidden in evidence');
    }
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if (key === 'role' && typeof child === 'string' && /^(?:system|developer|user|assistant)$/i.test(child)) {
      throw new Error('private conversation content is forbidden in evidence');
    }
    if (isSensitiveKey(key)) throw new Error('raw sensitive field is forbidden in evidence');
    assertPrivateContentAbsent(child);
  }
}
