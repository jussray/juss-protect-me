/**
 * Muse provider for Juss Protect Me (Model One) — WORKER-SIDE ONLY. DRAFT.
 *
 * Semantics mirror the Founder Control Room reference adapter
 * (src/lib/operatorRelayMuseProvider.ts):
 * - server-side only; secret read from env.MODEL_API_KEY, never serialized;
 * - endpoint https://api.meta.ai/v1/responses, POST {model, input, store:false,
 *   max_output_tokens:2000}, 60s timeout, 64 KiB response cap;
 * - model allow-list /^muse-spark-1\.(?:1|2|3)$/ via PROTECT_ME_MUSE_MODEL;
 * - returns undefined (provider not advertised) when the key or a safe model
 *   is missing — never a fabricated answer;
 * - sensitivity 'restricted' is rejected before any network call;
 * - provider error bodies are never promoted; errors are sanitized codes;
 * - success carries evidenceRef 'provider:meta:<id>' and authority 'none'.
 *
 * State ceiling: INTEGRATED. VERIFIED requires a real Muse request at the
 * exact repo/branch/SHA/deployment with the receipt recorded.
 * This module is not imported by the public page (public/ stays scriptless).
 */

const MUSE_RESPONSES_URL = 'https://api.meta.ai/v1/responses';
const PROVIDER_TIMEOUT_MS = 60_000;
const MAX_RESPONSE_BYTES = 64 * 1024;
const MAX_RESPONSE_ID_LENGTH = 200;
const MAX_PROMPT_CHARS = 12_000;
const SAFE_MUSE_MODEL = /^muse-spark-1\.(?:1|2|3)$/;

export const MUSE_MODEL_ENV = 'PROTECT_ME_MUSE_MODEL';

function safeModel(value) {
  const normalized = typeof value === 'string' ? value.trim() : '';
  return SAFE_MUSE_MODEL.test(normalized) ? normalized : null;
}

export function museProviderState(env = {}) {
  const configured = Boolean(String(env.MODEL_API_KEY ?? '').trim()) && safeModel(env[MUSE_MODEL_ENV]) !== null;
  return Object.freeze({
    provider: 'muse',
    state: configured ? 'PRESENT' : 'ABSENT',
    model: safeModel(env[MUSE_MODEL_ENV]),
    authority: 'none',
  });
}

async function boundedResponseText(response) {
  const contentLength = response.headers.get('content-length');
  if (contentLength) {
    const declaredBytes = Number(contentLength);
    if (Number.isFinite(declaredBytes) && declaredBytes > MAX_RESPONSE_BYTES) {
      try { await response.body?.cancel(); } catch { /* size verdict stands */ }
      throw new Error('muse_response_too_large');
    }
  }
  if (!response.body) return '';
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let bytesRead = 0;
  let text = '';
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytesRead += value.byteLength;
      if (bytesRead > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error('muse_response_too_large');
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    return text;
  } finally {
    reader.releaseLock();
  }
}

function validResponseId(body) {
  const id = typeof body?.id === 'string' ? body.id.trim() : '';
  return id && id.length <= MAX_RESPONSE_ID_LENGTH && /^[A-Za-z0-9._:-]+$/.test(id) ? id : null;
}

function extractText(body) {
  if (typeof body.output_text === 'string' && body.output_text.trim()) return body.output_text.trim();
  const parts = [];
  for (const item of Array.isArray(body.output) ? body.output : []) {
    if (!item || typeof item !== 'object' || item.type !== 'message') continue;
    for (const entry of Array.isArray(item.content) ? item.content : []) {
      if (entry && typeof entry === 'object' && entry.type === 'output_text'
        && typeof entry.text === 'string' && entry.text.trim()) {
        parts.push(entry.text.trim());
      }
    }
  }
  return parts.join('\n');
}

export async function invokeMuse(env = {}, input = {}, fetchImpl = fetch) {
  const prompt = typeof input.prompt === 'string' ? input.prompt.trim() : '';
  if (!prompt || prompt.length > MAX_PROMPT_CHARS) throw new Error('invalid_prompt');
  if (String(input.sensitivity ?? 'standard').trim().toLowerCase() === 'restricted') {
    throw new Error('restricted_not_authorized');
  }
  const apiKey = String(env.MODEL_API_KEY ?? '').trim();
  const model = safeModel(env[MUSE_MODEL_ENV]);
  if (!apiKey || !model) throw new Error('muse_not_configured');

  let response;
  try {
    response = await fetchImpl(MUSE_RESPONSES_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ model, input: prompt, store: false, max_output_tokens: 2_000 }),
      redirect: 'error',
      signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS),
    });
  } catch {
    throw new Error('muse_request_failed');
  }
  if (!response.ok) {
    try { await response.body?.cancel(); } catch { /* error bodies are never promoted */ }
    throw new Error(`muse_http_${response.status}`);
  }
  const raw = await boundedResponseText(response);
  let body;
  try { body = JSON.parse(raw); } catch { throw new Error('muse_invalid_json'); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('muse_invalid_response');
  if (body.status !== 'completed') throw new Error('muse_non_completed');
  const responseId = validResponseId(body);
  if (!responseId) throw new Error('muse_invalid_response_id');
  const text = extractText(body);
  if (!text) throw new Error('muse_empty_response');
  return Object.freeze({
    state: 'INTEGRATED',
    provider: 'muse',
    model,
    responseId,
    evidenceRef: `provider:meta:${responseId}`,
    authority: 'none',
    text,
  });
}

export function createMuseProvider(env = {}, fetchImpl = fetch) {
  if (museProviderState(env).state !== 'PRESENT') return undefined;
  return Object.freeze({
    provider: 'muse',
    authority: 'none',
    invoke: (input) => invokeMuse(env, input, fetchImpl),
  });
}
