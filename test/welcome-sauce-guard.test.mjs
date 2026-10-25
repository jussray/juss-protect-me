import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
const REQUIRED_NOTE = /Early-access preview/i;
const OTHER_SITE = 'https://protect2.jussco.company';
const publicCopy = html
  .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
  .replace(/<svg\b[^>]*>[\s\S]*?<\/svg>/gi, ' ')
  .replace(/<[^>]+>/g, ' ')
  .replace(/\s+/g, ' ');

test('Sauce Guard keeps implementation details out of the welcome experience', () => {
  const internalDetails = /\b(?:worker|wrangler|cloudflare|api|endpoint|shield|rate[- ]limit(?:er|ing)?|hmac|sha[- ]?256|github|pipeline|ci\/cd|execution ledger|system prompt|tool call|agent|token|secrets?|gate|attack[- ]?20|architecture|deployment)\b/i;
  assert.equal(internalDetails.test(publicCopy), false, 'Welcome copy must promote user value, not implementation details');
});

test('Sauce Guard preserves honest availability wording', () => {
  assert.match(publicCopy, REQUIRED_NOTE);
  assert.match(html, /name="viewport"/);
  assert.match(html, /Content-Security-Policy/);
  assert.equal(/<script\b/i.test(html), false);
});

test('Welcome navigation is anchored and cross-product discovery remains available', () => {
  assert.match(html, /id="availability"/);
  assert.match(html, /id="(?:promise|vision)"/);
  assert.match(html, /href="#availability"/);
  assert.ok(html.includes(OTHER_SITE));
});
