// Presentation-only Sauce Guard check. Publication authority stays with:
// jussray/founder-control-room/.agents/skills/sauce-guard/SKILL.md
// This test cannot approve publication or grant protection authority.
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

test('Sauce Guard prevents private links and obvious credentials in public markup', () => {
  const links = [...html.matchAll(/href="([^"]+)"/g)].map((match) => match[1]);
  for (const link of links) {
    assert.ok(
      link === '/' || link.startsWith('#')
        || link === 'https://protect.jussco.company'
        || link === 'https://protect2.jussco.company',
      'External or internal-only links must not appear in public welcome markup',
    );
  }
  assert.doesNotMatch(html, /(?:ghp_|github_pat_|sk-proj-|AIzaSy|-----BEGIN [A-Z ]*PRIVATE KEY-----|CF_API_TOKEN|SUPABASE_SERVICE_ROLE_KEY|SHIELD_SECRET|[/]\.env|[/]internal[/]|[/]admin[/])/i);
});
