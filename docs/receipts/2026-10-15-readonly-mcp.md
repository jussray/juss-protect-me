# Read-only MCP integration receipt

RECEIPT-ID: 2026-10-15-readonly-mcp-one
CREATED-AT: 2026-10-15
REPO: jussray/juss-protect-me
BRANCH: fix/privacy-safe-evidence-20261015
CODE-CANDIDATE: c1fb88c1e88b8ef1ac343615b2361e3c2a60d621
SCOPE: Model One; independently named product, no cross-product authorization

## VERIFIED
- `mcp/protocol.mjs`, `mcp/tools.mjs`, `mcp/worker.mjs`, `mcp/protocol.test.mjs`, and `wrangler.mcp.jsonc` committed on the existing privacy branch.
- Server disabled by default; bearer token length check and Origin allowlist implemented; read-only tools with no external writes.
- 8/8 isolated MCP protocol tests; threat recommendation and evidence field screening exercised.
- No private chat transcripts, real credentials, or user data used as test fixtures.

## UNKNOWN / BLOCKED
- Node.js `npm test` and exact-head GitHub Actions not yet run.
- Cloudflare runtime / endpoint not deployed or independently inspected.
- No bearer secret provisioned by this work and no ChatGPT custom plugin registered.
- Remote ChatGPT availability depends on account / workspace capabilities.
- This is not monitoring of ChatGPT conversations or OpenAI's infrastructure.

## RISK
- Transport security requires live provider readback and runtime tests with a protected endpoint.
- Pattern-based evidence screening is not complete sensitive-data prevention.
- An MCP tool call cannot protect messages that were never routed through it.

## ROLLBACK
Revert focused MCP commits or discard this branch; do not modify `main` until exact-head verification and founder authorization. Keep `MCP_ENABLED=false` until those gates pass.

## NEXT GATE
Run exact-head Node CI and authenticated HTTP smoke tests; review security and deployment identity; only then authorize protected rollout and optional plugin registration.

## Follow-up security verification and identity gate (2026-10-15)

- PROOF: Protect Me Model One branch code at a2a11ef22dac5fb2bd667577590c22ff7988fdae passed its entire recorded GitHub Actions workflow: https://github.com/jussray/juss-protect-me/actions/runs/38826033389.
- CONTINUITY: No branch/main divergence in the previous comparison. Existing Cloudflare Worker is not an active MCP service.
- IMPLEMENTED: read-only MCP protocol/Worker handlers and privacy rejection tests remain disabled for production by `MCP_ENABLED=false`.
- RISK: a static, server-wide `MCP_BEARER_TOKEN` is not a user-bound OAuth access token. Do **not** claim ChatGPT plugin readiness, account ownership verification, or chat confidentiality from this implementation.
- CANDIDATE IDENTITY: Existing Founder Control Room Supabase project is active, and current Supabase documentation describes an OAuth 2.1 server suitable for MCP; its enabled state, consent UI, token issuer, audience, project suitability, and cost impact have not been verified.
- AUTH GATE: before any public endpoint, require an established OAuth 2.1 provider, PKCE authorization-code flow, user approval, resource metadata, asymmetric signed-token validation (JWKS), issuer/audience/expiry/scope checks, separate MCP product permissions, and real client revocation proof. Never authorize access from user-editable metadata or a receipt.
- PROOF GATE: test the **final exact branch head** using GitHub CI, inspect deployment identity, run an authenticated/unauthed HTTP smoke, validate tool schema discovery and client consent/revocation, then seek founder approval for deployment and plugin registration.
- ROLLBACK: this branch is isolated. Do not change production `main`, Cloudflare runtime, account access, or Supabase Auth settings as part of this receipt.
- CURRENT RECEIPT STATE: INFERRED continuity text until a receipt checker establishes a valid chain; referenced GitHub CI is independently VERIFIED for its stated commit.
