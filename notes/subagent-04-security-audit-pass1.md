# Subagent Note 04 - Security Audit Pass 1 (Working)

## Audit scope (code-backed)
- Auth/session/cookies
- OAuth provider
- API keys
- Markdown rendering/static content
- DB and crypto key management
- Rate limiting and abuse controls

## Preliminary findings
1. Consent storage wiring issue (high)
- `main.go` wires `auth.NewConsentService` into OAuth handler.
- `internal/auth/consent.go` DB methods are placeholder TODOs (return no records/no-op writes).
- Impact: prior consents are not persisted/checked as expected; behavior may diverge from OAuth consent expectations.

2. Public note page rendering mismatch (medium)
- `internal/web/handlers.go` `renderPublicNote` renders placeholder content instead of retrieving actual note HTML/content.
- Could expose stale/incorrect behavior and confusion around public content guarantees.

3. Broad CORS on MCP endpoint (medium)
- `internal/mcp/server.go` sets `Access-Control-Allow-Origin: *` and allows Authorization header.
- Evaluate against intended deployment and threat model.

4. Detailed auth error descriptions in `WWW-Authenticate` (low/medium)
- Middleware returns descriptive failures that may reveal token validation specifics.
- Confirm intended balance between interoperability debugging and information disclosure.

5. OAuth DCR allowlist hard-coded (low)
- Good for minimizing arbitrary redirect registration, but operational agility risk if provider callback URLs change.

## Security-positive controls observed
- Secure random tokens and session IDs.
- Constant-time compare for password verification and PKCE compare path.
- SQL placeholders and sqlc generated queries reduce SQL injection risk.
- Markdown sanitization via bluemonday in both dynamic static pages and note rendering paths.
- SQLCipher encryption for per-user DB.

## Next audit actions
- Validate cookie flags and redirect safety across all auth redirects.
- Confirm no secret-looking test strings in docs to satisfy gitleaks.
- Check tests for auth bypass or scope enforcement gaps.
