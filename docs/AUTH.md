# common.ink AUTH

## Scope
This document describes the authentication and authorization behavior implemented in code today, and maps it to interoperability requirements for ChatGPT connectors, Claude remote MCP connectors, and standards-based OAuth clients.

Code references:
- `internal/auth`
- `internal/oauth`
- `internal/mcp`
- `cmd/server/main.go`

## Auth Modes Implemented

### 1. Session Cookie Auth (Web UX)
- Cookie name: `session_id`
- Flags: `HttpOnly`, `SameSite=Lax`, `Secure` (disabled only for localhost HTTP)
- Session TTL: 30 days
- Used by web routes and can also authenticate `/mcp` and JSON APIs via middleware

Code: `internal/auth/session.go`, `internal/auth/middleware.go`.

### 2. API Key Bearer Auth
- Header: `Authorization: Bearer agentnotes_key_{user_id}_{token}`
- Stored secret form: SHA-256 hash of token part (never plaintext)
- Validation path opens user DB by parsed `user_id`, then validates hash and expiry

Code: `internal/auth/apikey.go`, `internal/auth/middleware.go`.

### 3. OAuth JWT Bearer Auth
- Header: `Authorization: Bearer <access_token>`
- Access token verification delegated to OAuth provider verifier adapter
- Claims used by app auth context: `sub` (user), `client_id`, `scope`

Code: `cmd/server/main.go`, `internal/oauth/provider.go`, `internal/auth/middleware.go`.

## User Authentication Flows

### Google OIDC
- Uses Google as OIDC provider with scopes: `openid email profile`
- OIDC state kept in cookie (`oauth_state`) for CSRF defense
- Exchanges auth code for ID token, verifies claims, then creates/links local account and session

Code: `internal/auth/oidc_google.go`, `internal/auth/handlers.go`.

### Magic Link
- `POST /auth/magic` issues one-time token (15 min) and emails verification URL
- Verification consumes token and creates session

Code: `internal/auth/user.go`, `internal/auth/handlers.go`.

### Email + Password
- Password hashing uses Argon2id
- Registration and login use form-encoded posts

Code: `internal/auth/user.go`, `internal/auth/handlers.go`.

## OAuth 2.1 Provider (For MCP Clients)

### Metadata and Discovery
Implemented endpoints:
- `GET /.well-known/oauth-protected-resource`
- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/jwks.json`
- Subpath variants (including `/mcp`) and OIDC discovery fallbacks are also registered

Code: `internal/oauth/provider.go`.

This aligns with MCP authorization guidance that the resource server must expose protected-resource metadata and return `WWW-Authenticate` with `resource_metadata` when unauthorized.[1][2][3]

### Dynamic Client Registration (DCR)
- Endpoint: `POST /oauth/register`
- Accepts `none`, `client_secret_post`, `client_secret_basic`
- Redirect URI allowlist enforces known ChatGPT/Claude callback URLs plus localhost test callbacks

Code: `internal/oauth/dcr.go`.

Interop-critical allowlist entries currently include:
- `https://chatgpt.com/connector_platform_oauth_redirect`
- `https://platform.openai.com/apps-manage/oauth`
- `https://claude.ai/api/mcp/auth_callback`
- `https://claude.com/api/mcp/auth_callback`

These match published OpenAI and Anthropic connector flows.[1][4]

### Authorization Endpoint
- Endpoint: `GET /oauth/authorize`
- Requires: `client_id`, `redirect_uri`, `response_type=code`, `state`, `code_challenge`, `code_challenge_method=S256`
- Validates optional `resource` parameter against server resource (`base` or `/mcp` variant)
- If unauthenticated, redirects to `/login?return_to=<original authorize URL>`
- If authenticated and consent exists, issues code; otherwise renders consent page

Code: `internal/oauth/handlers.go`.

### Token Endpoint
- Endpoint: `POST /oauth/token`
- Supports both form body and JSON body
- Supports client auth via body params and HTTP Basic
- `authorization_code` grant:
  - public clients: requires PKCE verifier, rejects client_secret
  - confidential clients: requires verified client_secret
- `refresh_token` grant:
  - verifies client binding
  - rotates refresh token by deleting old token record then issuing new pair

Code: `internal/oauth/handlers.go`, `internal/oauth/provider.go`.

### JWT Access Tokens
- Signed with Ed25519 (`EdDSA`), `kid` published via JWKS
- Standard claims include issuer/audience/expiry and app claims (`scope`, `client_id`, `resource`)

Code: `internal/oauth/provider.go`.

## Conformance Testing Implemented

### End-to-End OAuth Conformance Suite (ChatGPT + Claude)
The repository includes code-level conformance coverage for both client classes:
- `tests/e2e/oauth_auth_test.go`
- `tests/e2e/testutil/server.go`

Implemented flow coverage in `tests/e2e/oauth_auth_test.go`:
- Metadata discovery (`/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`)
- Dynamic Client Registration with client-mode differences:
  - ChatGPT mode: confidential client (`client_secret_post`)
  - Claude mode: public client (`none`, no client secret on token exchange)
- Authorization code + PKCE (`S256`) flow
- Token exchange and MCP bearer-token usage validation
- `WWW-Authenticate` auth-trigger behavior validation
- Negative tests for missing PKCE and invalid redirect URI

Standards-client proof path:
- `tests/e2e/testutil/server.go` uses `golang.org/x/oauth2` for `AuthCodeURL(...)` and `Exchange(...)` with PKCE options to verify compatibility with a standard OAuth client library.[13]

Real client integration coverage:
- `tests/e2e/openai/conformance_test.go` obtains OAuth tokens and runs MCP calls through OpenAI MCP tooling.
- `tests/e2e/claude/conformance_test.go` obtains OAuth tokens and runs MCP calls through Claude CLI MCP tooling.

Operational note:
- `make test` excludes OpenAI/Claude conformance packages by design.
- `make test-full` includes OpenAI and Claude conformance suites and hard-requires `SPRITE_TOKEN` for app deployment conformance.
- Recommended token setup: `export SPRITE_TOKEN="$(flyctl auth token)"`.

### OAuth Smoke Script
- `scripts/oauth-conformance-test.sh` performs endpoint-level OAuth sanity checks and writes a local report under `test-results/oauth-conformance`.
- It is a smoke validator, not a full protocol conformance harness.

## Audience Validation Behavior and Git History

### Current Runtime Behavior
- Runtime MCP auth path is wired through:
  - `cmd/server/main.go` (`OAuthProviderVerifier`)
  - `internal/auth/middleware.go` (`WithOAuthVerifier(...)`)
  - `internal/oauth/provider.go` (`VerifyAccessToken`)
- On that path, JWT verification enforces signature + issuer + time-based claim validation.
- The runtime path does not enforce explicit `aud`/resource matching.

### Strict Audience Verifier Exists But Is Not Runtime-Wired
- `internal/auth/oauth_middleware.go` includes a stricter verifier that explicitly checks `aud` contains expected resource.
- This strict verifier is used in integration test wiring (`tests/e2e/integration_test.go`), not by the top-level production server wiring in `cmd/server/main.go`.

### Git History Findings
- `internal/oauth/provider.go` was introduced in commit `cfcdbf9` (2026-02-02) with `VerifyAccessToken` validating issuer/time but not explicit audience.
- Runtime bearer-token wiring was added in commit `971b4a3` (2026-02-03) and reused `provider.VerifyAccessToken` without adding explicit audience validation.
- No commit in project history explicitly documents removing audience checks for Claude compatibility.

### Server Log Evidence
- `server.log` shows successful OAuth-to-MCP traffic for both `openai-mcp/1.0.0 (ChatGPT)` and `Claude-User` user agents on 2026-02-16.
- No `invalid audience` or equivalent audience-validation failure entries appear in the current log.
- Inference: missing runtime audience enforcement appears to be a gap in current verifier wiring, not a clearly documented Claude-specific requirement in this codebase.

## MCP Interoperability Behavior

### Transport
- Internal MCP server is configured with Streamable HTTP handler (`Stateless: true`, `JSONResponse: true`).
- Top-level router exposes:
- `POST /mcp` (all tools)
- `POST /mcp/notes` (notes toolset)
- `POST /mcp/apps` (apps toolset)
- `GET`/`DELETE` on those routes return `405` in this stateless deployment mode.

Code: `internal/mcp/server.go`, `cmd/server/main.go`.

### 401 Challenge Format
On auth failure, middleware returns `WWW-Authenticate` Bearer challenge including:
- `resource_metadata=".../.well-known/oauth-protected-resource"`
- `error`
- `error_description`

Code: `internal/auth/middleware.go`.

This is required for automatic connector re-auth UX in MCP clients.[1][2][3]

## App Management REST Auth Behavior

The app management REST endpoints use the same auth middleware as notes APIs and therefore support:
- Session cookie (`session_id`)
- API key bearer token (`Authorization: Bearer agentnotes_key_...`)
- OAuth access token bearer (`Authorization: Bearer <JWT>`)

Protected app management routes:
- `GET /api/apps`
- `GET /api/apps/{name}`
- `DELETE /api/apps/{name}`
- `GET /api/apps/{name}/files`
- `GET /api/apps/{name}/files/{path...}`
- `GET /api/apps/{name}/logs`

Operational split:
- REST is read/manage (`/api/apps*`)
- Deployment/execution is MCP-only (`app_create` and `app_bash` on `/mcp/apps` or `/mcp`; use bash heredocs to write files while `BASH_ONLY` is enabled)

## Known Interop Gaps (Current Runtime)
- Consent persistence used by runtime OAuth handler is placeholder-backed, so prior consents are not durably reused.
  - `internal/auth/consent.go`
  - Wiring site: `cmd/server/main.go`
- `/mcp` GET/DELETE are intentionally disabled at the top-level mux, despite internal Streamable HTTP support.
- `/mcp`, `/mcp/notes`, and `/mcp/apps` GET/DELETE are intentionally disabled at the top-level mux, despite internal Streamable HTTP support.
- Redirect allowlist is static; platform callback changes require code update and redeploy.
- Runtime MCP bearer-token path does not enforce explicit `aud`/resource matching, even though strict audience verification code exists in `internal/auth/oauth_middleware.go`.

## Library Dependencies Used for Auth
- Google OIDC client library: `github.com/coreos/go-oidc/v3`.
- OAuth/JWT signing and verification primitives: `github.com/go-jose/go-jose/v3`.
- MCP server SDK: `github.com/modelcontextprotocol/go-sdk/mcp`.

## References
[1] OpenAI Apps SDK - Authentication: https://developers.openai.com/apps-sdk/build/authentication/

[2] MCP specification - Authorization: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization

[3] RFC 6750 (Bearer Token Usage): https://datatracker.ietf.org/doc/html/rfc6750

[4] Anthropic support - Remote MCP connector setup: https://support.anthropic.com/en/articles/11503834-building-custom-connectors-via-remote-mcp-servers

[5] Google Identity - OpenID Connect for web server apps: https://developers.google.com/identity/openid-connect/openid-connect

[6] RFC 9728 (OAuth Protected Resource Metadata): https://datatracker.ietf.org/doc/html/rfc9728

[7] RFC 8414 (OAuth Authorization Server Metadata): https://datatracker.ietf.org/doc/html/rfc8414

[8] RFC 7591 (Dynamic Client Registration): https://datatracker.ietf.org/doc/html/rfc7591

[9] RFC 7636 (PKCE): https://datatracker.ietf.org/doc/html/rfc7636

[10] RFC 8707 (Resource Indicators): https://datatracker.ietf.org/doc/html/rfc8707

[11] RFC 7517 (JWK): https://datatracker.ietf.org/doc/html/rfc7517

[12] RFC 8037 (EdDSA/OKP for JOSE): https://datatracker.ietf.org/doc/html/rfc8037

[13] `golang.org/x/oauth2` package documentation: https://pkg.go.dev/golang.org/x/oauth2
