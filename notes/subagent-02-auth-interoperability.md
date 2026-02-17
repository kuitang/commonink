# Subagent Note 02 - Auth and Interoperability (Working Draft)

## Authentication methods supported by runtime
- Session-cookie auth (`session_id`) for web and JSON APIs.
- Bearer API keys (`agentnotes_key_{user_id}_{token}`) validated against per-user DB.
- Bearer OAuth JWT access tokens validated by OAuth provider verifier (Ed25519 JWT).

## OAuth provider behavior from code
- Authorization server metadata advertises:
  - grant types: `authorization_code`, `refresh_token`
  - response type: `code`
  - PKCE method: `S256`
  - token auth methods: `client_secret_post`, `client_secret_basic`, `none`
- Protected resource metadata advertises scopes `notes:read` and `notes:write`.
- JWT access token claims include `sub`, `aud`, `iss`, `scope`, `client_id`, and standard lifetime claims.
- Access token lifetime default: 1 hour.
- Refresh token lifetime default: 30 days.
- Authorization code lifetime default: 10 minutes.
- Token and code values are hashed with SHA-256 in DB (hash lookup storage design).

## DCR specifics
- Endpoint: `POST /oauth/register`.
- Redirect URI allowlist hard-coded for ChatGPT and Claude callback URLs plus localhost test callbacks.
- Supports public clients (`token_endpoint_auth_method=none`) and confidential clients (`client_secret_post`/`client_secret_basic`).

## Authorization endpoint behavior
- Requires `client_id`, `redirect_uri`, `response_type`, `state`, `code_challenge`, `code_challenge_method`.
- Enforces `response_type=code` and `code_challenge_method=S256`.
- Validates client and exact redirect URI.
- Validates optional `resource` equals server resource (or `/mcp` suffix variant).
- If unauthenticated, redirects to `/login?return_to=<original authorize URL>`.
- If authenticated and consent exists, issues code and redirects.
- Else renders consent page and stores request in short-lived cookie.

## Token endpoint behavior
- Supports form and JSON payloads.
- Supports client auth via body params and HTTP Basic.
- Public client path:
  - requires code verifier
  - rejects client_secret usage
- Confidential client path:
  - requires and verifies client_secret.
- Refresh grant enforces client matching and rotates tokens by deleting old token row then minting new pair.

## Interop gaps/risks to capture in final AUTH.md
- Consent persistence is effectively not wired in current server setup (`auth.ConsentService` TODO stubs in use).
- Public note and consent UX have partial placeholder paths; needs explicit status callout in docs.
- MCP top-level route explicitly returns 405 for GET/DELETE even though SDK handler supports streamable patterns; this is deliberate stateless shape and should be documented clearly.
