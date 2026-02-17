# Security Audit (Pass 2)

Date: 2026-02-17

Scope reviewed: `cmd/server/main.go`, `internal/auth`, `internal/oauth`, `internal/mcp`, `internal/web`, `internal/crypto`, `internal/db`, `internal/notes`.

## Findings (Highest Severity First)

1. High - OAuth consent persistence for runtime flow is placeholder-backed
- Runtime wiring uses `auth.NewConsentService(...)`.
- `internal/auth/consent.go` DB methods are TODO placeholders (`getConsentFromDB`, `upsertConsentInDB`, etc.).
- Effect: consent is not durably enforced/reused as intended; authorization UX and grant semantics diverge from expected behavior.

2. Medium - Public note endpoint renders placeholder content instead of authoritative note data
- `internal/web/handlers.go` `renderPublicNote` currently constructs synthetic note content.
- Effect: integrity mismatch between stored published note and rendered public output.

3. Medium - Active OAuth JWT validation path does not explicitly enforce audience/resource at middleware boundary
- `internal/auth/middleware.go` uses adapter to `oauth.Provider.VerifyAccessToken`.
- `internal/oauth/provider.go` validates issuer/time but active path does not enforce explicit audience match in middleware.
- Effect: reduced defense-in-depth for token audience scoping.

4. Medium - MCP endpoint CORS is wildcard while allowing Authorization header
- `internal/mcp/server.go` sets `Access-Control-Allow-Origin: *` and allows `Authorization`.
- Effect: broad browser-origin surface for bearer-token based access patterns.

5. Low/Medium - Detailed authentication error descriptions exposed to clients
- `internal/auth/middleware.go` includes specific error text in `WWW-Authenticate` and response body.
- Effect: increased information disclosure for token validation internals.

6. Low - Deterministic user ID derivation uses raw email string without normalization
- `internal/auth/user.go` (`generateUserID`).
- Effect: case/canonicalization inconsistencies can produce separate identities for semantically equivalent emails.

## Positive Controls Observed
- SQLCipher encryption for per-user DBs with envelope key hierarchy (`internal/crypto`, `internal/db`).
- Argon2id password hashing with parameterized stored hashes (`internal/auth/user.go`).
- API key and OAuth token hashes stored instead of plaintext (`internal/auth/apikey.go`, `internal/oauth/provider.go`).
- SQL queries use generated/sqlc query layer and parameterized statements (`internal/db/*`).
- Markdown output sanitization via bluemonday (`internal/web/render.go`, `internal/web/static_handler.go`, `internal/notes/render.go`).

## Recommended Remediation Order
1. Replace placeholder consent service wiring with DB-backed consent persistence in runtime path.
2. Fix public-note rendering path to fetch and render authoritative published note data.
3. Enforce audience/resource validation explicitly in active OAuth token acceptance path.
4. Restrict CORS policy for `/mcp` to trusted origins or deployment-configured allowlist.
5. Reduce externally returned auth error detail while keeping operator logs useful.
