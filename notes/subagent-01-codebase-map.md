# Subagent Note 01 - Codebase Map (Working Draft)

## Scope
- Read `AGENTS.md`/`CLAUDE.md` and `spec.md` fully.
- Validate runtime behavior from code first: `cmd/server/main.go`, `internal/web`, `internal/auth`, `internal/oauth`, `internal/mcp`, `internal/notes`, `internal/db`, `internal/crypto`, `internal/ratelimit`.

## High-confidence runtime architecture
- Entry point: `cmd/server/main.go`.
- Config: `internal/config/config.go`.
- Persistence model:
  - Shared unencrypted DB: `sessions.db` for sessions, OAuth clients/tokens/codes, magic tokens, user key envelopes, consent records, short URLs.
  - Per-user encrypted DB: `{user_id}.db` for account row, notes, FTS index, API keys.
- Per-request user DB open path:
  - `auth.Middleware` validates session/API key/OAuth JWT.
  - It derives/loads DEK through `crypto.KeyManager` and opens SQLCipher DB via `db.OpenUserDBWithDEK`.

## Actual server routes (from code)
- OAuth metadata:
  - `GET /.well-known/oauth-protected-resource`
  - `GET /.well-known/oauth-authorization-server`
  - `GET /.well-known/jwks.json`
  - plus `/mcp` subpath metadata variants.
- OAuth endpoints:
  - `POST /oauth/register` (DCR)
  - `GET /oauth/authorize`
  - `POST /oauth/consent`
  - `POST /oauth/token`
- Auth endpoints:
  - `GET|POST /auth/google`
  - `GET /auth/google/callback`
  - `POST /auth/magic`
  - `GET /auth/magic/verify`
  - `POST /auth/register`
  - `POST /auth/login`
  - `POST /auth/password-reset`
  - `POST /auth/password-reset-confirm`
  - `GET|POST /auth/logout`
  - `GET /auth/whoami`
- Web app routes:
  - `GET /`, `/login`, `/register`, `/password-reset`, `/auth/password-reset-confirm`
  - notes CRUD form routes `/notes*`
  - public note paths `/public/{user_id}/{note_id}` and `/pub/{short_id}`
  - API key settings routes under `/settings/api-keys` and `/api-keys` aliases
  - OAuth consent page route `GET /oauth/consent`
- Static markdown-backed pages:
  - `/privacy`, `/terms`, `/about`, `/docs/api`, `/docs`
  - raw markdown suffix routes also supported (`.md` and Accept negotiation)
  - install template route `/docs/install`
- JSON APIs:
  - protected notes API under `/api/notes*`
  - API keys JSON API under `/api/keys*`
  - MCP endpoint `POST /mcp` (GET/DELETE return 405 in top-level mux)

## Notable code/spec drift already confirmed
- `spec.md` still documents several flows that are not implemented as written.
- Public note web render currently uses placeholder note content in `internal/web/handlers.go` (`renderPublicNote`) instead of reading from storage.
- Consent service injected from `auth.NewConsentService` is placeholder/no-op backed (`internal/auth/consent.go` TODO methods), while a DB-backed consent implementation exists in `internal/oauth/handlers.go` (`ConsentDBService`) but is not wired in `main.go`.
- MCP handler uses go-sdk Streamable HTTP in stateless mode, JSON responses enabled.

## Next extraction work
- Map exact auth interoperability details (DCR allowlist, token auth methods, PKCE requirements).
- Map crypto design and risk assessment from implemented code.
- Build list of markdown files safe to delete vs runtime required.
