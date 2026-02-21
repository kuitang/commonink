# common.ink SPEC

## What This App Does
common.ink is an MCP-first notes service with a web UI. It supports:

- Personal notes CRUD and full-text search.
- App deployment workflows on Fly Sprites via MCP (`app_*` tools).
- AI access over MCP (`POST /mcp`) using OAuth Bearer tokens, API keys, or session cookies.
- OAuth 2.1 provider endpoints for external MCP clients (ChatGPT, Claude, local clients).
- Public note publishing with short-link support.
- API key lifecycle management in web UI and JSON API.

Primary runtime entrypoint: `cmd/server/main.go`.

## User Journeys (Current Behavior)

### 1. Human User: Sign In and Use Notes
1. User visits `/` and is routed to `/login` when unauthenticated.
2. User authenticates with one of:
- Google OIDC (`/auth/google`, `/auth/google/callback`)
- Magic link (`POST /auth/magic`, `GET /auth/magic/verify`)
- Email/password (`POST /auth/register`, `POST /auth/login`)
3. Server creates `session_id` cookie and routes user to `/notes`.
4. User creates/edits/deletes notes via web forms (`/notes*`) or JSON API (`/api/notes*`).
5. User can search notes (`POST /api/notes/search`) and view storage usage (`GET /api/storage`).

Code: `internal/auth/handlers.go`, `internal/web/handlers.go`, `internal/notes/notes.go`.

### 2. Human User: Create API Keys
1. User opens `/api-keys` (or `/settings/api-keys`).
2. User submits key name/scope/expiry and re-auth credentials.
3. Server stores only SHA-256 hash of key material and returns plaintext token once.
4. User uses the key as `Authorization: Bearer agentnotes_key_...`.

Code: `internal/web/apikey_handlers.go`, `internal/auth/apikey.go`.

### 3. Human User: Publish a Public Note
1. User selects visibility on `/notes/{id}`: Private, Public (Anonymous), or Public (Show my name).
2. Server sets `is_public` (0/1/2), renders Markdown to standalone HTML via Go template, uploads to S3, and creates short URL mapping.
3. Public access via `/pub/{short_id}` which 302-redirects to the S3 public URL.

Code: `internal/web/handlers.go`, `internal/notes/public.go`, `internal/notes/render.go`, `internal/shorturl/shorturl.go`.

### 4. AI Client: Connect via OAuth + MCP
1. Client discovers metadata (`/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`, `/.well-known/jwks.json`).
2. Client registers with `POST /oauth/register`.
3. User authorizes at `GET /oauth/authorize` with PKCE (`S256`) and consent.
4. Client exchanges code at `POST /oauth/token`.
5. Client calls one MCP endpoint with Bearer token:
- `POST /mcp` for all tools
- `POST /mcp/notes` for notes-only toolset
- `POST /mcp/apps` for apps-only toolset
6. For app workflows, client uses `app_create` (candidate names), `app_write`, and `app_bash`.

Code: `internal/oauth/provider.go`, `internal/oauth/dcr.go`, `internal/oauth/handlers.go`, `internal/mcp/server.go`, `internal/mcp/handlers.go`.

## Interfaces and Behaviors Supported

### Web Routes
- Auth pages: `/login`, `/register`, `/password-reset`, `/auth/password-reset-confirm`
- Notes pages: `/notes`, `/notes/new`, `/notes/{id}`, `/notes/{id}/edit`
- Public pages: `/pub/{short_id}` (302 redirect to S3)
- API key pages: `/api-keys`, `/api-keys/new`, `/settings/api-keys`
- Static markdown-backed pages: `/privacy`, `/terms`, `/about`, `/docs`, `/docs/api`, `/docs/install`

### JSON APIs
- Notes: `GET/POST /api/notes`, `GET/PUT/DELETE /api/notes/{id}`, `POST /api/notes/search`
- Storage: `GET /api/storage`
- API keys: `POST /api/keys`, `GET /api/keys`, `DELETE /api/keys/{id}`

### OAuth Provider
- Metadata: `/.well-known/*`
- DCR: `POST /oauth/register`
- Authorization: `GET /oauth/authorize`, `POST /oauth/consent`
- Token: `POST /oauth/token`

### MCP
- Supported:
- `POST /mcp` (all tools)
- `POST /mcp/notes` (notes toolset)
- `POST /mcp/apps` (apps toolset)
- Explicitly rejected in top-level server mode: `GET`/`DELETE` for each MCP route return `405`

## Data Model Summary

### Shared DB (`sessions.db`, unencrypted)
Stores sessions, magic tokens, user key envelopes, OAuth clients/tokens/codes, consent records, short URL mappings.

Schema source: `internal/db/schema.go`.

### Per-user DB (`{user_id}.db`, SQLCipher encrypted)
Stores account row, notes table, FTS5 index/triggers, API keys, and app metadata (`apps` table with sprite name/URL/status/timestamps).

Schema source: `internal/db/schema.go`.

## Current Known Gaps (Code-Truth)
- Consent persistence used by runtime OAuth handler is placeholder-backed and does not persist grants as expected.
  - `internal/auth/consent.go`
  - Wiring: `cmd/server/main.go`
- Paid-tier rate-limit routing is not wired (`getIsPaid` always returns `false`).
  - `cmd/server/main.go`

## Source-of-Truth Rule
Behavioral truth is code under:
- `cmd/server`
- `internal/auth`
- `internal/oauth`
- `internal/mcp`
- `internal/notes`
- `internal/db`
- `internal/web`
