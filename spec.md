# Remote Notes MicroSaaS - Engineering Specification

## Overview
MCP-first notes service enabling AI context sharing across Claude, ChatGPT, and any MCP-compatible client. Users authenticate via Google, store encrypted notes, access via MCP protocol.

---

## Architecture

### Tech Stack
- **Language**: Go 1.25+
- **Database**: SQLite (one file per user) + SQLCipher encryption
- **Deployment**: Fly.io (single region, single instance for MVP)
- **Auth**: Magic Login + Email/Password + Google OIDC (users) + OAuth 2.1 provider (for AI clients)
- **Payments**: LemonSqueezy ($5/year unlimited + free tier)
- **Email**: Resend

### Key Libraries
See `notes/go-libraries-2026.md` for versions.
- MCP: `github.com/modelcontextprotocol/go-sdk v1.2.0`
- OAuth Provider: `github.com/ory/fosite v0.49.0`
- OIDC Client: `github.com/coreos/go-oidc/v3 v3.17.0`
- SQLite: `github.com/mutecomm/go-sqlcipher` (with CGO)
- HTTP: stdlib `net/http` (Go 1.22+ routing)
- Rate Limiting: stdlib `golang.org/x/time/rate`
- Payment: `github.com/NdoleStudio/lemonsqueezy-go v1.3.1`
- Email: `github.com/resend/resend-go/v3 v3.1.0`
- Testing: `pgregory.net/rapid v1.2.0` + stdlib fuzzing + `playwright-go v0.5200.1`

### Database Architecture

```
${DATA_ROOT}/sessions.db      -- Shared (unencrypted bootstrap)
${DATA_ROOT}/{user_id}.db     -- Per-user (encrypted with SQLCipher)
```

- **User Data**: ALL in user's encrypted DB
- **Bootstrap Data**: Minimal in shared sessions.db (sessions, OAuth clients/tokens, user keys)

### Authentication

All three methods supported:
1. **Magic Login** - Email with token (passwordless)
2. **Email/Password** - Argon2id hashed (OWASP recommended)
3. **Google OIDC** - Sign in with Google (`openid email profile` scopes, no offline_access)

Auto-link accounts by email. Both magic login and Google always available. Session-based auth with 30-day sessions (no Google refresh token storage).

### Rate Limiting

Per-user via stdlib `golang.org/x/time/rate`:
- **Free tier**: 10 req/sec, burst 20
- **Paid tier**: 1000 req/sec
- **Memory**: TTL-based cleanup every hour

### Storage Limits

- **Free tier**: 100MB, **Paid tier**: Unlimited
- Cache DB size on login, check on writes

### Public Notes

**Storage**: Fly.io Tigris (S3-compatible, global CDN built-in)
- Interface: `ObjectStorage` (M3 mock → M4+ Tigris)
- Pre-render Markdown → HTML with SEO tags
- Upload to: `public/{user_id}/{note_id}.html`
- URL: `yourdomain.com/public/{user_id}/{note_id}`

**See**: `DEPLOYMENT_ARCHITECTURE.md` for Tigris setup, local MinIO, and cost details.

---

## System Modules

```
┌─────────────────────────────────────────────────────────┐
│ main.go                                                  │
│ • App initialization                                     │
│ • Secret loading (Fly secrets)                           │
│ • Server lifecycle                                       │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ internal/auth/                                           │
│ ├── google.go       - Google OIDC client                 │
│ │   • RedirectToGoogle()                                 │
│ │   • HandleGoogleCallback()                             │
│ │   • ValidateIDToken()                                  │
│ │                                                         │
│ ├── oauth_provider.go - OAuth 2.1 server endpoints       │
│ │   • /.well-known/oauth-authorization-server            │
│ │   • /.well-known/oauth-protected-resource              │
│ │   • POST /oauth/register (DCR)                         │
│ │   • GET  /oauth/authorize (consent screen)             │
│ │   • POST /oauth/token (code exchange + refresh)        │
│ │                                                         │
│ ├── session.go      - Session management                 │
│ │   • CreateSession()                                    │
│ │   • ValidateSession()                                  │
│ │                                                         │
│ └── middleware.go   - Auth middleware                    │
│     • RequireAuth()                                      │
│     • RequireOAuthToken()                                │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ internal/notes/                                          │
│ ├── store.go        - Database interface                 │
│ │   • OpenUserDB(userID) - get/create user's SQLite     │
│ │   • Create(note)                                       │
│ │   • Read(noteID)                                       │
│ │   • Update(noteID, content)                            │
│ │   • Delete(noteID)                                     │
│ │   • List(cursor, limit)                                │
│ │   • Search(query, tags)                                │
│ │                                                         │
│ ├── encryption.go   - Key management                     │
│ │   • DeriveKEK(masterKey, userID, version)              │
│ │   • EncryptDEK(kek, dek)                               │
│ │   • DecryptDEK(kek, encryptedDEK)                      │
│ │   • RotateUserKEK(userID)                              │
│ │                                                         │
│ └── schema.sql      - DB schema                          │
│     • notes(id, title, content, tags, created, updated)  │
│     • fts_index (FTS5 for search)                        │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ internal/mcp/                                            │
│ ├── server.go       - MCP protocol handler               │
│ │   • POST /mcp (streamable HTTP)                        │
│ │   • HandleToolsList()                                  │
│ │   • HandleToolCall(toolName, params)                   │
│ │                                                         │
│ └── tools.go        - Tool implementations               │
│     • note_view(note_id, section_range?)                 │
│     • note_create(title, content, tags?)                 │
│     • note_update(note_id, old_content, new_content)     │
│     • note_search(query, tags?, limit)                   │
│     • note_list(cursor?, limit)                          │
│     • note_delete(note_id)                               │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ internal/payment/                                        │
│ ├── checkout.go     - Create checkout sessions           │
│ │   • CreateCheckout(userID, planID)                     │
│ │                                                         │
│ ├── webhook.go      - Payment webhooks                   │
│ │   • HandleLemonWebhook()                               │
│ │   • subscription_created → activate user               │
│ │   • subscription_cancelled → deactivate                │
│ │                                                         │
│ └── subscription.go - Subscription status                │
│     • CheckUserSubscription(userID)                      │
│     • EnforceLimits(userID)                              │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ internal/email/                                          │
│ ├── client.go       - Resend client wrapper              │
│ │   • Send(to, subject, html)                            │
│ │                                                         │
│ └── templates.go    - Email templates                    │
│     • WelcomeEmail(user)                                 │
│     • SubscriptionConfirmation(user, plan)               │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ internal/ratelimit/                                      │
│ ├── middleware.go   - Rate limiting middleware           │
│     • PerUserLimit(rpm int)                              │
│     • PerIPLimit(rpm int)                                │
│     • PerEndpointLimits(map[string]int)                  │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ web/                                                     │
│ ├── templates/      - HTML templates                     │
│ │   • login.html                                         │
│ │   • oauth_consent.html                                 │
│ │   • notes_list.html (minimal UI)                       │
│ │   • settings_tokens.html (PAT management)              │
│ │                                                         │
│ └── static/         - CSS, JS (minimal)                  │
└─────────────────────────────────────────────────────────┘
```

---

## API Routes

### Web UI (Session-based)
```
GET  /                      - Landing page
GET  /login                 - Redirect to Google OIDC
GET  /auth/callback         - Google OIDC callback
GET  /logout                - Clear session
GET  /notes                 - List notes (minimal web UI)
```

### OAuth Provider (for AI clients)
```
GET  /.well-known/oauth-authorization-server     - Metadata
GET  /.well-known/oauth-protected-resource       - Resource metadata
POST /oauth/register        - Dynamic Client Registration (DCR)
GET  /oauth/authorize       - Authorization endpoint (PKCE)
POST /oauth/token           - Token endpoint (code exchange, refresh)
```

### MCP Server (Streamable HTTP Transport - MCP Spec 2025-03-26)
```
POST /mcp                   - Send JSON-RPC messages (requests, notifications, responses)
                              Client MUST include Accept header with application/json and text/event-stream
                              Server responds with JSON or SSE stream
GET  /mcp                   - Open SSE stream for server-initiated messages (optional)
                              Client MUST include Accept: text/event-stream
                              Server returns 405 if not supported
DELETE /mcp                 - Terminate session (optional)
                              Client MUST include Mcp-Session-Id header

Session Management:
  - Server MAY return Mcp-Session-Id header in InitializeResult
  - Client MUST include Mcp-Session-Id in all subsequent requests
  - Server returns 404 when session expires

JSON-RPC Methods:
  - initialize              - MCP handshake (returns session ID)
  - initialized             - Client confirms initialization
  - tools/list              - List available tools
  - tools/call              - Execute tool
  - notifications/cancelled - Cancel running operation
```

### Personal Access Tokens (PAT)
```
POST /api/tokens            - Create PAT (requires email + password)
GET  /api/tokens            - List user's PATs (session auth required)
DELETE /api/tokens/{id}     - Revoke a PAT (session auth required)
```

### Payments
```
POST /checkout              - Create checkout session
POST /webhooks/lemon        - LemonSqueezy webhook
GET  /subscription/status   - Check user's subscription
```

### Admin / Health
```
GET  /health                - Health check
GET  /metrics               - Prometheus metrics (optional)
```

---

## Data Model

### sessions.db (Shared, Unencrypted Bootstrap)

```sql
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    INDEX idx_user_id (user_id)
);

CREATE TABLE magic_tokens (
    token_hash TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    user_id TEXT,  -- NULL until user created
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    INDEX idx_email (email)
);

CREATE TABLE user_keys (
    user_id TEXT PRIMARY KEY,
    kek_version INTEGER NOT NULL DEFAULT 1,
    encrypted_dek BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    rotated_at INTEGER
);

CREATE TABLE oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_secret TEXT NOT NULL,
    client_name TEXT,
    redirect_uris TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE oauth_tokens (
    access_token TEXT PRIMARY KEY,
    refresh_token TEXT,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    scope TEXT,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    INDEX idx_user_client (user_id, client_id)
);

CREATE TABLE oauth_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT DEFAULT 'S256',
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
```

### {user_id}.db (Per-User, Encrypted)

```sql
CREATE TABLE account (
    user_id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,    -- NULL if not set
    google_sub TEXT,       -- NULL if not linked
    created_at INTEGER NOT NULL,
    subscription_status TEXT DEFAULT 'free',
    subscription_id TEXT,  -- LemonSqueezy subscription_id
    db_size_bytes INTEGER DEFAULT 0,
    last_login INTEGER
);

CREATE TABLE notes (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    content TEXT NOT NULL CHECK(length(content) <= 1048576),
    is_public INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE VIRTUAL TABLE fts_notes USING fts5(
    title,
    content,
    content='notes',
    content_rowid='rowid'
);

CREATE TRIGGER notes_ai AFTER INSERT ON notes BEGIN
    INSERT INTO fts_notes(rowid, title, content)
    VALUES (new.rowid, new.title, new.content);
END;

CREATE TRIGGER notes_ad AFTER DELETE ON notes BEGIN
    DELETE FROM fts_notes WHERE rowid = old.rowid;
END;

CREATE TRIGGER notes_au AFTER UPDATE ON notes BEGIN
    UPDATE fts_notes SET title = new.title, content = new.content
    WHERE rowid = new.rowid;
END;

CREATE TABLE personal_access_tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    scope TEXT DEFAULT 'read_write',  -- 'read' or 'read_write'
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);
```

**Note**: OAuth clients, codes, and tokens are stored in sessions.db (see above).

### Notes Schema Details

- **id**: UUID or nanoid
- **title**: Free text, searchable
- **content**: Max 1MB (1,048,576 bytes)
- **is_public**: Boolean flag for public sharing
- **FTS5 triggers**: Auto-sync with full-text search index

### Personal Access Tokens Schema

Users can create PATs for programmatic access (alternative to OAuth):
- **id**: Unique identifier (shown to user as `token_id`)
- **name**: User-provided description for the token
- **token_hash**: Argon2id hash of the actual token
- **scope**: `read` or `read_write`
- **expires_at**: Token expiration (1 year from creation)
- **last_used_at**: Track usage for cleanup and audit

---

## Encryption Design

### Key Hierarchy
```
Master Key (Fly secret)
    ↓ HKDF(masterKey, userID + ":" + version)
User KEK (versioned)
    ↓ AES-256 encrypt
User DEK (stored in DB)
    ↓ SQLCipher PRAGMA key
SQLite DB (encrypted at rest)
```

### Key Rotation
1. Derive old KEK with old version
2. Decrypt DEK
3. Increment `kek_version`
4. Derive new KEK with new version
5. Re-encrypt DEK with new KEK
6. Update `users.encrypted_dek` and `users.kek_version`

---

## MCP Tools Specification

### note_view
**Parameters:**
- `note_id` (string, required)
- `section_range` (object, optional): `{start_line: int, end_line: int}`

**Returns:**
```json
{
  "content": "note content",
  "metadata": {
    "title": "Note Title",
    "created_at": "2026-02-02T10:00:00Z",
    "updated_at": "2026-02-02T12:00:00Z",
    "tags": ["project", "design"]
  }
}
```

**Acceptance Criteria:**
- Returns 404 if note not found or belongs to different user
- Respects section_range if provided
- Enforces user isolation (cannot view other users' notes)

---

### note_create
**Parameters:**
- `title` (string, required)
- `content` (string, required, max 1MB)
- `tags` (array of strings, optional)

**Returns:**
```json
{
  "note_id": "uuid",
  "created_at": "2026-02-02T10:00:00Z"
}
```

**Acceptance Criteria:**
- Generates unique ID
- Stores encrypted in user's SQLite
- Updates FTS index
- Enforces max content size (1MB)

---

### note_update
**Parameters:**
- `note_id` (string, required)
- `old_content` (string, required) - for conflict detection
- `new_content` (string, required)

**Returns:**
```json
{
  "success": true,
  "updated_at": "2026-02-02T12:00:00Z"
}
```

**Acceptance Criteria:**
- Returns 409 if `old_content` doesn't match current (optimistic locking)
- Updates `updated_at` timestamp
- Updates FTS index
- Returns 404 if note not found or belongs to different user

---

### note_search
**Parameters:**
- `query` (string, required)
- `tags` (array of strings, optional)
- `limit` (integer, default 10)

**Returns:**
```json
{
  "results": [
    {
      "note_id": "uuid",
      "title": "Matching Note",
      "snippet": "...highlighted context...",
      "relevance_score": 0.95
    }
  ]
}
```

**Acceptance Criteria:**
- Uses FTS5 for full-text search (supports AND, OR, NOT operators natively)
- Searches both title and content (default FTS5 weighting)
- Returns only current user's notes

---

### note_list
**Parameters:**
- `cursor` (string, optional) - for pagination
- `limit` (integer, default 20)

**Returns:**
```json
{
  "notes": [
    {
      "note_id": "uuid",
      "title": "Note Title",
      "updated_at": "2026-02-02T12:00:00Z"
    }
  ],
  "next_cursor": "base64_cursor"
}
```

**Acceptance Criteria:**
- Sorted by `updated_at` DESC
- Cursor-based pagination (not offset)
- Returns only current user's notes

---

### note_delete
**Parameters:**
- `note_id` (string, required)

**Returns:**
```json
{
  "success": true
}
```

**Acceptance Criteria:**
- Hard delete (no versioning for MVP)
- Returns 404 if note not found or belongs to different user
- Removes from FTS index

---

## OAuth Flow Specification

### User Connects to ChatGPT/Claude

1. **User adds connector in AI client**
   - URL: `https://your-domain.com/mcp`

2. **AI client fetches metadata**
   ```
   GET /.well-known/oauth-protected-resource
   → Discovers authorization server
   ```

3. **Dynamic Client Registration (DCR)**
   ```
   POST /oauth/register
   {
     "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
     "client_name": "Claude",
     "grant_types": ["authorization_code", "refresh_token"],
     "response_types": ["code"]
   }

   Response:
   {
     "client_id": "generated_uuid",
     "client_secret": "generated_secret",
     "client_id_issued_at": 1234567890
   }
   ```

4. **Authorization Request (PKCE)**
   ```
   User redirected to:
   GET /oauth/authorize?
       client_id={client_id}
       &redirect_uri=https://claude.ai/api/mcp/auth_callback
       &response_type=code
       &scope=notes:read notes:write
       &state={random_state}
       &code_challenge={sha256(verifier)}
       &code_challenge_method=S256
   ```

5. **User authenticates (Google OIDC)**
   - If not logged in → redirect to Google
   - If logged in → show consent screen

6. **Consent & Redirect**
   ```
   User approves → redirect to:
   https://claude.ai/api/mcp/auth_callback?
       code={auth_code}
       &state={state}
   ```

7. **Token Exchange**
   ```
   POST /oauth/token
   {
     "grant_type": "authorization_code",
     "client_id": "{client_id}",
     "client_secret": "{client_secret}",
     "code": "{auth_code}",
     "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
     "code_verifier": "{original_verifier}"
   }

   Response:
   {
     "access_token": "jwt_or_opaque",
     "token_type": "Bearer",
     "expires_in": 3600,
     "refresh_token": "refresh_token_value",
     "scope": "notes:read notes:write"
   }
   ```

8. **MCP Request with Token**
   ```
   POST /mcp
   Authorization: Bearer {access_token}
   {
     "jsonrpc": "2.0",
     "method": "tools/list",
     "id": 1
   }
   ```

**Acceptance Criteria:**
- PKCE required (reject requests without code_challenge)
- Redirect URI must match registered URIs exactly
- Tokens expire (access: 1 hour, refresh: 30 days)
- Refresh token rotation (issue new refresh token on each use)

---

## Personal Access Token (PAT) Specification

PATs allow users to authenticate programmatically without going through the OAuth flow. Useful for CLI tools, scripts, and local MCP clients.

### Create PAT

**Endpoint**: `POST /api/tokens`

**Request** (no session required - uses email/password):
```json
{
  "email": "user@example.com",
  "password": "user_password",
  "name": "My CLI Token",
  "scope": "read_write"
}
```

**Response** (token shown ONCE, never stored in plaintext):
```json
{
  "token": "pat_xxx...xxx",
  "token_id": "tok_abc123",
  "name": "My CLI Token",
  "scope": "read_write",
  "expires_at": "2027-02-02T10:00:00Z",
  "created_at": "2026-02-02T10:00:00Z"
}
```

**Scope Values:**
- `read` - Read-only access to notes
- `read_write` - Full access to notes (default)

### List PATs

**Endpoint**: `GET /api/tokens`

**Auth**: Session cookie required

**Response** (actual token values are NEVER returned - only metadata for management):
```json
{
  "tokens": [
    {
      "token_id": "tok_abc123",
      "name": "My CLI Token",
      "scope": "read_write",
      "created_at": "2026-02-02T10:00:00Z",
      "last_used_at": "2026-02-02T15:30:00Z"
    }
  ]
}
```

### Revoke PAT

**Endpoint**: `DELETE /api/tokens/{token_id}`

**Auth**: Session cookie required

**Response**: `204 No Content`

### Using PATs

PATs can be used as Bearer tokens for MCP and API requests:

```bash
curl -X POST https://your-domain.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $YOUR_PAT_TOKEN" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

**Acceptance Criteria:**
- PAT created only with valid email/password
- Token shown once on creation, never retrievable again
- Tokens hashed (Argon2id) before storage
- PATs expire after 1 year
- PAT authentication works for MCP and API endpoints
- `last_used_at` updated on each use
- Revoking PAT immediately invalidates it

### PAT Management UI

**Route**: `GET /settings/tokens`

**Auth**: Session cookie required

**UI Flow**:

1. **Token List View** (default)
   - Table showing all user's PATs: name, scope, created_at, last_used_at
   - "Revoke" button per token (confirmation dialog)
   - "Create New Token" button

2. **Create Token Form**
   - Name field (required, for user's reference)
   - Scope dropdown: "Read & Write" (default), "Read Only"
   - Password field (re-authenticate to create token)
   - "Generate Token" button

3. **Token Created Modal** (shown once after creation)
   - Display token value with copy button
   - Warning: "This token will only be shown once. Copy it now."
   - "Done" button (dismisses modal, token never shown again)

4. **Revoke Confirmation Dialog**
   - "Are you sure? This will immediately invalidate the token."
   - "Cancel" / "Revoke" buttons

**Template**: `web/templates/settings_tokens.html`

**Implementation**: UI calls same backend API endpoints (`POST/GET/DELETE /api/tokens`)

---

## Testing Strategy

See `notes/testing-strategy.md` for full details. Summary:

### Test Categories
1. **E2E API Property Tests** (`tests/e2e/*_test.go`)
   - rapid + httptest.Server
   - Properties: roundtrip, idempotence, user isolation, pagination consistency

2. **E2E MCP Property Tests** (`tests/e2e/*_mcp_test.go`)
   - Test MCP protocol compliance
   - Tool schema validation
   - Request/response matching

3. **Sensitive Logic Unit Tests** (`internal/<pkg>/*_test.go`)
   - Auth: token generation, validation, expiry
   - Crypto: encryption roundtrip, key derivation
   - Parsing: injection prevention, unicode edge cases

4. **Playwright Browser Tests** (`tests/browser/*_test.go`)
   - Critical flows: signup, OAuth consent
   - Not property-based (deterministic scenarios)

### CI Levels
- **quick**: rapid only, ~30s
- **full**: rapid + Playwright + coverage, ~5min
- **fuzz**: coverage-guided fuzzing, 30+ min

### External Test Resources
- MCP conformance: `npx @modelcontextprotocol/conformance`
- MCP inspector: `npx @modelcontextprotocol/inspector`
- OAuth conformance: OpenID Conformance Suite (Docker)
- PKCE validation: online tools + manual scripts
- Mock OIDC: `mockoidc` (Go) for testing Google Sign-In

See `notes/testing-tools.md` for detailed tool usage.

### External Service Testing (LemonSqueezy & Resend)

#### LemonSqueezy Payment Testing

**Official Test Mode**: LemonSqueezy provides full test mode support without requiring real payments.

**Test Environment Setup**:
- Create separate test mode API keys in LemonSqueezy dashboard
- Test keys only interact with test mode data
- Use test credit cards (never real card numbers):
  - Visa: 4242 4242 4242 4242
  - Mastercard: 5555 5555 5555 4444
  - Insufficient funds: 4000 0000 0000 9995
  - Expired card: 4000 0000 0000 0069

**Testing Approaches**:

1. **Unit Tests** (Interface Wrapper Pattern):
```go
// internal/payment/service.go
type PaymentService interface {
    CreateCheckout(userID, planID string) (*Checkout, error)
    GetSubscription(id string) (*Subscription, error)
}

// tests/payment/mock_service.go
type MockPaymentService struct {
    CreateCheckoutFunc func(userID, planID string) (*Checkout, error)
}
```

2. **Integration Tests** (Test Mode API):
```go
// tests/e2e/payment_test.go
func testPaymentIntegration(t *rapid.T) {
    client := lemonsqueezy.New(
        lemonsqueezy.WithAPIKey(os.Getenv("LEMON_TEST_API_KEY")),
    )
    // Tests run against real test mode API
}
```

3. **HTTP Mocking** (When test mode insufficient):
```go
import "github.com/jarcoal/httpmock"

func TestPaymentWebhook(t *testing.T) {
    httpmock.Activate(t)
    defer httpmock.DeactivateAndReset()

    httpmock.RegisterResponder("POST",
        "https://api.lemonsqueezy.com/v1/checkouts",
        httpmock.NewJsonResponderOrPanic(200, checkoutResponse))
}
```

**Webhook Testing**:
- Test mode sends webhooks for all events
- Use LemonSqueezy dashboard to manually trigger test webhooks
- Verify webhook signature validation in tests

#### Resend Email Testing

**Official Test Mode**: Resend provides test email addresses and sandbox domain for testing without real email setup.

**Test Environment Setup**:
- No domain verification required for testing
- Use sandbox domain: `[email protected]`
- Set `testMode: true` (default) to restrict delivery to test addresses only
- Create test API key in Resend dashboard

**Test Email Addresses**:
- `delivered@resend.dev` - Successful delivery
- `bounced@resend.dev` - Simulate SMTP 550 rejection
- `complained@resend.dev` - Spam/complaint scenario
- `suppressed@resend.dev` - Previously bounced address
- Labeling supported: `delivered+user1@resend.dev`, `delivered+flow2@resend.dev`

**Testing Approaches**:

1. **Unit Tests** (Interface Wrapper Pattern):
```go
// internal/email/service.go
type EmailService interface {
    Send(to, subject, html string) error
    SendTemplate(to string, template string, data interface{}) error
}

// tests/email/mock_service.go
type MockEmailService struct {
    SendFunc func(to, subject, html string) error
}
```

2. **Integration Tests** (Test Email Addresses):
```go
// tests/e2e/email_test.go
func testEmailDelivery(t *rapid.T) {
    client := resend.NewClient(os.Getenv("RESEND_TEST_API_KEY"))

    // Test successful delivery
    err := client.Emails.Send(&resend.SendEmailRequest{
        From:    "noreply@yourdomain.com",
        To:      []string{"delivered@resend.dev"},
        Subject: "Test Email",
        Html:    "<p>Test content</p>",
    })

    // Verify via webhooks or API
}

func testEmailBounce(t *testing.T) {
    // Send to bounced@resend.dev
    // Verify bounce handling
}
```

3. **HTTP Mocking** (Unit tests):
```go
func TestEmailRetry(t *testing.T) {
    httpmock.Activate(t)
    defer httpmock.DeactivateAndReset()

    // Simulate API failure
    httpmock.RegisterResponder("POST",
        "https://api.resend.com/emails",
        httpmock.NewStringResponder(500, "Internal Server Error"))

    // Test retry logic
}
```

**Webhook Testing**:
- Configure webhook URL in Resend dashboard
- Test delivery, bounce, complaint events
- Use labeling to track different test scenarios

#### General HTTP Mocking Libraries

When official test modes are insufficient or for isolated unit tests:

**Option A: `github.com/jarcoal/httpmock`** (Recommended for external API mocking)
- Transport-level HTTP interception
- Pattern matching for URLs (regex support)
- Call count tracking
- Easy response stubbing

**Option B: `net/http/httptest`** (Stdlib, for testing handlers)
- Create test HTTP servers
- Good for testing HTTP handlers, not clients
- No external dependencies

**Option C: Interface Wrappers** (Recommended for complex services)
- Define service interfaces
- Mock implementations for tests
- Production implementations use real clients
- Best for property-based testing with rapid

#### Testing Strategy Summary

| Service | Unit Tests | Integration Tests | E2E Tests |
|---------|-----------|-------------------|-----------|
| **LemonSqueezy** | Interface wrapper | Test mode API + test cards | Test mode webhooks |
| **Resend** | Interface wrapper | Test email addresses | Webhook verification |

**Environment Variables for Testing**:
```bash
# .env.test
LEMON_TEST_API_KEY=test_xxx
RESEND_TEST_API_KEY=re_xxx
TEST_MODE=true
```

**CI/CD Integration**:
- Store test API keys as GitHub secrets
- Use test mode for all CI runs
- Mock external services for unit tests (fast)
- Use real test APIs for integration tests (slower but comprehensive)

---

## Deployment

### Fly.io Configuration
- **Platform**: Fly.io
- **Regions**: Single region (MVP)
- **Storage**: Single mounted volume at `/data/`
  - `sessions.db` for shared data
  - `{user_id}.db` for per-user encrypted notes
- **Scaling**: Single instance (MVP - SQLite file locking simplicity)
- **Secrets**: Master encryption key stored in Fly secrets

### Environment Variables
```
MASTER_KEY=<hex-encoded-key>           # For KEK derivation
GOOGLE_CLIENT_ID=<google-oauth-id>
GOOGLE_CLIENT_SECRET=<google-secret>
LEMON_API_KEY=<lemonsqueezy-key>
RESEND_API_KEY=<resend-key>
OAUTH_ISSUER=https://your-domain.com
DATABASE_PATH=/data
```

---

## Decision Summary

All architectural decisions finalized for MVP:

| Area | Decision |
|------|----------|
| **Payment** | LemonSqueezy ($5/year + free tier) |
| **HTTP** | stdlib `net/http` (Go 1.22+ routing) |
| **Scaling** | Single instance, single region |
| **Metadata DB** | Shared `sessions.db` (SQLite) |
| **Note limits** | 1MB content, 100MB total (free), unlimited (paid) |
| **Organization** | Flat list with tags (no folders) |
| **Deletion** | Hard delete (no versioning) |
| **Auth methods** | Magic Login + Email/Password + Google OIDC |
| **PAT (API tokens)** | Supported - email/password → 1-year token (stored hashed in user DB) |
| **OAuth tokens** | Shared `sessions.db` |
| **Search** | FTS5 default weighting, native operators |
| **Web UI** | Minimal (OAuth consent + basic CRUD) |
| **Public notes** | `/{user_id}/{note_id}` URLs |
| **Rate limits** | Per-user (10/s free, 1000/s paid) |
| **Fuzzing** | 30 min nightly |
| **Browsers** | Chromium only |
| **Flakiness** | 0% tolerance |
| **Email** | Welcome, magic login, subscription confirmations |
