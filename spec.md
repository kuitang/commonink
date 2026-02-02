# Remote Notes MicroSaaS - Engineering Specification

## Overview
MCP-first notes service enabling AI context sharing across Claude, ChatGPT, and any MCP-compatible client. Users authenticate via Google, store encrypted notes, access via MCP protocol.

---

## Architecture

### Tech Stack
- **Language**: Go 1.22+
- **Database**: SQLite (one file per user) + SQLCipher encryption
- **Deployment**: Fly.io
- **Auth**: Google OIDC (users) + OAuth 2.1 provider (for AI clients)
- **Payments**: [DECIDE: Stripe vs LemonSqueezy]
- **Email**: Resend

### Key Libraries
See `notes/go-libraries-2026.md` for versions.
- MCP: `github.com/modelcontextprotocol/go-sdk`
- OAuth Provider: `github.com/ory/fosite`
- OIDC Client: `github.com/coreos/go-oidc/v3`
- SQLite: `github.com/mutecomm/go-sqlcipher`
- HTTP: [DECIDE: chi vs gin]
- Payment: `github.com/stripe/stripe-go/v84` or `github.com/NdoleStudio/lemonsqueezy-go`
- Email: `github.com/resend/resend-go/v3`
- Testing: `pgregory.net/rapid` + stdlib fuzzing + `playwright-go`

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
│ │   • HandleStripeWebhook() or HandleLemonWebhook()      │
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

### MCP Server
```
POST /mcp                   - MCP streamable HTTP endpoint
  Methods:
    - initialize            - MCP handshake
    - tools/list            - List available tools
    - tools/call            - Execute tool
```

### Payments
```
POST /checkout              - Create checkout session
POST /webhooks/stripe       - Stripe webhook (or /webhooks/lemon)
GET  /subscription/status   - Check user's subscription
```

### Admin / Health
```
GET  /health                - Health check
GET  /metrics               - Prometheus metrics (optional)
```

---

## Data Model

### User (stored in shared metadata DB or user's SQLite?)
```sql
users (
    id            TEXT PRIMARY KEY,     -- Google sub claim
    email         TEXT UNIQUE NOT NULL,
    name          TEXT,
    picture_url   TEXT,
    created_at    INTEGER NOT NULL,
    kek_version   INTEGER DEFAULT 1,
    encrypted_dek BLOB NOT NULL,
    subscription_status TEXT DEFAULT 'free',  -- free, active, cancelled
    subscription_id TEXT
)
```

### Notes (per-user SQLite DB)
```sql
notes (
    id         TEXT PRIMARY KEY,
    title      TEXT NOT NULL,
    content    TEXT NOT NULL,
    tags       TEXT,              -- JSON array or comma-separated
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
)

-- FTS5 index for search
CREATE VIRTUAL TABLE fts_notes USING fts5(
    title, content,
    content='notes',
    content_rowid='rowid'
)
```

### OAuth Clients (stored where? Shared DB?)
```sql
oauth_clients (
    client_id     TEXT PRIMARY KEY,
    client_secret TEXT NOT NULL,
    client_name   TEXT,           -- "Claude", "ChatGPT", etc.
    redirect_uris TEXT NOT NULL,  -- JSON array
    created_at    INTEGER NOT NULL
)

oauth_codes (
    code              TEXT PRIMARY KEY,
    client_id         TEXT NOT NULL,
    user_id           TEXT NOT NULL,
    redirect_uri      TEXT NOT NULL,
    scope             TEXT,
    code_challenge    TEXT NOT NULL,
    expires_at        INTEGER NOT NULL
)

oauth_tokens (
    access_token  TEXT PRIMARY KEY,
    refresh_token TEXT,
    client_id     TEXT NOT NULL,
    user_id       TEXT NOT NULL,
    scope         TEXT,
    expires_at    INTEGER NOT NULL
)
```

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
- `content` (string, required)
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
- [DECIDE: Enforce max content size?]

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
- Uses FTS5 for full-text search
- Searches both title and content
- [DECIDE: Different weights for title vs content?]
- Returns only current user's notes
- [DECIDE: Support search operators (AND, OR, NOT)?]

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
- Soft delete or hard delete? [DECIDE]
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
- **Regions**: [DECIDE: single or multi-region?]
- **Storage**: Mounted volume for SQLite files
  - Path: `/data/{user_id}/notes.db`
  - [DECIDE: Single volume or distributed?]
- **Scaling**: [DECIDE: Horizontal scaling strategy with SQLite file locking?]
- **Secrets**: Master encryption key stored in Fly secrets

### Environment Variables
```
MASTER_KEY=<hex-encoded-key>           # For KEK derivation
GOOGLE_CLIENT_ID=<google-oauth-id>
GOOGLE_CLIENT_SECRET=<google-secret>
STRIPE_SECRET_KEY=<stripe-key>         # or LEMON_API_KEY
RESEND_API_KEY=<resend-key>
OAUTH_ISSUER=https://your-domain.com
DATABASE_PATH=/data
```

---

## Open Questions (DECIDE)

### Critical Path
1. **Payment provider**: Stripe or LemonSqueezy?
2. **Pricing model**: Free tier? Subscription tiers? Limits?
3. **HTTP framework**: chi (minimal) vs gin (popular)?
4. **Horizontal scaling**: How to handle multiple instances + SQLite file locking?

### Data Storage
5. **Metadata DB**: Where to store users, oauth_clients, oauth_tokens?
   - Separate PostgreSQL instance?
   - Shared SQLite file (not per-user)?
6. **Note size limits**: Max content size? Max total storage per user?
7. **Note organization**: Flat list with tags, or support folders?
8. **Note deletion**: Soft delete with retention period, or hard delete?

### Auth & Security
9. **Email/password**: Support in addition to Google OIDC, or Google-only?
10. **API keys**: Support for programmatic access (non-browser environments)?
11. **Token storage**: Where to persist OAuth tokens? (User's SQLite, shared DB, Redis?)

### Features
12. **Search**: Title/content weighting? Search operators? Fuzzy matching?
13. **Web UI**: How minimal? Just OAuth consent, or basic CRUD forms?
14. **Note sharing**: Support sharing notes between users? Public URLs?
15. **Versioning**: Support note version history, or just last-modified?

### Rate Limiting
16. **Limits**: What's reasonable? (e.g., 100 req/min per user?)
17. **Per-endpoint**: Different limits for read vs write vs search?
18. **Free vs paid**: Different rate limits for tiers?

### Testing
19. **Fuzzing duration**: 30 min nightly, or longer?
20. **Playwright browsers**: Chromium only, or Firefox/WebKit too?
21. **Flakiness budget**: Retry failed tests, or 0% tolerance?

### Email
22. **Email use cases**: Welcome, password reset, subscription confirmations, marketing?

---

## Next Steps
1. Answer open questions
2. Initialize Go project with dependencies
3. Write hello world + library smoke tests
4. Implement CI scripts (quick, full, fuzz)
5. Setup git hooks (go fmt + quick CI)
6. Write CLAUDE.md with test plan
