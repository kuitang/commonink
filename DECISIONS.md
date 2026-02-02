# Architecture Decisions - Remote Notes MicroSaaS

**Date**: 2026-02-02
**Status**: Decisions Made - Ready for Implementation

---

## ✅ CONFIRMED DECISIONS

### 1. Transparent Proxy Pattern
**Decision**: Implement stateless reverse proxy in front of OpenCode Chat
- Single-tenant OpenCode Chat app (one sandbox)
- Proxy authenticates users and maps to their SQLite DBs
- OpenCode Chat remains unchanged, simple integration

**Implementation**:
```
User Request → Proxy (auth + DB routing) → OpenCode Chat (single tenant)
```

### 2. Database Architecture
**Decision**: `DATA_ROOT/{user_id}.db` - One SQLite file per user

**Details**:
- Environment variable: `DATA_ROOT`
- File path: `${DATA_ROOT}/{user_id}.db`
- Open file on each request (stateless)
- Store MCP sessions in the DB
- No connection pooling needed (SQLite is just a file)

**Rationale**: Simple, stateless, works perfectly with SQLite's design

### 3. Horizontal Scaling with SQLite
**Decision**: Single region (EWR), single volume, rely on native SQLite file locks

**Why native locks work**:
- SQLite uses OS-level file locks (fcntl on Linux, LockFileEx on Windows)
- Multiple processes can read simultaneously
- Only one writer at a time (automatic queuing)
- WAL mode enables concurrent readers during writes
- File locks are atomic and respected across processes

**Configuration**:
```sql
PRAGMA journal_mode = WAL;  -- Write-Ahead Logging for better concurrency
PRAGMA busy_timeout = 5000; -- Wait up to 5s for locks
```

**Limitation**: Single volume = all processes must be on same Fly.io machine. For multi-machine scaling, need to switch to PostgreSQL or shared storage.

### 4. Encryption Implementation
**Pattern Confirmed**: Versioned KEK derivation (from your code example)

**Key Hierarchy**:
```
MASTER_KEY (Fly secret)
  ↓ HKDF(masterKey, userID, version)
KEK (versioned, per-user)
  ↓ AES-256-GCM wrap
DEK (stored in DB, encrypted)
  ↓ SQLCipher PRAGMA key
SQLite DB (encrypted at rest)
```

**Key Functions**:
- `DeriveKEK(userID, version)` - Versioned derivation
- `CreateUserKeys(db, userID)` - At signup
- `OpenUserDatabase(authDB, userID)` - Get KEK, unwrap DEK, open DB
- `RotateUserKEK(db, userID)` - Increment version, re-wrap DEK
- `RotateMasterKey(db, oldMaster, newMaster)` - Re-wrap all DEKs

**Rotation Costs**:
| Scenario | Data Re-encrypted | Cost |
|----------|------------------|------|
| User KEK rotation | No (just re-wrap DEK) | Cheap |
| Master key rotation | No (just re-wrap all DEKs) | Medium |
| User DEK compromised | **Yes** (entire DB re-keyed) | Expensive |

### 5. SQLite: Pure Go vs CGO
**Decision**: **Use CGO-based SQLite with encryption** (mattn/go-sqlite3 + go-sqlcipher)

**Research Summary**:
- **Pure Go** (modernc.org/sqlite): 2x slower, no native encryption, simpler deployment
- **CGO** (go-sqlcipher): Industry standard, AES-256, 5-15% overhead, complex build

**Why CGO**:
- Encryption is critical for notes app
- Pure Go alternatives lack mature encryption (ncruces/go-sqlite3 with Adiantum is too new)
- Performance acceptable for notes use case
- SQLCipher is battle-tested (WhatsApp, Signal)

**Trade-off Accepted**: Complex cross-compilation for better security

See: `notes/sqlite-encryption-research.md` for full analysis

### 6. Authentication Methods
**Decision**: Email/password + Magic email login (no Google OIDC for now)

**Flow**:
1. User signs up with email
2. Receives magic login link (email verification)
3. Can optionally set password after first login
4. Password reset = magic login email

**Rationale**:
- Simpler than multi-provider OAuth
- Magic login serves dual purpose (verification + login)
- Users can add password for convenience later
- Reduces dependencies (no Google OAuth setup needed initially)

### 7. API Keys
**Decision**: Implement developer-friendly API key management

**Features**:
- Default scope: Read/write
- Optional: Read-only keys
- REST endpoint: `POST /api/keys` to provision
- Session-based web UI for key management
- Store in shared `sessions.db` (see next section)

**Implementation**: Standard token-based auth with scopes

### 8. Session Storage
**Decision**: Shared `sessions.db` across all users (separate from user notes DBs)

**Why Shared DB**:
- Cookies are shared across users (HTTP is stateless)
- Session lookup needs to be fast and global
- Sessions reference `user_id`, then open that user's DB
- API keys also stored here (global lookup)

**Structure**:
```
${DATA_ROOT}/sessions.db (shared)
${DATA_ROOT}/{user_id}.db (per-user notes)
```

**sessions.db schema**:
```sql
sessions (session_id, user_id, expires_at, created_at)
api_keys (key_id, user_id, scope, created_at, last_used)
oauth_clients (client_id, client_secret, redirect_uris)
oauth_tokens (access_token, user_id, client_id, expires_at)
```

### 9. Payment Provider
**Decision**: LemonSqueezy

**Why LemonSqueezy**:
- Merchant of Record (handles all tax/VAT globally)
- Simple pricing: 5% + $0.50 per transaction
- No monthly fees (pay only on sales)
- Built-in customer portal
- Sends billing/receipt emails automatically
- Test mode sandbox included

**Setup**:
- Sign up at lemonsqueezy.com
- Create API key (test + production)
- Create products: Free tier + $5/year unlimited
- Webhook for subscription events

**Email Responsibilities**:
- **LemonSqueezy sends**: Receipts, payment success/failed, renewal reminders
- **We send**: Magic login, feature announcements, usage alerts

See: `notes/lemonsqueezy-setup-guide.md` for complete setup

### 10. Email Provider
**Decision**: Resend for transactional emails

**Use Cases** (Transactional Only - Phase 1):
- Magic login email (primary authentication)
- Password reset (if user set password)
- Account creation verification (combined with magic login)

**Future** (Marketing - Phase 2, Optional):
- Feature announcements
- Usage limit warnings
- Re-engagement campaigns
- Opt-in required (GDPR compliant)

**Setup**:
- Sign up at resend.com
- Free tier: 3,000 emails/month (sufficient for launch)
- Domain verification (SPF, DKIM, DMARC DNS records)
- API key (sending_access permission)

**Marketing Email Decision**:
- Start with transactional only
- Add marketing later with explicit opt-in
- LemonSqueezy does NOT send marketing emails (we would need to)

**Legal Implications**:
- **Transactional**: No consent needed, no unsubscribe required
- **Marketing**: Requires opt-in (GDPR), unsubscribe link, CAN-SPAM compliance

See: `notes/resend-email-setup-guide.md` for legal requirements

### 11. MCP Transport
**Decision**: Streamable HTTP only

**Clarification**: MCP Streamable HTTP = Server-Sent Events (SSE)
- Client opens HTTP connection
- Server streams responses via SSE
- Connection stays open for bidirectional-ish communication
- Reference: https://modelcontextprotocol.io/specification/2025-03-26/basic/transports

**No Need For**:
- stdio (process-based, not applicable for web service)
- WebSocket (more complex, SSE sufficient)

**Tool Approval**: Auto-execute (no user approval needed)
- For MCP server, distinction between auto/manual approval doesn't matter
- User authenticated = trusted to use all tools
- No UI for per-tool approval in v0

### 12. Free Tier Limits
**Decision**: 100MB max DB size per user

**Enforcement**:
- Check at login time
- If exceeded: Block all writes, allow reads
- Prompt to upgrade to paid plan
- Calculate size: `SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()`

**Paid Tier**: $5/year unlimited (no DB size limit, reasonable rate limits)

### 13. Rate Limiting
**Decision**:
- **Free tier**: 10 req/sec per user
- **Paid tier**: No rate limit (or very high, like 100 req/sec)
- **Idiomatic**: Per-user, not per-IP (authenticated API)

**Rationale**:
- Notes app is not high-frequency (unlike chat)
- 10 req/sec = 600 req/min = sufficient for normal use
- Prevents abuse while allowing batch operations
- Use `tollbooth` for HTTP middleware

### 14. Search Implementation
**Decision**: SQLite FTS5, search title + body, no special weighting

**Default FTS5 Behavior**:
- BM25 ranking algorithm (standard for FTS)
- Automatic stemming (English)
- Phrase search, prefix search, boolean operators (AND, OR, NOT)

**Typo Tolerance**:
- **NOT implementing Levenshtein (edit distance 2)** initially
- FTS5 doesn't support fuzzy search natively
- Would require extension or application-level logic
- Deferring to idiom: Most note apps (Notational Velocity, nvALT, Simplenote) use exact/prefix match

**Search Weighting**:
- No different weights for title vs content
- FTS5 ranks by term frequency + document frequency (BM25)
- Users can manually boost title searches with: `title:keyword`

**Implementation**:
```sql
CREATE VIRTUAL TABLE fts_notes USING fts5(
    title,
    content,
    content='notes',
    content_rowid='rowid'
);

-- Search both title and content
SELECT * FROM fts_notes WHERE fts_notes MATCH 'search query';
```

### 15. Web UI
**Decision**: Minimal viewer + API key management, NO JavaScript, stdlib only

**Features**:
- **v0 Scope**:
  - View notes list (read-only)
  - Get API key
  - Subscription management (via LemonSqueezy portal link)
  - Magic login form
  - Password set/reset form

**No Features**:
- No note editor (use MCP clients like Claude/ChatGPT)
- No rich text editing
- No frontend framework (React, Vue, etc.)
- No JavaScript (except if OAuth/LemonSqueezy requires it)

**Implementation**:
- Server-side templates: `html/template` (stdlib)
- Plain HTML + minimal CSS
- Forms submit to backend
- Redirects for navigation

**Payment Screens**:
- Display current plan (Free / Unlimited)
- Link to LemonSqueezy customer portal (they handle checkout)
- Show usage stats (DB size, request count)

### 16. Public Notes & URLs
**Decision**: Public notes with public URLs, rendered to Markdown, served via Tigris

**Features**:
- Flag per note: `is_public BOOLEAN`
- Public URL: `https://notes.yourdomain.com/{user_id}/{note_id}`
- Render to Markdown HTML (server-side, pre-rendered)
- Upload to Tigris CDN (S3-compatible object storage)
- No tags needed (simplify v0)

**Deployment**:
- **Production**: Fly.io + Tigris
  - Pre-render Markdown to HTML on note save
  - Upload to Tigris bucket
  - Tigris serves with global caching
  - Cost: ~$0.02/GB storage, $0 egress

- **Development**: Local MinIO (Docker)
  - S3-compatible local storage
  - Same code works in dev and prod (AWS SDK)
  - No Tigris account needed for local dev

See: `DEPLOYMENT_ARCHITECTURE.md` for complete setup

### 17. Note Size Limits
**Decision**: 1MB per note (reasonable for text content)

**Rationale**:
- 1MB = ~500,000 words (far more than any reasonable note)
- Markdown files are small (GitHub limits to 100MB, we're 100x smaller)
- Prevents abuse, keeps DB performant
- Enforcement: Check `length(content) > 1048576` before insert/update

### 18. Note Versioning
**Decision**: No versioning, just `updated_at` timestamp

**Rationale**:
- Claude file edits with versioning = expensive storage (full copy per edit)
- Most note apps don't version (Notion, Evernote have it, but it's enterprise feature)
- Users can use Git if they want versioning (export notes to files)
- Keeps DB simple and small
- Can add later if needed (would store diffs, not full copies)

**What We Track**:
- `created_at` - Note creation time
- `updated_at` - Last modification time
- No edit history, no diffs, no rollback

### 19. HTTP Framework
**Decision**: Pure stdlib (`net/http`) - NO framework

**Rationale**:
- Go 1.22+ has enhanced routing (`http.ServeMux` supports path parameters)
- Simple app doesn't need framework overhead
- No dependencies = easier maintenance
- Idiomatic Go (stdlib-first approach)
- Can add Chi later if routing gets complex

**Example**:
```go
mux := http.NewServeMux()
mux.HandleFunc("GET /notes/{id}", handleGetNote)
mux.HandleFunc("POST /notes", handleCreateNote)
mux.HandleFunc("GET /api/keys", handleListAPIKeys)
```

### 20. Testing Strategy
**Conformance Tests**:
- **MCP**: Use `@modelcontextprotocol/conformance` (npm)
  - Run via: `npx @modelcontextprotocol/conformance server --url http://localhost:8080/mcp`
  - Can automate in CI via GitHub Actions composite action

- **OAuth 2.1**: Use OpenID Conformance Suite (Docker)
  - No OAuth 2.1-specific suite yet (still draft)
  - OpenID suite covers OAuth 2.0 + PKCE
  - Local: `docker-compose up` → test at https://localhost:8443
  - CI: `python run-test-plan.py` for automation

- **Playwright**: Chromium only
  - Test critical flows: magic login, API key creation, subscription upgrade
  - Use Go playwright-go integration

- **Fuzzing**: 30 minutes nightly (confirmed acceptable)

See: `CONFORMANCE_TESTING.md` and `CONFORMANCE_QUICK_REFERENCE.md`

---

## 📋 REMAINING OPEN QUESTIONS

### Critical Implementation Questions

**Q1: Transparent Proxy Implementation**
- Should the proxy be a separate Go binary, or embedded in the main app?
- How does the proxy communicate with OpenCode Chat?
  - HTTP reverse proxy to OpenCode Chat backend?
  - Shared process with import?
- Does OpenCode Chat expose an HTTP API we can proxy to?
- **Action Needed**: Research OpenCode Chat architecture

**Q2: Metadata Storage Location**
You mentioned:
- Per-user SQLite: `${DATA_ROOT}/{user_id}.db` for notes
- Shared `sessions.db` for sessions/API keys

But what about:
- User account info (email, password hash, created_at)?
- OAuth clients (client_id, client_secret)?
- Subscription status (free/paid, LemonSqueezy subscription_id)?

**Options**:
A. Store in `sessions.db` (shared DB for all metadata)
B. Store in per-user DB (user.db has account info + notes)
C. Separate `accounts.db` for user accounts

**Recommendation**: Option A (`sessions.db` contains everything global)
```sql
-- sessions.db schema
users (user_id, email, password_hash, created_at, subscription_status)
sessions (session_id, user_id, expires_at)
api_keys (key_id, user_id, scope, created_at)
oauth_clients (client_id, client_secret, redirect_uris)
oauth_tokens (access_token, user_id, expires_at)
```

**Q3: Magic Login Email - Token Storage**
Where do we store magic login tokens?
- `sessions.db` (shared)?
- Per-user DB?
- In-memory with TTL?

**Recommendation**: `sessions.db` with schema:
```sql
magic_tokens (token_hash, email, expires_at, created_at)
```

**Q4: Password Hashing Algorithm**
Which algorithm for password hashing?
- bcrypt (Go stdlib via golang.org/x/crypto/bcrypt)
- argon2id (golang.org/x/crypto/argon2)
- scrypt (less common)

**Recommendation**: bcrypt (idiomatic, widely used, stdlib support)

**Q5: Public Note URLs - Subdomain or Path?**
You said `notes.yourdomain.com/{user_id}/{note_id}`.
- Do we need to configure a subdomain in DNS?
- Or use path: `yourdomain.com/public/{user_id}/{note_id}`?

**Clarification Needed**: Subdomain requires DNS setup. Is that OK?

**Q6: Go Version Manager**
You said "use go version manager to use the latest stable Golang."
- Which version manager? (gvm, asdf, g, go itself via `go install golang.org/dl/go1.22@latest`)
- Should I set it up now, or just document the requirement?

**Recommendation**: Use `asdf` (supports multiple languages) or just install Go 1.22 directly

---

## 📝 IMPLEMENTATION PRIORITY

### Phase 1: Foundation (Week 1)
1. Install Go 1.22+ (use asdf or direct install)
2. Setup project with stdlib HTTP router
3. Implement sessions.db schema
4. Magic login email flow
5. Basic auth middleware

### Phase 2: Core Features (Week 2)
1. Per-user SQLite DB with encryption
2. Notes CRUD (create, read, update, delete, list)
3. FTS5 search
4. API key management
5. Rate limiting

### Phase 3: MCP Integration (Week 3)
1. MCP server (SSE transport)
2. MCP tools (note_view, note_create, note_update, note_search, note_list, note_delete)
3. OAuth 2.1 provider endpoints
4. MCP conformance tests

### Phase 4: Payments & Deployment (Week 4)
1. LemonSqueezy integration
2. Free tier limit enforcement (100MB)
3. Subscription webhook handling
4. Fly.io deployment + Tigris
5. Public notes rendering

### Phase 5: Testing & Polish (Week 5)
1. E2E property tests (rapid)
2. OAuth conformance tests
3. Playwright browser tests
4. Fuzzing
5. Production monitoring

---

## 🎯 NEXT STEPS

1. **Answer remaining questions** (Q1-Q6 above)
2. **Install Go 1.22+** using version manager
3. **Update spec.md** with all confirmed decisions
4. **Begin Phase 1 implementation**

---

## 📚 NEW DOCUMENTATION CREATED

1. **notes/sqlite-encryption-research.md** - Pure Go vs CGO SQLite analysis
2. **notes/lemonsqueezy-setup-guide.md** - LemonSqueezy integration guide
3. **notes/resend-email-setup-guide.md** - Resend setup + legal compliance
4. **DEPLOYMENT_ARCHITECTURE.md** - Fly.io + Tigris architecture
5. **CONFORMANCE_TESTING.md** - MCP + OAuth conformance tests
6. **CONFORMANCE_QUICK_REFERENCE.md** - Quick test commands

All research complete. Ready to implement once questions are answered.
