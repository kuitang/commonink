# Milestone 2: User Authentication + Envelope Encryption (Mocks Only)

**Goal**: Implement ALL authentication methods (Google OIDC, Magic Login, Email/Password) using **dependency injection with mocks**, plus the envelope encryption scheme for per-user database encryption. No real external services - fully automated tests.

**Prerequisites**: Milestone 1 complete (MCP server + HTTP API working with hardcoded user)

**Key Principle**: All external services (Google OIDC, Email) are behind interfaces. Milestone 2 uses mock implementations only. Real integrations deferred to Milestone 4.

---

## Implementation DAG

```
                         [Milestone 1 Complete]
                                   │
       ┌───────────────────────────┼───────────────────────────┐
       │                           │                           │
[Envelope Encryption]    [Sessions DB Queries]      [Email Interface+Mock]
       │                      (6 queries)                      │
       └───────────────────────────┼───────────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
      [OIDC Interface+Mock]  [User Service]      [Session Service]
              │               (consolidated)           │
              └────────────────────┼────────────────────┘
                                   │
                      ┌────────────┴────────────┐
                      │                         │
              [Auth Middleware]           [Auth Handlers]
                      │                    (10 routes)
                      └────────────┬────────────┘
                                   │
                         [Wire into main.go]
                                   │
                  ┌────────────────┼────────────────┐
                  │                │                │
          [Property Tests] [Integration Tests] [gosec Scan]
                  │                │                │
                  └────────────────┼────────────────┘
                                   │
                         [Master Test Script]
```

---

## Tasks (Topologically Sorted for Parallel Execution)

### Layer 0: Prerequisites
- [x] Milestone 1 complete (MCP + HTTP API with hardcoded user)
- [x] Database layer with sessions.db and user DBs
- [x] Notes service working

### Layer 1 (Parallel - No Dependencies)

1. **Envelope Encryption** (`internal/crypto/`)
   - **Key Hierarchy** (per spec.md):
     ```
     Master Key (env var MASTER_KEY)
         ↓ HKDF(masterKey, userID + ":" + version)
     User KEK (Key Encryption Key, versioned)
         ↓ AES-256-GCM encrypt
     User DEK (Data Encryption Key, stored encrypted in sessions.db)
         ↓ SQLCipher PRAGMA key
     SQLite DB (encrypted at rest)
     ```
   - `crypto.go`:
     - `DeriveKEK(masterKey, userID, version)` - HKDF-SHA256
     - `GenerateDEK()` - 32 bytes random
     - `EncryptDEK(kek, dek)` - AES-256-GCM
     - `DecryptDEK(kek, encryptedDEK)` - AES-256-GCM
   - `keymanager.go`:
     - `KeyManager` struct: masterKey, db
     - `GetOrCreateUserDEK(userID)` - Create DEK on first login
     - `GetUserDEK(userID)` - Retrieve and decrypt DEK
     - `RotateUserKEK(userID)` - Key rotation support
   - Update `internal/db/db.go`:
     - `OpenUserDB(userID)` now uses KeyManager to get DEK
     - Remove hardcoded DEK

2. **Sessions DB Queries** (`internal/db/sql/sessions.sql`)
   - **Minimal query set** - only what's needed for type safety:
     ```sql
     -- Sessions: simple CRUD by primary key
     -- name: UpsertSession :exec
     INSERT INTO sessions (session_id, user_id, expires_at, created_at)
     VALUES (?, ?, ?, ?) ON CONFLICT(session_id) DO UPDATE SET expires_at = excluded.expires_at;

     -- name: GetSession :one
     SELECT * FROM sessions WHERE session_id = ? AND expires_at > unixepoch();

     -- name: DeleteSession :exec
     DELETE FROM sessions WHERE session_id = ?;

     -- Magic tokens: same pattern
     -- name: UpsertMagicToken :exec
     INSERT INTO magic_tokens (token_hash, email, user_id, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?) ON CONFLICT(token_hash) DO UPDATE SET expires_at = excluded.expires_at;

     -- name: GetMagicToken :one
     SELECT * FROM magic_tokens WHERE token_hash = ? AND expires_at > unixepoch();

     -- name: DeleteMagicToken :exec
     DELETE FROM magic_tokens WHERE token_hash = ?;

     -- User keys: upsert handles create + update
     -- name: UpsertUserKey :exec
     INSERT INTO user_keys (user_id, kek_version, encrypted_dek, created_at, rotated_at)
     VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET
       kek_version = excluded.kek_version, encrypted_dek = excluded.encrypted_dek, rotated_at = excluded.rotated_at;

     -- name: GetUserKey :one
     SELECT * FROM user_keys WHERE user_id = ?;

     -- Cleanup: single batch delete for expired rows
     -- name: DeleteExpiredRows :exec
     DELETE FROM sessions WHERE expires_at <= unixepoch();
     DELETE FROM magic_tokens WHERE expires_at <= unixepoch();
     ```
   - **6 queries total** (vs 11 before) - upsert pattern reduces duplication

3. **Email Service Interface** (`internal/email/`)
   - `service.go` - Interface:
     ```go
     type EmailService interface {
         Send(to, templateName string, data any) error
     }
     ```
   - `mock.go` - Mock implementation:
     ```go
     type MockEmailService struct {
         mu     sync.Mutex
         Emails []SentEmail
     }
     type SentEmail struct {
         To, Template string
         Data         any
     }
     func (m *MockEmailService) LastEmail() SentEmail
     func (m *MockEmailService) Clear()
     ```

### Layer 2 (Depends on Layer 1)

4. **OIDC Client Interface + Mock** (`internal/auth/oidc.go`)
   - **Interface**:
     ```go
     type OIDCClient interface {
         GetAuthURL(state string) string
         ExchangeCode(ctx context.Context, code string) (*Claims, error)
     }
     type Claims struct { Sub, Email, Name string; EmailVerified bool }
     ```
   - **Mock** in same file (small):
     ```go
     type MockOIDCClient struct {
         NextClaims *Claims
         NextError  error
     }
     ```

5. **User Service** (`internal/auth/user.go`) - **CONSOLIDATED**
   - Handles: user CRUD, magic tokens, password hashing
   - `UserService` struct: db, keyManager, emailService
   - **User management**:
     - `FindOrCreateByEmail(email)` - Idempotent user creation
     - `FindByGoogleSub(sub)` - For OIDC login
     - `LinkGoogleAccount(userID, googleSub)`
   - **Password** (Argon2id):
     - `SetPassword(userID, password)` - Hash and store
     - `VerifyPassword(userID, password)` - Check hash
     - `ValidatePasswordStrength(password)` - Min 8 chars
   - **Magic tokens**:
     - `SendMagicLink(email)` - Generate token, store hash, send email
     - `VerifyMagicToken(token)` - Hash, lookup, check expiry, delete, return email
     - Token = 32 bytes random, store SHA-256 hash, 15 min expiry
   - **Password reset** (reuses magic token):
     - `SendPasswordReset(email)` - Same as magic link, different template
     - `ResetPassword(token, newPassword)` - Verify token + set password

6. **Session Service** (`internal/auth/session.go`)
   - `SessionService` struct: db
   - `Create(userID)` - 32-byte random ID, 30-day expiry, returns session ID
   - `Validate(sessionID)` - Check exists and not expired, returns userID
   - `Delete(sessionID)` - Logout
   - `Cleanup()` - Delete expired (background goroutine)
   - Cookie helpers: `SetCookie(w, id)`, `ClearCookie(w)`, `GetFromRequest(r)`

### Layer 3 (Depends on Layer 2)

7. **Auth Middleware** (`internal/auth/middleware.go`)
   - `Middleware` struct: sessionService, userService, keyManager
   - `RequireAuth(next)` - Reject 401 if no valid session
   - `OptionalAuth(next)` - Add user to context if present, continue either way
   - `GetUserID(ctx)`, `GetUserDB(ctx)` - Context helpers

8. **Auth Handlers** (`internal/auth/handlers.go`)
   - `Handler` struct: oidcClient, userService, sessionService
   - **Routes** (10 total):
     - `GET  /auth/google` - Redirect to OIDC
     - `GET  /auth/google/callback` - OIDC callback
     - `POST /auth/magic` - Request magic link
     - `GET  /auth/magic/verify` - Verify magic link
     - `POST /auth/register` - Email/password registration
     - `POST /auth/login` - Email/password login
     - `POST /auth/password/reset` - Request reset
     - `POST /auth/password/reset/confirm` - Confirm reset
     - `POST /auth/logout` - Logout
     - `GET  /auth/whoami` - Current user info

### Layer 4 (Depends on Layer 3)

9. **Update main.go**
    - Load MASTER_KEY from environment
    - Initialize: KeyManager → EmailService (mock) → OIDCClient (mock)
    - Initialize: UserService → SessionService → AuthMiddleware → AuthHandler
    - Register auth routes (10 total)
    - Wrap notes routes with `RequireAuth` middleware
    - Remove hardcoded `test-user-001`

10. **Update Notes Service**
    - Accept `*db.UserDB` parameter per-request (from context)
    - Remove `HardcodedUserID` constant

### Layer 5 (Parallel, Depends on Layer 4)

11. **Property Tests** (`internal/crypto/*_test.go`, `internal/auth/*_test.go`)
    - **Crypto**:
      - DEK encrypt/decrypt roundtrip
      - KEK derivation deterministic
      - Wrong KEK fails decrypt
    - **Session**:
      - Create → validate → delete lifecycle
      - Expired session rejected
      - High entropy session IDs
    - **User** (consolidated):
      - FindOrCreate idempotent
      - Magic token verify + consume
      - Password hash + verify (Argon2id)
      - Password reset flow

12. **Integration Tests** (`tests/auth/auth_test.go`)
    - Full flows with mock OIDC + mock email
    - Google login → session created
    - Magic link → email captured → token works
    - Password register → login works
    - Password reset → email captured → new password works

### Layer 6 (Depends on Layer 5)

13. **Master Test Script** (`scripts/milestone2-test.sh`)
    - Run property tests
    - Run integration tests
    - Report results

**Note**: Security scanning (gosec) runs automatically via `make check` on every build.

---

## Envelope Encryption Design (Key Section)

### Key Hierarchy
```
MASTER_KEY (32 bytes, from environment)
    │
    ├─── HKDF-SHA256(masterKey, "user:alice:v1") ──→ Alice's KEK v1
    │         │
    │         └─── AES-256-GCM encrypt ──→ Alice's encrypted DEK
    │                                            │
    │                                            └─── SQLCipher key for alice.db
    │
    └─── HKDF-SHA256(masterKey, "user:bob:v1") ──→ Bob's KEK v1
              │
              └─── AES-256-GCM encrypt ──→ Bob's encrypted DEK
                                               │
                                               └─── SQLCipher key for bob.db
```

### Storage
- `sessions.db` → `user_keys` table:
  ```sql
  CREATE TABLE user_keys (
      user_id TEXT PRIMARY KEY,
      kek_version INTEGER NOT NULL DEFAULT 1,
      encrypted_dek BLOB NOT NULL,
      created_at INTEGER NOT NULL,
      rotated_at INTEGER
  );
  ```

### Key Rotation Flow
1. Derive old KEK: `HKDF(masterKey, "user:" + userID + ":v" + oldVersion)`
2. Decrypt DEK with old KEK
3. Increment version
4. Derive new KEK: `HKDF(masterKey, "user:" + userID + ":v" + newVersion)`
5. Re-encrypt DEK with new KEK
6. Update `user_keys` table

### First Login Flow
1. User authenticates (any method)
2. Check if user_keys entry exists
3. If not: Generate random DEK, derive KEK, encrypt DEK, store
4. Derive KEK, decrypt DEK
5. Open SQLite with DEK as PRAGMA key
6. Store DB handle in context

---

## Expected File Structure

```
/home/kuitang/git/agent-notes/
├── internal/
│   ├── crypto/
│   │   ├── crypto.go           # KEK/DEK derivation + encryption
│   │   ├── keymanager.go       # User key management
│   │   └── crypto_test.go      # Property tests
│   ├── auth/
│   │   ├── oidc.go             # OIDC interface + mock (small, same file)
│   │   ├── user.go             # CONSOLIDATED: user + magic tokens + passwords
│   │   ├── session.go          # Session management
│   │   ├── handlers.go         # HTTP handlers (10 routes)
│   │   ├── middleware.go       # Auth middleware
│   │   └── *_test.go           # Property tests
│   │   # oidc_google.go deferred to Milestone 4
│   ├── email/
│   │   ├── service.go          # Interface + mock (small, same file)
│   │   └── templates.go        # Email HTML templates
│   │   # resend.go deferred to Milestone 4
│   └── db/
│       └── sql/
│           └── sessions.sql    # 6 queries total (upsert pattern)
├── tests/
│   └── auth/
│       └── auth_test.go        # Integration tests with mocks
├── scripts/
│   ├── ci.sh                   # Updated with gosec
│   └── milestone2-test.sh      # Master test orchestrator
└── cmd/server/
    └── main.go                 # Updated with auth + encryption
```

---

## Environment Variables

**Milestone 2 - NO EXTERNAL CREDENTIALS NEEDED**:
```bash
# Master key for envelope encryption (required)
MASTER_KEY=<64-char-hex-string>  # 32 bytes = 256 bits

# Mocks are always used in M2
# USE_MOCK_EMAIL=true     # Implicit
# USE_MOCK_OIDC=true      # Implicit

# Session (optional, has defaults)
SESSION_DURATION=720h     # 30 days

# Argon2id (optional, has defaults per OWASP)
ARGON2_MEMORY=65536       # 64 MiB
ARGON2_TIME=1             # iterations
ARGON2_THREADS=4          # parallelism
```

**Existing from Milestone 1**:
```bash
DATABASE_PATH=/data
```

---

## Dependencies to Add

```go
// go.mod additions for Milestone 2
require (
    github.com/oauth2-proxy/mockoidc v0.0.0-20240214162133-caebfff84d25  // Mock OIDC
    golang.org/x/crypto v0.28.0                // argon2 + hkdf
)
```

**Security tool (CI)**:
```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

---

## Success Criteria

### Encryption
- [ ] Master key loaded from environment
- [ ] KEK derived per-user with HKDF
- [ ] DEK generated on first login, encrypted with KEK, stored
- [ ] User database opened with decrypted DEK
- [ ] Key rotation works (re-encrypt DEK with new KEK version)

### Authentication (All Mock)
- [ ] Google OIDC flow works (mock provider)
- [ ] Magic link flow works (mock email captures token)
- [ ] Password registration and login work (Argon2id)
- [ ] Password reset flow works (reuses magic token)
- [ ] Sessions created, validated, deleted correctly
- [ ] Same email across auth methods = same user account

### Multi-User Isolation
- [ ] Each user has separate encrypted database
- [ ] User A cannot access User B's notes

### Security
- [ ] `make check` passes (includes gosec - zero medium+ severity)
- [ ] No hardcoded secrets
- [ ] 256-bit entropy for session IDs and tokens

---

## What's Deferred to Later Milestones

| Milestone | Content |
|-----------|---------|
| **M3** | Rate Limiting, Public Notes, Web UI (Tailwind), OAuth Consent Screens |
| **M4** | Real Auth Integrations (Google OIDC, Resend Email) - manual testing |
| **M5** | OAuth 2.1 Provider (for AI clients) - ngrok needed |
| **M6** | Payments (LemonSqueezy) |

---

## Commands to Execute

```bash
# Initialize goenv
export GOENV_ROOT="$HOME/.goenv" && export PATH="$GOENV_ROOT/bin:$PATH" && eval "$(goenv init -)"

# Install development tools (gosec for security scanning)
make install-tools

# Install Milestone 2 dependencies
go get github.com/oauth2-proxy/mockoidc
go get golang.org/x/crypto/argon2
go get golang.org/x/crypto/hkdf

# Generate master key for testing
openssl rand -hex 32  # Save this as MASTER_KEY

# Run sqlc to generate queries
sqlc generate

# Build (runs fmt, vet, gosec, mod-tidy first)
make build

# Run tests
./scripts/ci.sh quick

# Run full test suite
./scripts/ci.sh full
```
