# Milestone 2: User Authentication + Envelope Encryption (Mocks Only)

**Goal**: Implement ALL authentication methods (Google OIDC, Magic Login, Email/Password) using **dependency injection with mocks**, plus the envelope encryption scheme for per-user database encryption. No real external services - fully automated tests.

**Prerequisites**: Milestone 1 complete (MCP server + HTTP API working with hardcoded user)

**Key Principle**: All external services (Google OIDC, Email) are behind interfaces. Milestone 2 uses mock implementations only. Real integrations deferred to Milestone 4.

---

## Implementation DAG

```
                              [Milestone 1 Complete]
                                        │
    ┌───────────────────────────────────┼───────────────────────────────────┐
    │                                   │                                   │
[Sessions DB Queries]          [Email Service Interface]           [Envelope Encryption]
    │                                   │                                   │
    │                     ┌─────────────┴─────────────┐                     │
    │                     │                           │                     │
    │              [Mock Email Impl]           [User Service]               │
    │                     │                           │                     │
    └─────────────────────┼───────────────────────────┼─────────────────────┘
                          │                           │
         ┌────────────────┴───────────────────────────┴────────────────┐
         │                            │                                │
  [OIDC Interface + Mock]  [Magic Token Service]            [Password Service]
         │                            │                                │
         └────────────────────────────┼────────────────────────────────┘
                                      │
                              [Session Service]
                                      │
                         ┌────────────┴────────────┐
                         │                         │
                 [Auth Middleware]          [Auth Handlers]
                         │                    (all 3 methods)
                         └────────────┬────────────┘
                                      │
                          [Wire into main.go]
                                      │
                    [Remove Hardcoded User + Use Encryption]
                                      │
                           [Property Tests]
                                      │
                    ┌─────────────────┼─────────────────┐
                    │                 │                 │
            [Encryption Tests] [Mock Auth Tests] [gosec Security Scan]
                    │                 │                 │
                    └─────────────────┼─────────────────┘
                                      │
                            [Master Test Script]
                                      │
                                  [Commit]
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

2. **Sessions DB Queries** (`internal/db/sql/sessions_auth.sql`)
   - Add sqlc queries for:
     - `CreateSession(session_id, user_id, expires_at)`
     - `GetSession(session_id)` → returns user_id + expires_at
     - `DeleteSession(session_id)`
     - `DeleteExpiredSessions()`
     - `CreateMagicToken(token_hash, email, expires_at)`
     - `GetMagicToken(token_hash)` → returns email + user_id + expires_at
     - `DeleteMagicToken(token_hash)`
     - `DeleteExpiredMagicTokens()`
     - `CreateUserKey(user_id, kek_version, encrypted_dek)`
     - `GetUserKey(user_id)` → returns kek_version + encrypted_dek
     - `UpdateUserKey(user_id, kek_version, encrypted_dek)` - for rotation
   - Run `sqlc generate` to create Go code

3. **Email Service Interface** (`internal/email/service.go`)
   - Define interface (enables mocking):
     ```go
     type EmailService interface {
         SendMagicLink(to, token string) error
         SendPasswordReset(to, token string) error
         SendWelcome(to, name string) error
     }
     ```
   - `SentEmail` struct for test capture: To, Subject, Body, Token, Type

4. **Mock Email Implementation** (`internal/email/mock.go`)
   - `MockEmailService` struct with `SentEmails []SentEmail`
   - Thread-safe (sync.Mutex)
   - All methods append to SentEmails slice
   - `GetSentEmails()` for test assertions
   - `GetLastToken()` - convenience for tests
   - `Clear()` to reset between tests

5. **User Service** (`internal/auth/user.go`)
   - `User` struct: ID, Email, PasswordHash, GoogleSub, CreatedAt, LastLogin
   - `UserService` struct wrapping sessions DB + KeyManager
   - `FindOrCreateByEmail(email)` - Create user + DEK if not exists
   - `FindByEmail(email)` - Lookup by email
   - `FindByGoogleSub(sub)` - Lookup by Google subject
   - `LinkGoogleAccount(userID, googleSub)` - Link Google to existing user
   - `SetPassword(userID, passwordHash)` - Set/update password
   - `GetPasswordHash(userID)` - For verification

### Layer 2 (Depends on Layer 1)

6. **OIDC Client Interface + Mock** (`internal/auth/oidc.go`, `internal/auth/oidc_mock.go`)
   - **Interface**:
     ```go
     type OIDCClient interface {
         GetAuthURL(state string) string
         ExchangeCode(ctx context.Context, code string) (*Claims, error)
     }
     type Claims struct {
         Sub, Email, Name, Picture string
         EmailVerified bool
     }
     ```
   - **Mock Implementation**:
     - `MockOIDCClient` with configurable responses
     - `QueueUser(claims)` - Set next user to return
     - `SetError(err)` - Simulate failures
     - `GetLastState()` - Verify state parameter
   - **Real Implementation** deferred to Milestone 4

7. **Magic Token Service** (`internal/auth/magic.go`)
   - `MagicTokenService` struct: db, emailService
   - `GenerateToken()` - 32 bytes random, returns token + hash (SHA-256)
   - `SendMagicLink(email)` - Generate token, store hash, send email
   - `VerifyToken(token)` - Hash token, lookup, check expiry, return email
   - `ConsumeToken(token)` - Verify + delete (one-time use)
   - Token expiry: 15 minutes

8. **Password Service** (`internal/auth/password.go`)
   - `PasswordService` struct: userService
   - `HashPassword(password)` - Argon2id (OWASP recommended)
     - Parameters: memory=64MiB, time=1, threads=4, keyLen=32, saltLen=16
   - `VerifyPassword(hash, password)` - Argon2id verify
   - `SetUserPassword(userID, password)` - Hash and store
   - `ValidatePasswordStrength(password)` - Min 8 chars

### Layer 3 (Depends on Layer 2)

9. **Session Service** (`internal/auth/session.go`)
   - `Session` struct: ID, UserID, ExpiresAt, CreatedAt
   - `SessionService` struct: db
   - `CreateSession(userID)` - 32-byte random ID, 30-day expiry
   - `ValidateSession(sessionID)` - Check exists and not expired
   - `DeleteSession(sessionID)` - Logout
   - `CleanupExpiredSessions()` - Background cleanup
   - Cookie helpers: `SetSessionCookie(w, sessionID)`, `ClearSessionCookie(w)`

### Layer 4 (Depends on Layer 3)

10. **Auth Middleware** (`internal/auth/middleware.go`)
    - `AuthMiddleware` struct: sessionService, userService, keyManager
    - `RequireAuth(next http.Handler)` - Reject if no valid session
    - `OptionalAuth(next http.Handler)` - Add user to context if present
    - `GetUserID(ctx)` - Extract userID from context
    - `GetUserDB(ctx)` - Get user's encrypted database from context

11. **Auth Handlers** (`internal/auth/handlers.go`)
    - `AuthHandler` struct: all services (oidc, magic, password, session, user)
    - **Google OIDC** (uses mock in M2):
      - `HandleGoogleLogin(w, r)` - Redirect to OIDC provider
      - `HandleGoogleCallback(w, r)` - Exchange code, find/create user, session
    - **Magic Login**:
      - `HandleMagicLinkRequest(w, r)` - POST email, send magic link
      - `HandleMagicLinkVerify(w, r)` - GET with token, verify, session
    - **Email/Password**:
      - `HandleRegister(w, r)` - POST email+password, create user
      - `HandlePasswordLogin(w, r)` - POST email+password, verify, session
      - `HandlePasswordReset(w, r)` - POST email, send reset link
      - `HandlePasswordResetConfirm(w, r)` - POST token+newPassword
    - **Common**:
      - `HandleLogout(w, r)` - Delete session, clear cookie
      - `HandleWhoAmI(w, r)` - Return current user info

### Layer 5 (Depends on Layer 4)

12. **Update main.go**
    - Load MASTER_KEY from environment
    - Initialize KeyManager with master key
    - Initialize email service (mock)
    - Initialize OIDC client (mock)
    - Initialize all auth services
    - Register auth routes:
      - `GET  /auth/google` - Start Google login
      - `GET  /auth/google/callback` - Google callback
      - `POST /auth/magic` - Request magic link
      - `GET  /auth/magic/verify` - Verify magic link
      - `POST /auth/register` - Email/password registration
      - `POST /auth/login` - Email/password login
      - `POST /auth/password/reset` - Request password reset
      - `POST /auth/password/reset/confirm` - Confirm password reset
      - `POST /auth/logout` - Logout
      - `GET  /auth/whoami` - Current user
    - Wrap notes routes with `RequireAuth` middleware
    - Remove hardcoded `test-user-001`
    - Each request gets user's encrypted DB via middleware

13. **Update Notes Service**
    - Accept `*db.UserDB` parameter per-request (from context)
    - Remove `HardcodedUserID` constant

### Layer 6 (Parallel, Depends on Layer 5)

14. **Encryption Property Tests** (`internal/crypto/*_test.go`)
    - Property: DEK encrypted then decrypted equals original
    - Property: Different KEK versions produce different ciphertexts
    - Property: KEK derivation is deterministic (same inputs → same output)
    - Property: Wrong KEK fails to decrypt
    - Property: Rotated KEK can still decrypt (re-encrypted DEK)

15. **Auth Property Tests** (`internal/auth/*_test.go`)
    - `session_test.go`:
      - Property: Created session can be validated
      - Property: Expired session returns error
      - Property: Deleted session cannot be validated
      - Property: Session ID has high entropy
    - `magic_test.go`:
      - Property: Generated token verifies correctly
      - Property: Consumed token cannot be reused
      - Property: Expired token returns error
    - `password_test.go`:
      - Property: Hashed password verifies correctly (Argon2id)
      - Property: Wrong password fails verification
      - Property: Same password produces different hashes (random salt)
    - `user_test.go`:
      - Property: FindOrCreate is idempotent (same email → same user)
      - Property: User gets unique encrypted database

16. **Mock Auth Integration Tests** (`tests/auth/`)
    - Test complete flows with mock OIDC and mock email
    - `mock_oidc_test.go` - Google login flow
    - `mock_email_test.go` - Magic link and password reset flows

17. **Security Scan**
    - Add `gosec` to CI
    - Add to `scripts/ci.sh`:
      ```bash
      gosec -quiet ./...
      ```
    - Zero tolerance for high-severity findings

### Layer 7 (Depends on Layer 6)

18. **Master Test Script** (`scripts/milestone2-test.sh`)
    - Build server
    - Run encryption tests
    - Run auth property tests
    - Run mock integration tests
    - Run gosec security scan
    - Verify all pass
    - Report results

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
│   │   ├── crypto.go           # KEK derivation, DEK encryption
│   │   ├── keymanager.go       # User key management
│   │   └── crypto_test.go      # Property tests
│   ├── auth/
│   │   ├── oidc.go             # OIDC interface definition
│   │   ├── oidc_mock.go        # Mock OIDC implementation
│   │   # oidc_google.go deferred to Milestone 4
│   │   ├── magic.go            # Magic token service
│   │   ├── password.go         # Password hashing (Argon2id)
│   │   ├── session.go          # Session management
│   │   ├── user.go             # User service
│   │   ├── handlers.go         # All HTTP handlers
│   │   ├── middleware.go       # Auth middleware
│   │   └── *_test.go           # Property tests
│   ├── email/
│   │   ├── service.go          # Interface definition
│   │   ├── mock.go             # Mock implementation
│   │   └── templates.go        # Email HTML templates
│   │   # resend.go deferred to Milestone 4
│   └── db/
│       └── sql/
│           └── sessions_auth.sql  # Auth-related queries
├── tests/
│   └── auth/
│       ├── mock_oidc_test.go   # Mock OIDC integration tests
│       └── mock_email_test.go  # Mock email integration tests
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
- [ ] DEK generated on first login
- [ ] DEK encrypted with KEK and stored
- [ ] User database opened with decrypted DEK
- [ ] Key rotation works (re-encrypt DEK)
- [ ] Different users have different DEKs

### Authentication (All Mock)
- [ ] Google OIDC flow works (mock provider)
- [ ] Magic link flow works (mock email)
- [ ] Password registration and login work
- [ ] Password reset flow works (mock email)
- [ ] Sessions created and validated correctly
- [ ] Logout clears session

### Multi-User Isolation
- [ ] Each user has separate encrypted database
- [ ] User A cannot access User B's notes
- [ ] Same email across auth methods = same account

### Security
- [ ] gosec passes with no high-severity issues
- [ ] No hardcoded secrets in code
- [ ] Session IDs have 256 bits entropy
- [ ] Passwords hashed with Argon2id

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

# Install Milestone 2 dependencies
go get github.com/oauth2-proxy/mockoidc
go get golang.org/x/crypto/argon2
go get golang.org/x/crypto/hkdf

# Install security scanner
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Generate master key for testing
openssl rand -hex 32  # Save this as MASTER_KEY

# Run sqlc to generate queries
sqlc generate

# Run tests
./scripts/ci.sh quick

# Run full test suite
./scripts/ci.sh full

# Run master milestone test
./scripts/milestone2-test.sh
```
