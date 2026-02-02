# Architecture Decisions - FINAL

**Date**: 2026-02-02
**Status**: ✅ ALL DECISIONS LOCKED - Implementation Ready

---

## ✅ ALL DECISIONS FINALIZED

### Database Architecture
**User Data**: ALL in user's encrypted DB
**Bootstrap Data**: Minimal in shared sessions.db

```
${DATA_ROOT}/sessions.db      -- Shared (unencrypted bootstrap)
${DATA_ROOT}/{user_id}.db     -- Per-user (encrypted with SQLCipher)
```

### Authentication - All Three Methods
1. ✅ **Magic Login** - Email with token (passwordless)
2. ✅ **Email/Password** - bcrypt hashed
3. ✅ **Google OIDC** - Sign in with Google

### Technology Stack
- **Database**: SQLCipher (github.com/mutecomm/go-sqlcipher) - WORKING
- **Rate Limiting**: stdlib golang.org/x/time/rate (per-user)
- **HTTP**: stdlib net/http (Go 1.22+ routing)
- **Payment**: LemonSqueezy only
- **Email**: Resend
- **Password**: bcrypt

### Public Notes
- **URL Pattern**: `yourdomain.com/public/{user_id}/{note_id}`

---

## ✅ 7 FOLLOW-UP QUESTIONS - ALL ANSWERED

### 1. Google + Email Auto-Linking
**Decision**: ✅ **Yes, auto-link by email**

If user signs up with magic login (email@example.com), then later tries Google Sign-In with same email:
- **Auto-link**: Same email = same account
- Update account: Set `google_sub` field
- User can now use either method

**Implementation**:
```sql
-- Look up by email first, then by google_sub
SELECT * FROM account WHERE email = ? OR google_sub = ?
```

### 2. Magic Login After Google Sign-Up
**Decision**: ✅ **Yes, allow magic login after Google**

If user signs up with Google first, they can use magic login with that email later:
- Email already verified by Google
- Magic login just works
- Both methods always available

### 3. Google Token Storage
**Decision**: ✅ **Don't store refresh tokens**

**What we store**:
- ✅ `google_sub` (Google's unique user ID)
- ✅ `email`, `name` (from ID token)
- ❌ NOT refresh token (security liability)

**Why**:
- Only using Google for authentication (not API access)
- Reduced attack surface (no long-lived tokens)
- Session-based: 30-day sessions, re-auth is one click
- User sees Google consent screen again after session expires (but Google remembers them = one click)

**Session duration**: 30 days (balance between UX and security)

### 4. Rate Limiter Memory Management
**Decision**: ✅ **Expiring cache with TTL**

**Implementation**:
```go
type rateLimiterEntry struct {
    limiter   *rate.Limiter
    lastUsed  time.Time
}

var limiters = make(map[string]*rateLimiterEntry)
var limiterMutex sync.RWMutex

// Background cleanup every hour
func cleanupLimiters() {
    ticker := time.NewTicker(1 * time.Hour)
    for range ticker.C {
        limiterMutex.Lock()
        now := time.Now()
        for userID, entry := range limiters {
            if now.Sub(entry.lastUsed) > 1*time.Hour {
                delete(limiters, userID)
            }
        }
        limiterMutex.Unlock()
    }
}
```

**Rationale**: TTL = automatic cleanup, bounded memory, simple

### 5. DB Size Calculation
**Decision**: ✅ **Calculate on login, cache in memory**

**Implementation**:
```go
// On login
func handleLogin(userID string) {
    dbSize := calculateDBSize(userID)

    // Cache in memory (keyed by user_id)
    dbSizeCache[userID] = dbSize

    // Check limit
    if dbSize > 100*1024*1024 && !isPaidUser(userID) {
        // Show upgrade prompt
        return
    }
}

// On write
func handleNoteCreate(userID string) {
    if cachedSize := dbSizeCache[userID]; cachedSize > 100MB && !isPaidUser(userID) {
        return http.StatusPaymentRequired
    }

    // Allow write
    // Note: Actual size may slightly exceed 100MB before next login,
    // but that's acceptable
}
```

**Rationale**: Fast, good enough accuracy, minimal overhead

### 6. Google OIDC Scopes
**Decision**: ✅ **Minimal scopes only**

**Scopes**: `openid email profile`

**No additional scopes**:
- ❌ NOT `offline_access` (no refresh token)
- ❌ NOT Gmail, Calendar, Drive scopes

**Rationale**: Principle of least privilege

### 7. Password + Google OIDC Both Allowed
**Decision**: ✅ **Yes, allow both methods**

Users can:
- Sign up with Google, later set a password
- Sign up with email/password, later link Google
- Use whichever method they prefer

**Database**:
```sql
CREATE TABLE account (
    user_id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,    -- NULL if not set
    google_sub TEXT,       -- NULL if not linked
    ...
);
```

**Rationale**: Maximum flexibility for users

---

## 📋 FINAL SCHEMAS

### sessions.db (Shared, Unencrypted)
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

CREATE TABLE api_keys (
    key_id TEXT PRIMARY KEY,
    key_hash TEXT NOT NULL,
    scope TEXT DEFAULT 'read_write',
    created_at INTEGER NOT NULL,
    last_used INTEGER
);
```

---

## 🎯 READY FOR IMPLEMENTATION

All decisions made. All questions answered. Proceed with Phase 1!
