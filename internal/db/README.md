# Database Layer

This package provides the database layer for the agent-notes service, implementing encrypted per-user SQLite databases with SQLCipher.

## Architecture

The database layer consists of two types of databases:

1. **sessions.db** - Shared, unencrypted bootstrap database containing:
   - User sessions
   - Magic authentication tokens
   - User encryption keys (encrypted DEKs)
   - OAuth clients, tokens, and authorization codes

2. **{user_id}.db** - Per-user encrypted databases containing:
   - User account information
   - Notes with full-text search (FTS5)
   - API keys

## Encryption

For Milestone 1, we use a hardcoded 32-byte DEK for testing purposes. In production, the encryption key hierarchy will be:

```
Master Key (from environment/secrets)
    ↓ HKDF derivation
User KEK (Key Encryption Key, versioned)
    ↓ AES-256 encryption
User DEK (Data Encryption Key, stored in sessions.db)
    ↓ SQLCipher PRAGMA key
SQLite Database (encrypted at rest)
```

## Building and Testing

This package requires CGO and specific build flags to enable FTS5 support in SQLCipher:

```bash
# Run tests
CGO_ENABLED=1 CGO_CFLAGS="-DSQLITE_ENABLE_FTS5" CGO_LDFLAGS="-lm" go test ./internal/db/

# Build
CGO_ENABLED=1 CGO_CFLAGS="-DSQLITE_ENABLE_FTS5" CGO_LDFLAGS="-lm" go build ./internal/db/
```

**Important**: Always use these flags when building or testing this package, otherwise FTS5 will not be available.

## Usage

```go
import "github.com/kuitang/agent-notes/internal/db"

// Initialize the database layer for the test user
err := db.InitSchemas("test-user-001")
if err != nil {
    log.Fatal(err)
}

// Open the shared sessions database
sessionsDB, err := db.OpenSessionsDB()
if err != nil {
    log.Fatal(err)
}

// Open a user's encrypted database
userDB, err := db.OpenUserDB("test-user-001")
if err != nil {
    log.Fatal(err)
}

// Use the database...

// Close all connections on shutdown
defer db.CloseAll()
```

## Database Schemas

### Sessions Database (Unencrypted)

- `sessions` - Active user sessions
- `magic_tokens` - Passwordless auth tokens
- `user_keys` - Encrypted DEKs for user databases
- `oauth_clients` - Registered OAuth clients
- `oauth_tokens` - OAuth access and refresh tokens
- `oauth_codes` - OAuth authorization codes (PKCE)

### User Database (Encrypted)

- `account` - User account information
- `notes` - Notes with 1MB content limit
- `fts_notes` - FTS5 virtual table for full-text search
- `api_keys` - Programmatic access keys

The `notes` table has automatic triggers that keep the FTS5 index synchronized on INSERT, UPDATE, and DELETE operations.

## Connection Pooling

Each database uses connection pooling with:
- MaxOpenConns: 25
- MaxIdleConns: 5

User databases are cached in memory after first access to avoid reopening overhead.

## Testing

The test suite includes:

- Schema creation and validation
- Multi-user database isolation
- FTS5 trigger functionality
- Content size limits (1MB)
- Encryption verification
- Connection caching
- Graceful shutdown

Run tests with:
```bash
CGO_ENABLED=1 CGO_CFLAGS="-DSQLITE_ENABLE_FTS5" CGO_LDFLAGS="-lm" go test -v ./internal/db/
```

## Milestone 1 Limitations

For Milestone 1, the following simplifications are in place:

1. **Hardcoded DEK**: Using a fixed 32-byte encryption key instead of KEK/DEK derivation
2. **No key rotation**: Key rotation functionality will be added in later milestones
3. **Hardcoded user**: The application hardcodes `user_id = "test-user-001"`
4. **No authentication**: Authentication layer will be added in later milestones

These will be replaced with proper implementations in subsequent milestones.
