package db

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	// Import SQLCipher driver with "sqlite3" driver name
	_ "github.com/mutecomm/go-sqlcipher/v4"

	"github.com/kuitang/agent-notes/internal/db/sessions"
	"github.com/kuitang/agent-notes/internal/db/userdb"
)

// Default hardcoded DEK for Milestone 1 testing.
// This is a 32-byte (256-bit) key for SQLCipher encryption.
// In production, this will be replaced with proper KEK/DEK derivation from a master key.
var hardcodedDEK = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

const (
	// DefaultDataDirectory is the default root directory for all database files
	DefaultDataDirectory = "./data"

	// SessionsDBName is the filename for the shared sessions database
	SessionsDBName = "sessions.db"

	// MaxOpenConns is the maximum number of open connections for the sessions database.
	// SQLite is single-writer, so high connection counts are counterproductive.
	MaxOpenConns = 10

	// MaxIdleConns is the maximum number of idle connections for the sessions database
	MaxIdleConns = 2

	// UserDBMaxOpenConns is the maximum open connections per user database.
	// Each user gets their own SQLite file, so keep this low to avoid
	// connection goroutine exhaustion when many users are created in tests.
	UserDBMaxOpenConns = 2

	// UserDBMaxIdleConns is the maximum idle connections per user database
	UserDBMaxIdleConns = 1
)

var (
	// DataDirectory is the actual data directory being used (can be overridden for tests)
	DataDirectory = DefaultDataDirectory
)

var (
	// sessionsDB is the singleton shared sessions database connection
	sessionsDB     *sql.DB
	sessionsDBOnce sync.Once
	sessionsDBErr  error

	// userDBs caches per-user database connections
	userDBs   = make(map[string]*sql.DB)
	userDBsMu sync.RWMutex
)

// SessionsDB wraps the sql.DB connection and provides access to sqlc queries
type SessionsDB struct {
	db      *sql.DB
	queries *sessions.Queries
}

// UserDB wraps the sql.DB connection and provides access to sqlc queries and FTS operations
type UserDB struct {
	db      *sql.DB
	queries *userdb.Queries
	userID  string
}

// DB returns the underlying sql.DB for direct access when needed
func (s *SessionsDB) DB() *sql.DB {
	return s.db
}

// Queries returns the sqlc-generated Queries for type-safe database operations
func (s *SessionsDB) Queries() *sessions.Queries {
	return s.queries
}

// DB returns the underlying sql.DB for direct access when needed
func (u *UserDB) DB() *sql.DB {
	return u.db
}

// Queries returns the sqlc-generated Queries for type-safe database operations
func (u *UserDB) Queries() *userdb.Queries {
	return u.queries
}

// UserID returns the user ID for this database
func (u *UserDB) UserID() string {
	return u.userID
}

// FTSSearchResult represents a single FTS search result
type FTSSearchResult struct {
	ID        string
	Title     string
	Content   string
	IsPublic  int64
	CreatedAt int64
	UpdatedAt int64
	Rank      float64 // FTS5 ranking score
}

// EscapeFTS5Query escapes a user-provided search query for safe use with FTS5 MATCH.
// FTS5 has special syntax characters (AND, OR, NOT, *, ^, ", :, (, ), -, NEAR, etc.)
// that can cause parsing errors or unexpected behavior if not properly escaped.
//
// The function wraps the entire query in double quotes to treat it as a literal phrase,
// and escapes any embedded double quotes by doubling them (FTS5 escape convention).
//
// Examples:
//   - "hello" -> "\"hello\""
//   - "hello world" -> "\"hello world\""
//   - "hello \"world\"" -> "\"hello \"\"world\"\"\""
//   - "AND OR NOT" -> "\"AND OR NOT\""
//   - "test*" -> "\"test*\""
func EscapeFTS5Query(query string) string {
	// Remove null bytes which cause "unterminated string" error in FTS5
	// (SQLite's FTS5 is written in C where null bytes are string terminators)
	query = strings.ReplaceAll(query, "\x00", "")
	// Escape embedded double quotes by doubling them
	escaped := strings.ReplaceAll(query, `"`, `""`)
	// Wrap in double quotes to treat as a literal phrase
	return `"` + escaped + `"`
}

// GetTotalNotesSize returns the total size of all notes (title + content) in bytes.
// This is used for storage limit enforcement.
func (u *UserDB) GetTotalNotesSize(ctx context.Context) (int64, error) {
	var totalSize int64
	err := u.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(length(title) + length(content)), 0) FROM notes`,
	).Scan(&totalSize)
	if err != nil {
		return 0, fmt.Errorf("failed to get total notes size: %w", err)
	}
	return totalSize, nil
}

// SearchNotes performs a full-text search on notes using FTS5
// The query parameter is user-provided input that will be automatically escaped
// to prevent FTS5 syntax errors and injection attacks.
func (u *UserDB) SearchNotes(ctx context.Context, query string, limit, offset int64) ([]FTSSearchResult, error) {
	// Escape user input to prevent FTS5 syntax errors from special characters
	escapedQuery := EscapeFTS5Query(query)

	rows, err := u.db.QueryContext(ctx, `
		SELECT n.id, n.title, n.content, n.is_public, n.created_at, n.updated_at, rank
		FROM notes n
		JOIN fts_notes f ON n.rowid = f.rowid
		WHERE fts_notes MATCH ?
		ORDER BY rank
		LIMIT ? OFFSET ?
	`, escapedQuery, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("FTS search failed: %w", err)
	}
	defer rows.Close()

	var results []FTSSearchResult
	for rows.Next() {
		var r FTSSearchResult
		var isPublic sql.NullInt64
		if err := rows.Scan(&r.ID, &r.Title, &r.Content, &isPublic, &r.CreatedAt, &r.UpdatedAt, &r.Rank); err != nil {
			return nil, fmt.Errorf("failed to scan FTS result: %w", err)
		}
		if isPublic.Valid {
			r.IsPublic = isPublic.Int64
		}
		results = append(results, r)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating FTS results: %w", err)
	}

	return results, nil
}

// SearchNotesCount returns the count of notes matching the FTS5 query
// The query parameter is user-provided input that will be automatically escaped
// to prevent FTS5 syntax errors and injection attacks.
func (u *UserDB) SearchNotesCount(ctx context.Context, query string) (int64, error) {
	// Escape user input to prevent FTS5 syntax errors from special characters
	escapedQuery := EscapeFTS5Query(query)

	var count int64
	err := u.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM notes n
		JOIN fts_notes f ON n.rowid = f.rowid
		WHERE fts_notes MATCH ?
	`, escapedQuery).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("FTS count failed: %w", err)
	}
	return count, nil
}

// OpenSessionsDB opens the shared sessions database (unencrypted).
// This database contains bootstrap data like sessions, magic tokens, OAuth clients, etc.
// The connection is cached as a singleton and reused across calls.
//
// Returns:
//   - *SessionsDB: Database wrapper with sqlc queries
//   - error: Any error encountered during initialization
func OpenSessionsDB() (*SessionsDB, error) {
	sessionsDBOnce.Do(func() {
		// Ensure data directory exists
		if err := os.MkdirAll(DataDirectory, 0750); err != nil {
			sessionsDBErr = fmt.Errorf("failed to create data directory: %w", err)
			return
		}

		dbPath := filepath.Join(DataDirectory, SessionsDBName)

		// Open unencrypted SQLite database
		db, err := sql.Open("sqlite3", dbPath)
		if err != nil {
			sessionsDBErr = fmt.Errorf("failed to open sessions database: %w", err)
			return
		}

		// Configure connection pool
		db.SetMaxOpenConns(MaxOpenConns)
		db.SetMaxIdleConns(MaxIdleConns)

		// Verify connection
		if err := db.Ping(); err != nil {
			db.Close()
			sessionsDBErr = fmt.Errorf("failed to ping sessions database: %w", err)
			return
		}

		// Initialize schema
		if _, err := db.Exec(SessionsDBSchema); err != nil {
			db.Close()
			sessionsDBErr = fmt.Errorf("failed to initialize sessions schema: %w", err)
			return
		}

		sessionsDB = db
	})

	if sessionsDBErr != nil {
		return nil, sessionsDBErr
	}

	return &SessionsDB{
		db:      sessionsDB,
		queries: sessions.New(sessionsDB),
	}, nil
}

// OpenUserDB opens a per-user encrypted database.
// The database is encrypted with SQLCipher using a hardcoded DEK for Milestone 1.
// In production, the DEK will be derived from a KEK which itself is derived from a master key.
//
// Parameters:
//   - userID: The unique identifier for the user
//
// Returns:
//   - *UserDB: Database wrapper with sqlc queries
//   - error: Any error encountered during initialization
func OpenUserDB(userID string) (*UserDB, error) {
	return OpenUserDBWithDEK(userID, hardcodedDEK)
}

// OpenUserDBWithDEK opens a per-user encrypted database with a provided DEK.
// This is the production version that accepts a DEK from the KeyManager.
//
// Parameters:
//   - userID: The unique identifier for the user
//   - dek: The 32-byte Data Encryption Key for SQLCipher
//
// Returns:
//   - *UserDB: Database wrapper with sqlc queries
//   - error: Any error encountered during initialization
func OpenUserDBWithDEK(userID string, dek []byte) (*UserDB, error) {
	if userID == "" {
		return nil, fmt.Errorf("userID cannot be empty")
	}

	if len(dek) != 32 {
		return nil, fmt.Errorf("DEK must be exactly 32 bytes, got %d", len(dek))
	}

	// Check if database is already cached
	userDBsMu.RLock()
	if db, exists := userDBs[userID]; exists {
		userDBsMu.RUnlock()
		return &UserDB{
			db:      db,
			queries: userdb.New(db),
			userID:  userID,
		}, nil
	}
	userDBsMu.RUnlock()

	// Acquire write lock to create new connection
	userDBsMu.Lock()
	defer userDBsMu.Unlock()

	// Double-check after acquiring write lock (race condition prevention)
	if db, exists := userDBs[userID]; exists {
		return &UserDB{
			db:      db,
			queries: userdb.New(db),
			userID:  userID,
		}, nil
	}

	// Ensure data directory exists
	if err := os.MkdirAll(DataDirectory, 0750); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Construct database path
	dbPath := filepath.Join(DataDirectory, fmt.Sprintf("%s.db", userID))

	// Encode DEK as hex for SQLCipher pragma
	dekHex := hex.EncodeToString(dek)

	// Construct DSN with SQLCipher encryption parameters
	// Format: file.db?_pragma_key=x'HEX_KEY'&_pragma_cipher_page_size=4096
	// Note: go-sqlcipher includes FTS5 by default, but we enable it explicitly for clarity
	dsn := fmt.Sprintf("%s?_pragma_key=x'%s'&_pragma_cipher_page_size=4096&_fts5_tokenizer=porter", dbPath, dekHex)

	// Open encrypted SQLite database
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open user database for %s: %w", userID, err)
	}

	// Configure connection pool — keep low for per-user SQLite files
	db.SetMaxOpenConns(UserDBMaxOpenConns)
	db.SetMaxIdleConns(UserDBMaxIdleConns)

	// Verify connection and encryption by executing a simple query
	// If the encryption key is wrong, this will fail
	var sqliteVersion string
	if err := db.QueryRow("SELECT sqlite_version()").Scan(&sqliteVersion); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to verify user database connection for %s: %w", userID, err)
	}

	// Initialize schema
	if _, err := db.Exec(UserDBSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize user schema for %s: %w", userID, err)
	}

	// Cache the connection
	userDBs[userID] = db

	return &UserDB{
		db:      db,
		queries: userdb.New(db),
		userID:  userID,
	}, nil
}

// InitSchemas ensures all database schemas are initialized.
// This function is idempotent and safe to call multiple times.
//
// Parameters:
//   - userIDs: List of user IDs to initialize user databases for
//
// Returns:
//   - error: Any error encountered during initialization
func InitSchemas(userIDs ...string) error {
	// Initialize sessions database
	if _, err := OpenSessionsDB(); err != nil {
		return fmt.Errorf("failed to initialize sessions database: %w", err)
	}

	// Initialize user databases
	for _, userID := range userIDs {
		if _, err := OpenUserDB(userID); err != nil {
			return fmt.Errorf("failed to initialize user database for %s: %w", userID, err)
		}
	}

	return nil
}

// CloseAll closes all open database connections.
// This should be called during graceful shutdown.
//
// Returns:
//   - error: First error encountered during closing, if any
func CloseAll() error {
	var firstErr error

	// Close sessions database
	if sessionsDB != nil {
		if err := sessionsDB.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to close sessions database: %w", err)
		}
		sessionsDB = nil
	}

	// Close all user databases
	userDBsMu.Lock()
	defer userDBsMu.Unlock()

	for userID, db := range userDBs {
		if err := db.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to close user database for %s: %w", userID, err)
		}
	}

	// Clear the cache
	userDBs = make(map[string]*sql.DB)

	return firstErr
}

// GetHardcodedDEK returns the hardcoded DEK for testing purposes.
// This is only for Milestone 1. In production, DEKs will be derived securely.
func GetHardcodedDEK() []byte {
	// Return a copy to prevent external modification
	dek := make([]byte, len(hardcodedDEK))
	copy(dek, hardcodedDEK)
	return dek
}

// ResetForTesting resets all internal state for clean test isolation.
// This function is intended only for testing and should not be used in production.
// It closes all connections and resets the singleton state.
func ResetForTesting() {
	// Close all connections
	CloseAll()

	// Reset the sessions database singleton
	sessionsDBOnce = sync.Once{}
	sessionsDB = nil
	sessionsDBErr = nil

	// Note: userDBs is already cleared by CloseAll
}

// ResetUserDBsForTesting closes and clears cached per-user database connections
// without resetting the shared sessions database singleton.
// This is useful for long-lived test fixtures that need cheap state reset.
func ResetUserDBsForTesting() {
	userDBsMu.Lock()
	defer userDBsMu.Unlock()

	for userID, userDB := range userDBs {
		_ = userDB.Close()
		delete(userDBs, userID)
	}
	userDBs = make(map[string]*sql.DB)
}

// NewUserDBInMemory creates an in-memory encrypted UserDB for testing.
// This is faster than file-based databases and avoids filesystem contention.
// The database is not cached and should be closed when done.
func NewUserDBInMemory(userID string) (*UserDB, error) {
	if userID == "" {
		userID = "test-user"
	}

	// Open in-memory database with encryption
	// Using mode=memory with a shared cache allows multiple connections to the same in-memory DB
	dekHex := hex.EncodeToString(hardcodedDEK)
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared&_pragma_key=x'%s'&_pragma_cipher_page_size=4096", userID, dekHex)

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open in-memory database: %w", err)
	}

	// Keep at least one connection open to prevent the in-memory DB from being destroyed
	db.SetMaxIdleConns(1)
	db.SetMaxOpenConns(10)

	// Verify connection
	var sqliteVersion string
	if err := db.QueryRow("SELECT sqlite_version()").Scan(&sqliteVersion); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to verify in-memory database: %w", err)
	}

	// Initialize schema
	if _, err := db.Exec(UserDBSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize in-memory schema: %w", err)
	}

	return &UserDB{
		db:      db,
		queries: userdb.New(db),
		userID:  userID,
	}, nil
}

// Close closes the SessionsDB connection.
func (s *SessionsDB) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// NewSessionsDBInMemory creates an in-memory unencrypted SessionsDB for testing.
// Each call creates a fresh, independent database (no singleton caching).
// The caller is responsible for calling Close() when done.
func NewSessionsDBInMemory() (*SessionsDB, error) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("failed to open in-memory sessions database: %w", err)
	}

	db.SetMaxIdleConns(1)
	db.SetMaxOpenConns(10)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping in-memory sessions database: %w", err)
	}

	if _, err := db.Exec(SessionsDBSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize in-memory sessions schema: %w", err)
	}

	return &SessionsDB{
		db:      db,
		queries: sessions.New(db),
	}, nil
}

// Close closes the UserDB connection. Only needed for in-memory databases
// that are not cached by the package.
func (u *UserDB) Close() error {
	if u.db != nil {
		return u.db.Close()
	}
	return nil
}
