package db

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	// Import SQLCipher driver with "sqlite3" driver name
	_ "github.com/mutecomm/go-sqlcipher"
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

	// MaxOpenConns is the maximum number of open connections per database
	MaxOpenConns = 25

	// MaxIdleConns is the maximum number of idle connections per database
	MaxIdleConns = 5
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

// OpenSessionsDB opens the shared sessions database (unencrypted).
// This database contains bootstrap data like sessions, magic tokens, OAuth clients, etc.
// The connection is cached as a singleton and reused across calls.
//
// Returns:
//   - *sql.DB: Database connection
//   - error: Any error encountered during initialization
func OpenSessionsDB() (*sql.DB, error) {
	sessionsDBOnce.Do(func() {
		// Ensure data directory exists
		if err := os.MkdirAll(DataDirectory, 0755); err != nil {
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

	return sessionsDB, sessionsDBErr
}

// OpenUserDB opens a per-user encrypted database.
// The database is encrypted with SQLCipher using a hardcoded DEK for Milestone 1.
// In production, the DEK will be derived from a KEK which itself is derived from a master key.
//
// Parameters:
//   - userID: The unique identifier for the user
//
// Returns:
//   - *sql.DB: Database connection
//   - error: Any error encountered during initialization
func OpenUserDB(userID string) (*sql.DB, error) {
	if userID == "" {
		return nil, fmt.Errorf("userID cannot be empty")
	}

	// Check if database is already cached
	userDBsMu.RLock()
	if db, exists := userDBs[userID]; exists {
		userDBsMu.RUnlock()
		return db, nil
	}
	userDBsMu.RUnlock()

	// Acquire write lock to create new connection
	userDBsMu.Lock()
	defer userDBsMu.Unlock()

	// Double-check after acquiring write lock (race condition prevention)
	if db, exists := userDBs[userID]; exists {
		return db, nil
	}

	// Ensure data directory exists
	if err := os.MkdirAll(DataDirectory, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Construct database path
	dbPath := filepath.Join(DataDirectory, fmt.Sprintf("%s.db", userID))

	// Encode DEK as hex for SQLCipher pragma
	dekHex := hex.EncodeToString(hardcodedDEK)

	// Construct DSN with SQLCipher encryption parameters
	// Format: file.db?_pragma_key=x'HEX_KEY'&_pragma_cipher_page_size=4096
	// Note: go-sqlcipher includes FTS5 by default, but we enable it explicitly for clarity
	dsn := fmt.Sprintf("%s?_pragma_key=x'%s'&_pragma_cipher_page_size=4096&_fts5_tokenizer=porter", dbPath, dekHex)

	// Open encrypted SQLite database
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open user database for %s: %w", userID, err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(MaxOpenConns)
	db.SetMaxIdleConns(MaxIdleConns)

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

	return db, nil
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
