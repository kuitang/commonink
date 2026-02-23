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

	"github.com/kuitang/agent-notes/internal/db/sessions"
	"github.com/kuitang/agent-notes/internal/db/userdb"
)

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

// NewSessionsDBFromSQL wraps an existing sql.DB as SessionsDB.
func NewSessionsDBFromSQL(sqlDB *sql.DB) *SessionsDB {
	return &SessionsDB{
		db:      sqlDB,
		queries: sessions.New(sqlDB),
	}
}

// NewUserDBFromSQL wraps an existing sql.DB as UserDB.
func NewUserDBFromSQL(userID string, sqlDB *sql.DB) *UserDB {
	return &UserDB{
		db:      sqlDB,
		queries: userdb.New(sqlDB),
		userID:  userID,
	}
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

// FTSSnippetResult represents a single FTS search result with snippet
type FTSSnippetResult struct {
	ID        string
	Title     string
	Snippet   string
	IsPublic  bool
	CreatedAt int64
	UpdatedAt int64
	Rank      float64
}

// FTSSnippetSearchResult wraps snippet results with fallback metadata.
// When a raw FTS5 query has a syntax error, the search falls back to an
// escaped version. FallbackApplied is true in that case, with the original
// error and the corrected query available for the caller to surface.
type FTSSnippetSearchResult struct {
	Results         []FTSSnippetResult
	FallbackApplied bool
	OriginalError   string // coarse error code (empty if no fallback)
	CorrectedQuery  string // The escaped query used in fallback (empty if no fallback)
}

// EscapeFTS5Query converts human-friendly search input into safe FTS5 MATCH syntax.
// Designed for typeahead search bars — supports prefix matching, OR, quoted phrases,
// and exclusion via - prefix.
//
// Syntax supported:
//   - bare word     → prefix match:  pub → pub*
//   - OR            → FTS5 OR:       cat OR dog → cat* OR dog*
//   - "phrase"      → exact phrase:  "hello world" → "hello world"
//   - -word         → exclusion:     -spam → NOT spam*
//   - implicit AND for adjacent terms
//
// For raw FTS5 syntax (LLM/API callers), use SearchNotesWithSnippets which
// passes queries through directly and only falls back to this on syntax error.
func EscapeFTS5Query(query string) string {
	query = strings.ReplaceAll(query, "\x00", "")
	tokens := tokenizeHumanSearch(query)

	// First pass: convert tokens to FTS5 terms
	var terms []string
	for _, tok := range tokens {
		switch {
		case tok.isPhrase:
			phrase := sanitizeFTS5Word(tok.text)
			if phrase != "" {
				terms = append(terms, `"`+strings.ReplaceAll(tok.text, `"`, `""`)+`"`)
			}
		case strings.EqualFold(tok.text, "OR"):
			terms = append(terms, "OR")
		case strings.HasPrefix(tok.text, "-") && len(tok.text) > 1:
			clean := sanitizeFTS5Word(tok.text[1:])
			if clean != "" {
				terms = append(terms, "NOT "+clean+"*")
			}
		default:
			clean := sanitizeFTS5Word(tok.text)
			if clean != "" {
				terms = append(terms, clean+"*")
			}
		}
	}

	// Check if we have any positive (non-NOT) terms
	hasPositive := false
	for _, term := range terms {
		if term != "OR" && !strings.HasPrefix(term, "NOT ") {
			hasPositive = true
			break
		}
	}

	// If only NOT terms, NOT is invalid (binary operator in FTS5). Convert to positive.
	if !hasPositive {
		for i, term := range terms {
			if strings.HasPrefix(term, "NOT ") {
				terms[i] = strings.TrimPrefix(term, "NOT ")
			}
		}
	}

	// Second pass: remove invalid OR positions (leading, trailing, consecutive)
	var parts []string
	for _, term := range terms {
		if term == "OR" {
			if len(parts) == 0 || parts[len(parts)-1] == "OR" {
				continue
			}
			parts = append(parts, term)
		} else {
			parts = append(parts, term)
		}
	}
	// Remove trailing OR
	for len(parts) > 0 && parts[len(parts)-1] == "OR" {
		parts = parts[:len(parts)-1]
	}

	// Third pass: NOT is a binary operator in FTS5 and cannot start a group.
	// If a group starts with NOT (at query start or right after OR), degrade it
	// to a positive term so the final query always remains syntactically valid.
	var normalized []string
	hasPositiveInGroup := false
	for _, term := range parts {
		if term == "OR" {
			if len(normalized) == 0 || normalized[len(normalized)-1] == "OR" {
				continue
			}
			normalized = append(normalized, term)
			hasPositiveInGroup = false
			continue
		}

		if strings.HasPrefix(term, "NOT ") && !hasPositiveInGroup {
			term = strings.TrimPrefix(term, "NOT ")
		}

		if term == "" {
			continue
		}
		normalized = append(normalized, term)
		if !strings.HasPrefix(term, "NOT ") {
			hasPositiveInGroup = true
		}
	}
	// Remove trailing OR again after normalization.
	for len(normalized) > 0 && normalized[len(normalized)-1] == "OR" {
		normalized = normalized[:len(normalized)-1]
	}

	if len(normalized) == 0 {
		return ""
	}
	return strings.Join(normalized, " ")
}

// searchToken represents a parsed token from human search input.
type searchToken struct {
	text     string // the token text (without surrounding quotes for phrases)
	isPhrase bool   // true if this was a "quoted phrase"
}

// tokenizeHumanSearch splits search input into tokens, preserving quoted phrases.
func tokenizeHumanSearch(input string) []searchToken {
	var tokens []searchToken
	i := 0
	for i < len(input) {
		// Skip whitespace
		if input[i] == ' ' || input[i] == '\t' {
			i++
			continue
		}
		// Quoted phrase
		if input[i] == '"' {
			end := strings.IndexByte(input[i+1:], '"')
			if end >= 0 {
				tokens = append(tokens, searchToken{text: input[i+1 : i+1+end], isPhrase: true})
				i = i + 1 + end + 1
			} else {
				// Unclosed quote: treat rest as phrase
				tokens = append(tokens, searchToken{text: input[i+1:], isPhrase: true})
				break
			}
			continue
		}
		// Regular word (until next space or quote)
		end := i + 1
		for end < len(input) && input[end] != ' ' && input[end] != '\t' && input[end] != '"' {
			end++
		}
		tokens = append(tokens, searchToken{text: input[i:end]})
		i = end
	}
	return tokens
}

// sanitizeFTS5Word strips characters that cause FTS5 syntax errors.
// Keeps letters, digits, and underscore (safe in FTS5 tokens).
func sanitizeFTS5Word(word string) string {
	clean := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r > 127 {
			return r
		}
		return -1
	}, word)
	return strings.ToLower(clean)
}

// GetTotalNotesSize returns the total size of all notes (title + content) in bytes.
// This is used for storage limit enforcement.
func (u *UserDB) GetTotalNotesSize(ctx context.Context) (int64, error) {
	var totalSize int64
	err := u.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(length(title) + length(content)), 0) FROM notes WHERE deleted_at IS NULL`,
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
	if escapedQuery == "" {
		return nil, nil
	}

	rows, err := u.db.QueryContext(ctx, `
		SELECT n.id, n.title, n.content, n.is_public, n.created_at, n.updated_at, rank
		FROM notes n
		JOIN fts_notes f ON n.rowid = f.rowid
		WHERE fts_notes MATCH ? AND n.deleted_at IS NULL
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
	if escapedQuery == "" {
		return 0, nil
	}

	var count int64
	err := u.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM notes n
		JOIN fts_notes f ON n.rowid = f.rowid
		WHERE fts_notes MATCH ? AND n.deleted_at IS NULL
	`, escapedQuery).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("FTS count failed: %w", err)
	}
	return count, nil
}

// isFTS5SyntaxError checks if an error is an FTS5 query syntax error.
func isFTS5SyntaxError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "fts5: syntax error") ||
		strings.Contains(msg, "fts5: parse error") ||
		strings.Contains(msg, "unterminated string") ||
		strings.Contains(msg, "no such column") ||
		strings.Contains(msg, "unknown special query")
}

// SearchNotesWithSnippets performs FTS5 search returning snippets instead of full content.
// Tries raw FTS5 query syntax first (supporting AND/OR/NOT/prefix*/NEAR), falls back
// to phrase-escaped version on syntax errors.
// Column weighting: title matches weighted 5x higher than content (bm25 weights 5.0, 1.0).
// Snippet: auto-selects best column, wraps matches in **bold**, ~32 tokens of context.
// Returns FTSSnippetSearchResult with fallback metadata when the raw query had a syntax error.
func (u *UserDB) SearchNotesWithSnippets(ctx context.Context, query string, limit, offset int64) (*FTSSnippetSearchResult, error) {
	results, err := u.searchWithSnippetQuery(ctx, query, limit, offset)
	if err != nil && isFTS5SyntaxError(err) {
		escaped := EscapeFTS5Query(query)
		if escaped == "" {
			return &FTSSnippetSearchResult{FallbackApplied: true, OriginalError: "fts_query_syntax_error", CorrectedQuery: ""}, nil
		}
		fallbackResults, fallbackErr := u.searchWithSnippetQuery(ctx, escaped, limit, offset)
		if fallbackErr != nil {
			return nil, fallbackErr
		}
		return &FTSSnippetSearchResult{
			Results:         fallbackResults,
			FallbackApplied: true,
			OriginalError:   "fts_query_syntax_error",
			CorrectedQuery:  escaped,
		}, nil
	}
	if err != nil {
		return nil, err
	}
	return &FTSSnippetSearchResult{Results: results}, nil
}

func (u *UserDB) searchWithSnippetQuery(ctx context.Context, query string, limit, offset int64) ([]FTSSnippetResult, error) {
	rows, err := u.db.QueryContext(ctx, `
		SELECT n.id, n.title,
		       snippet(fts_notes, -1, '**', '**', '...', 32) as snippet,
		       n.is_public, n.created_at, n.updated_at,
		       bm25(fts_notes, 5.0, 1.0) as rank
		FROM notes n
		JOIN fts_notes f ON n.rowid = f.rowid
		WHERE fts_notes MATCH ? AND n.deleted_at IS NULL
		ORDER BY rank
		LIMIT ? OFFSET ?
	`, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("FTS snippet search failed: %w", err)
	}
	defer rows.Close()

	var results []FTSSnippetResult
	for rows.Next() {
		var r FTSSnippetResult
		var isPublic sql.NullInt64
		var snippet sql.NullString
		if err := rows.Scan(&r.ID, &r.Title, &snippet, &isPublic, &r.CreatedAt, &r.UpdatedAt, &r.Rank); err != nil {
			return nil, fmt.Errorf("failed to scan FTS snippet result: %w", err)
		}
		if isPublic.Valid && isPublic.Int64 >= 1 {
			r.IsPublic = true
		}
		if snippet.Valid {
			r.Snippet = snippet.String
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating FTS snippet results: %w", err)
	}
	return results, nil
}

// MigrateUserDB applies idempotent schema migrations to an existing user database.
// This handles adding new columns (like deleted_at) to databases created before the schema change.
// SQLite ADD COLUMN errors if the column exists, so we catch and ignore that specific error.
func (u *UserDB) MigrateUserDB() error {
	statements := strings.Split(UserDBMigrations, ";")
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		_, err := u.db.Exec(stmt)
		if err != nil {
			// Ignore "duplicate column name" errors from ADD COLUMN
			if strings.Contains(err.Error(), "duplicate column name") {
				continue
			}
			return fmt.Errorf("migration failed: %w", err)
		}
	}
	return nil
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
		dsn := appendSQLiteParams(dbPath, sqliteCommonParams())

		// Open unencrypted SQLite database
		db, err := sql.Open(SQLiteDriverName, dsn)
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

	return NewSessionsDBFromSQL(sessionsDB), nil
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
		return NewUserDBFromSQL(userID, db), nil
	}
	userDBsMu.RUnlock()

	// Acquire write lock to create new connection
	userDBsMu.Lock()
	defer userDBsMu.Unlock()

	// Double-check after acquiring write lock (race condition prevention)
	if db, exists := userDBs[userID]; exists {
		return NewUserDBFromSQL(userID, db), nil
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
	dsn = appendSQLiteParams(dsn, sqliteCommonParams())

	// Open encrypted SQLite database
	db, err := sql.Open(SQLiteDriverName, dsn)
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

	// Apply idempotent migrations for existing databases
	udb := NewUserDBFromSQL(userID, db)
	if err := udb.MigrateUserDB(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate user schema for %s: %w", userID, err)
	}

	// Cache the connection
	userDBs[userID] = db

	return NewUserDBFromSQL(userID, db), nil
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

func sqliteCommonParams() string {
	// Production-safe defaults: WAL + NORMAL provides good throughput while preserving safety.
	return "_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=5000&_foreign_keys=on"
}

func appendSQLiteParams(dsn, params string) string {
	if strings.Contains(dsn, "?") {
		return dsn + "&" + params
	}
	return dsn + "?" + params
}

// Close closes the SessionsDB connection.
func (s *SessionsDB) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Close closes the UserDB connection. Only needed for in-memory databases
// that are not cached by the package.
func (u *UserDB) Close() error {
	if u.db != nil {
		return u.db.Close()
	}
	return nil
}
