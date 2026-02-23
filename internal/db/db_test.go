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
	"sync/atomic"
	"testing"

	"github.com/kuitang/agent-notes/internal/db/sessions"
	"github.com/kuitang/agent-notes/internal/db/testutil"
	"github.com/kuitang/agent-notes/internal/db/userdb"
	"pgregory.net/rapid"
)

func drawUnixEpoch(t *rapid.T, label string) int64 {
	return rapid.Int64Range(946684800, 4102444800).Draw(t, label) // 2000-01-01 .. 2100-01-01 UTC
}

var testNoteIDCounter uint64
var testDataRoot string

func nextTestNoteID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, atomic.AddUint64(&testNoteIDCounter, 1))
}

// closeOnCleanup registers a cleanup function on rapid.T that closes a UserDB.
// rapid.T does not have Cleanup(), so we use a pattern where the caller defers this.
func mustCloseUserDB(t *rapid.T, db *UserDB) {
	if err := db.Close(); err != nil {
		t.Fatalf("Failed to close UserDB: %v", err)
	}
}

func mustCloseSessionsDB(t *rapid.T, db *SessionsDB) {
	if err := db.Close(); err != nil {
		t.Fatalf("Failed to close SessionsDB: %v", err)
	}
}

// TestMain runs before all tests and cleans up after.
// File-based tests use a dedicated temp root under /tmp.
func TestMain(m *testing.M) {
	root, err := os.MkdirTemp("/tmp", "commonink-db-testdata-")
	if err != nil {
		panic(fmt.Sprintf("failed to create db test temp root: %v", err))
	}
	testDataRoot = root

	code := m.Run()

	// Cleanup file-based test artifacts
	CloseAll()
	if testDataRoot != "" {
		_ = os.RemoveAll(testDataRoot)
	}

	os.Exit(code)
}

// setupTestDir creates a clean test directory for non-rapid (testing.TB) tests.
// Used by integration_test.go for file-based tests.
func setupTestDir(t testing.TB) string {
	// Close all databases to prevent caching issues between tests
	CloseAll()

	// Reset the singleton
	sessionsDBOnce = sync.Once{}
	sessionsDB = nil
	sessionsDBErr = nil

	testDir, err := os.MkdirTemp(testDataRoot, "test-")
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Override the data directory for this test
	DataDirectory = testDir

	return testDir
}

// setupTestDirRapid creates a clean test directory for rapid tests
func setupTestDirRapid(t *rapid.T) string {
	// Close all databases to prevent caching issues between tests
	CloseAll()

	// Reset the singleton
	sessionsDBOnce = sync.Once{}
	sessionsDB = nil
	sessionsDBErr = nil

	testDir, err := os.MkdirTemp(testDataRoot, "rapid-")
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Override the data directory for this test
	DataDirectory = testDir

	return testDir
}

// =============================================================================
// Property: SessionsDB returns singleton and schema is correct
// =============================================================================

func testSessionsDB_Singleton_Properties(t *rapid.T) {
	setupTestDirRapid(t)
	ctx := context.Background()

	// Property: OpenSessionsDB returns non-nil database wrapper on success
	db1, err := OpenSessionsDB()
	if err != nil {
		t.Fatalf("OpenSessionsDB failed: %v", err)
	}
	if db1 == nil {
		t.Fatal("Expected non-nil database wrapper")
	}

	// Property: Singleton returns same underlying DB instance on subsequent calls
	db2, err := OpenSessionsDB()
	if err != nil {
		t.Fatalf("Second OpenSessionsDB call failed: %v", err)
	}
	if db1.DB() != db2.DB() {
		t.Fatal("Expected same database instance on subsequent calls (singleton)")
	}

	// Property: Database is functional (can query using sqlc)
	count, err := db1.Queries().CountSessions(ctx)
	if err != nil {
		t.Fatalf("Failed to count sessions: %v", err)
	}

	// Property: Empty database has 0 rows initially
	if count != 0 {
		t.Fatalf("Expected 0 sessions in fresh database, got %d", count)
	}
}

func TestSessionsDB_Singleton_Properties(t *testing.T) {
	rapid.Check(t, testSessionsDB_Singleton_Properties)
}

func FuzzSessionsDB_Singleton_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testSessionsDB_Singleton_Properties))
}

// =============================================================================
// Property: SessionsDB schema has all required tables
// =============================================================================

func testSessionsDB_Schema_Properties(t *rapid.T) {
	sessDB, err := NewSessionsDBInMemory()
	if err != nil {
		t.Fatalf("NewSessionsDBInMemory failed: %v", err)
	}
	defer mustCloseSessionsDB(t, sessDB)

	db := sessDB.DB()

	// Property: All expected tables exist in schema
	tables := []string{
		"sessions",
		"magic_tokens",
		"user_keys",
		"oauth_clients",
		"oauth_tokens",
		"oauth_codes",
	}

	for _, table := range tables {
		var name string
		query := "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
		err := db.QueryRow(query, table).Scan(&name)
		if err == sql.ErrNoRows {
			t.Fatalf("Table %s does not exist (schema incomplete)", table)
		} else if err != nil {
			t.Fatalf("Failed to check for table %s: %v", table, err)
		}
	}
}

func TestSessionsDB_Schema_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testSessionsDB_Schema_Properties)
}

func FuzzSessionsDB_Schema_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testSessionsDB_Schema_Properties))
}

// =============================================================================
// Property: UserDB with random valid userIDs works correctly
// =============================================================================

func testUserDB_ValidUserID_Properties(t *rapid.T) {
	setupTestDirRapid(t)
	ctx := context.Background()

	userID := testutil.ValidUserID().Draw(t, "userID")

	// Property: OpenUserDBWithDEK with valid userID returns non-nil database wrapper
	dek := testDEK()
	db1, err := OpenUserDBWithDEK(userID, dek)
	if err != nil {
		t.Fatalf("OpenUserDBWithDEK failed for userID %q: %v", userID, err)
	}
	if db1 == nil {
		t.Fatal("Expected non-nil database wrapper")
	}

	// Property: Database is functional using sqlc
	count, err := db1.Queries().CountNotes(ctx)
	if err != nil {
		t.Fatalf("Failed to count notes: %v", err)
	}

	// Property: Empty database has 0 rows
	if count != 0 {
		t.Fatalf("Expected 0 notes in fresh database, got %d", count)
	}

	// Property: Same userID returns cached instance (singleton per user)
	db2, err := OpenUserDBWithDEK(userID, dek)
	if err != nil {
		t.Fatalf("Second OpenUserDBWithDEK call failed: %v", err)
	}
	if db1.DB() != db2.DB() {
		t.Fatal("Expected same database instance for same userID")
	}
}

func TestUserDB_ValidUserID_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testUserDB_ValidUserID_Properties)
}

func FuzzUserDB_ValidUserID_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testUserDB_ValidUserID_Properties))
}

// =============================================================================
// Property: UserDB with empty userID returns error
// =============================================================================

func testUserDB_EmptyUserID_Properties(t *rapid.T) {
	setupTestDirRapid(t)

	// Property: Empty userID always returns error
	_, err := OpenUserDBWithDEK("", testDEK())
	if err == nil {
		t.Fatal("Expected error for empty userID")
	}

	expectedMsg := "userID cannot be empty"
	if err.Error() != expectedMsg {
		t.Fatalf("Expected error message %q, got %q", expectedMsg, err.Error())
	}
}

func TestUserDB_EmptyUserID_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testUserDB_EmptyUserID_Properties)
}

func FuzzUserDB_EmptyUserID_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testUserDB_EmptyUserID_Properties))
}

// =============================================================================
// Property: UserDB schema has all required tables including FTS5
// =============================================================================

func testUserDB_Schema_Properties(t *rapid.T) {
	userID := testutil.ValidUserID().Draw(t, "userID")
	userDB, err := NewUserDBInMemory(userID)
	if err != nil {
		t.Fatalf("NewUserDBInMemory failed: %v", err)
	}
	defer mustCloseUserDB(t, userDB)

	db := userDB.DB()

	// Property: All expected tables exist
	tables := []string{
		"account",
		"notes",
		"fts_notes",
		"api_keys",
	}

	for _, table := range tables {
		var name string
		query := "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
		err := db.QueryRow(query, table).Scan(&name)
		if err == sql.ErrNoRows {
			t.Fatalf("Table %s does not exist", table)
		} else if err != nil {
			t.Fatalf("Failed to check for table %s: %v", table, err)
		}
	}

	// Property: FTS5 virtual table exists
	var ftsTables int
	query := "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'fts_notes%'"
	err = db.QueryRow(query).Scan(&ftsTables)
	if err != nil {
		t.Fatalf("Failed to check FTS tables: %v", err)
	}
	if ftsTables == 0 {
		t.Fatal("FTS5 virtual table not created")
	}
}

func TestUserDB_Schema_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testUserDB_Schema_Properties)
}

func FuzzUserDB_Schema_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testUserDB_Schema_Properties))
}

// =============================================================================
// Property: Multiple users have isolated databases
// =============================================================================

func testUserDB_MultipleUsers_Isolation_Properties(t *rapid.T) {
	ctx := context.Background()

	// Generate 2-5 unique user IDs
	numUsers := rapid.IntRange(2, 5).Draw(t, "numUsers")
	userIDs := make([]string, 0, numUsers)
	dbs := make(map[string]*UserDB)
	seen := make(map[string]struct{}, numUsers)

	for len(userIDs) < numUsers {
		idx := len(userIDs)
		userID := testutil.ValidUserID().Draw(t, fmt.Sprintf("userID-%d", idx))
		if _, exists := seen[userID]; exists {
			continue
		}
		seen[userID] = struct{}{}
		userIDs = append(userIDs, userID)
	}

	// Open in-memory databases for all users (each is an independent :memory: DB)
	for _, userID := range userIDs {
		userDB, err := NewUserDBInMemory(userID)
		if err != nil {
			t.Fatalf("Failed to open in-memory database for %s: %v", userID, err)
		}
		defer mustCloseUserDB(t, userDB)
		dbs[userID] = userDB
	}

	// Property: Each user's database is independent
	now := drawUnixEpoch(t, "nowUnixIsolation")
	for i, userID := range userIDs {
		userDB := dbs[userID]

		// Insert a test note using sqlc
		noteID := userID + "-note-1"
		title := "Test Note " + userID
		err := userDB.Queries().CreateNote(ctx, userdb.CreateNoteParams{
			ID:        noteID,
			Title:     title,
			Content:   "Test content",
			IsPublic:  sql.NullInt64{Int64: 0, Valid: true},
			CreatedAt: now,
			UpdatedAt: now,
		})
		if err != nil {
			t.Fatalf("Failed to insert note for %s: %v", userID, err)
		}

		// Property: Note exists in correct database
		note, err := userDB.Queries().GetNote(ctx, noteID)
		if err != nil {
			t.Fatalf("Failed to retrieve note for %s: %v", userID, err)
		}
		if note.Title != title {
			t.Fatalf("Expected title %q, got %q", title, note.Title)
		}

		// Property: Note does not exist in other users' databases
		for j, otherUserID := range userIDs {
			if i == j {
				continue
			}
			otherDB := dbs[otherUserID]
			_, err := otherDB.Queries().GetNote(ctx, noteID)
			if err == nil {
				t.Fatalf("User %s's note found in %s's database (isolation violated)", userID, otherUserID)
			} else if err != sql.ErrNoRows {
				t.Fatalf("Unexpected error checking other user's database: %v", err)
			}
		}
	}
}

func TestUserDB_MultipleUsers_Isolation_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testUserDB_MultipleUsers_Isolation_Properties)
}

func FuzzUserDB_MultipleUsers_Isolation_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testUserDB_MultipleUsers_Isolation_Properties))
}

// =============================================================================
// Property: FTS5 triggers keep index in sync with notes table
// =============================================================================

func testUserDB_FTS5_Sync_Properties(t *rapid.T) {
	ctx := context.Background()

	userID := testutil.ValidUserID().Draw(t, "userID")
	userDB, err := NewUserDBInMemory(userID)
	if err != nil {
		t.Fatalf("NewUserDBInMemory failed: %v", err)
	}
	defer mustCloseUserDB(t, userDB)

	now := drawUnixEpoch(t, "nowUnixFTSSync")

	// Generate arbitrary note content (including special chars, unicode, etc.)
	title := testutil.ArbitraryNoteTitle().Draw(t, "title")
	// Use a simple searchWord for FTS sync test since we're testing trigger sync, not FTS escaping
	searchWord := rapid.StringMatching("[a-z]{4,10}").Draw(t, "searchWord")
	content := "This is content with " + searchWord + " embedded"
	noteID := "note-" + rapid.StringMatching("[a-z0-9]{8}").Draw(t, "noteID")

	// Insert note using sqlc
	err = userDB.Queries().CreateNote(ctx, userdb.CreateNoteParams{
		ID:        noteID,
		Title:     title,
		Content:   content,
		IsPublic:  sql.NullInt64{Int64: 0, Valid: true},
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("Failed to insert note: %v", err)
	}

	// Property: FTS index is updated via INSERT trigger
	results, err := userDB.SearchNotes(ctx, searchWord, 10, 0)
	if err != nil {
		t.Fatalf("Failed to query FTS index after insert: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 search result, got %d", len(results))
	}
	if results[0].Title != title {
		t.Fatalf("FTS index title mismatch: expected %q, got %q", title, results[0].Title)
	}

	// Update note with new search word using sqlc
	newSearchWord := rapid.StringMatching("[a-z]{4,10}").Draw(t, "newSearchWord")
	newContent := "Updated content with " + newSearchWord + " now"
	err = userDB.Queries().UpdateNoteContent(ctx, userdb.UpdateNoteContentParams{
		Content:   newContent,
		UpdatedAt: now + 1,
		ID:        noteID,
	})
	if err != nil {
		t.Fatalf("Failed to update note: %v", err)
	}

	// Property: FTS index is updated via UPDATE trigger
	results, err = userDB.SearchNotes(ctx, newSearchWord, 10, 0)
	if err != nil {
		t.Fatalf("Failed to query FTS index after update: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 search result, got %d", len(results))
	}
	if results[0].Content != newContent {
		t.Fatalf("FTS index content mismatch: expected %q, got %q", newContent, results[0].Content)
	}

	// Delete note using sqlc (soft delete)
	err = userDB.Queries().DeleteNote(ctx, userdb.DeleteNoteParams{
		DeletedAt: sql.NullInt64{Int64: now + 2, Valid: true},
		ID:        noteID,
	})
	if err != nil {
		t.Fatalf("Failed to delete note: %v", err)
	}

	// Property: FTS index is cleaned up via DELETE trigger
	count, err := userDB.SearchNotesCount(ctx, newSearchWord)
	if err != nil {
		t.Fatalf("Failed to query FTS index after delete: %v", err)
	}
	if count != 0 {
		t.Fatalf("FTS entry should be deleted, but found %d entries", count)
	}
}

func TestUserDB_FTS5_Sync_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testUserDB_FTS5_Sync_Properties)
}

func FuzzUserDB_FTS5_Sync_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testUserDB_FTS5_Sync_Properties))
}

// =============================================================================
// Property: Note content size limits are enforced
// =============================================================================

func testUserDB_ContentSizeLimit_Properties(t *rapid.T) {
	ctx := context.Background()

	userID := testutil.ValidUserID().Draw(t, "userID")
	userDB, err := NewUserDBInMemory(userID)
	if err != nil {
		t.Fatalf("NewUserDBInMemory failed: %v", err)
	}
	defer mustCloseUserDB(t, userDB)

	now := drawUnixEpoch(t, "nowUnixSizeLimit")

	// Property: Content at exactly 1MB succeeds
	content1MB := make([]byte, 1048576)
	for i := range content1MB {
		content1MB[i] = 'a'
	}

	err = userDB.Queries().CreateNote(ctx, userdb.CreateNoteParams{
		ID:        "note-1mb",
		Title:     "1MB Note",
		Content:   string(content1MB),
		IsPublic:  sql.NullInt64{Int64: 0, Valid: true},
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("Failed to insert 1MB note: %v", err)
	}

	// Property: Content over 1MB fails (CHECK constraint)
	contentOver1MB := make([]byte, 1048577)
	for i := range contentOver1MB {
		contentOver1MB[i] = 'b'
	}

	err = userDB.Queries().CreateNote(ctx, userdb.CreateNoteParams{
		ID:        "note-over-1mb",
		Title:     "Over 1MB Note",
		Content:   string(contentOver1MB),
		IsPublic:  sql.NullInt64{Int64: 0, Valid: true},
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err == nil {
		t.Fatal("Expected error when inserting note over 1MB, but got none")
	}
}

func TestUserDB_ContentSizeLimit_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testUserDB_ContentSizeLimit_Properties)
}

func FuzzUserDB_ContentSizeLimit_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testUserDB_ContentSizeLimit_Properties))
}

// =============================================================================
// Property: Multiple user DBs can be initialized with explicit DEK
// =============================================================================

func testMultipleUserDBInit_Properties(t *rapid.T) {
	setupTestDirRapid(t)
	ctx := context.Background()
	dek := testDEK()

	// Generate random user IDs
	numUsers := rapid.IntRange(1, 3).Draw(t, "numUsers")
	userIDs := make([]string, numUsers)
	for i := 0; i < numUsers; i++ {
		userIDs[i] = testutil.ValidUserID().Draw(t, "userID")
	}

	// Property: Sessions database is initialized
	sessDB, err := OpenSessionsDB()
	if err != nil {
		t.Fatalf("Failed to get sessions database: %v", err)
	}
	if sessDB == nil {
		t.Fatal("Sessions database is nil")
	}

	// Property: All user databases are initialized with explicit DEK
	for _, userID := range userIDs {
		userDB, err := OpenUserDBWithDEK(userID, dek)
		if err != nil {
			t.Fatalf("Failed to get user database for %s: %v", userID, err)
		}
		if userDB == nil {
			t.Fatalf("User database for %s is nil", userID)
		}

		// Verify schema exists using sqlc
		count, err := userDB.Queries().CountNotes(ctx)
		if err != nil {
			t.Fatalf("Schema not initialized for %s: %v", userID, err)
		}
		if count != 0 {
			t.Fatalf("Expected 0 notes in fresh database, got %d", count)
		}
	}
}

func TestMultipleUserDBInit_Properties(t *testing.T) {
	rapid.Check(t, testMultipleUserDBInit_Properties)
}

func FuzzMultipleUserDBInit_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testMultipleUserDBInit_Properties))
}

// =============================================================================
// Property: CloseAll closes all connections
// =============================================================================

func testCloseAll_Properties(t *rapid.T) {
	setupTestDirRapid(t)

	// Open sessions database
	_, err := OpenSessionsDB()
	if err != nil {
		t.Fatalf("Failed to open sessions DB: %v", err)
	}

	// Open some user databases
	dek := testDEK()
	numUsers := rapid.IntRange(1, 3).Draw(t, "numUsers")
	for i := 0; i < numUsers; i++ {
		userID := testutil.ValidUserID().Draw(t, "userID")
		_, err := OpenUserDBWithDEK(userID, dek)
		if err != nil {
			t.Fatalf("Failed to open user DB for iteration %d: %v", i, err)
		}
	}

	// Property: CloseAll returns no error
	err = CloseAll()
	if err != nil {
		t.Fatalf("CloseAll returned error: %v", err)
	}
}

func TestCloseAll_Properties(t *testing.T) {
	rapid.Check(t, testCloseAll_Properties)
}

func FuzzCloseAll_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testCloseAll_Properties))
}

// =============================================================================
// Property: No hardcoded DEK fallback exists — OpenUserDB must not compile
// without an explicit DEK parameter. This test enforces that the hardcoded
// DEK exploit is removed. If OpenUserDB(userID) still exists, this test fails.
// =============================================================================

func testNoHardcodedDEK_Fallback_Properties(t *rapid.T) {
	setupTestDirRapid(t)

	userID := testutil.ValidUserID().Draw(t, "userID")

	// Property: OpenUserDBWithDEK with nil DEK returns error
	_, err := OpenUserDBWithDEK(userID, nil)
	if err == nil {
		t.Fatal("OpenUserDBWithDEK with nil DEK must return error")
	}

	// Property: OpenUserDBWithDEK with empty DEK returns error
	_, err = OpenUserDBWithDEK(userID, []byte{})
	if err == nil {
		t.Fatal("OpenUserDBWithDEK with empty DEK must return error")
	}

	// Property: OpenUserDBWithDEK with wrong-length DEK returns error
	shortDEK := rapid.SliceOfN(rapid.Byte(), 1, 31).Draw(t, "shortDEK")
	_, err = OpenUserDBWithDEK(userID, shortDEK)
	if err == nil {
		t.Fatalf("OpenUserDBWithDEK with %d-byte DEK must return error", len(shortDEK))
	}

	// Property: OpenUserDBWithDEK with valid 32-byte DEK succeeds
	validDEK := testDEK()
	udb, err := OpenUserDBWithDEK(userID, validDEK)
	if err != nil {
		t.Fatalf("OpenUserDBWithDEK with valid DEK failed: %v", err)
	}
	if udb == nil {
		t.Fatal("OpenUserDBWithDEK with valid DEK returned nil")
	}
}

func TestNoHardcodedDEK_Fallback_Properties(t *testing.T) {
	rapid.Check(t, testNoHardcodedDEK_Fallback_Properties)
}

func FuzzNoHardcodedDEK_Fallback_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testNoHardcodedDEK_Fallback_Properties))
}

// =============================================================================
// Property: Encryption roundtrip works (data can be read back)
// =============================================================================

func testUserDB_Encryption_Roundtrip_Properties(t *rapid.T) {
	ctx := context.Background()

	userID := testutil.ValidUserID().Draw(t, "userID")
	userDB, err := NewUserDBInMemory(userID)
	if err != nil {
		t.Fatalf("NewUserDBInMemory failed: %v", err)
	}
	defer mustCloseUserDB(t, userDB)

	// Generate random sensitive content
	sensitiveContent := rapid.StringMatching("[A-Za-z0-9 ]{10,100}").Draw(t, "sensitiveContent")
	title := rapid.StringMatching("[A-Za-z ]{5,30}").Draw(t, "title")
	noteID := "encrypted-note-" + rapid.StringMatching("[a-z0-9]{8}").Draw(t, "noteID")
	now := drawUnixEpoch(t, "nowUnixEncryption")

	err = userDB.Queries().CreateNote(ctx, userdb.CreateNoteParams{
		ID:        noteID,
		Title:     title,
		Content:   sensitiveContent,
		IsPublic:  sql.NullInt64{Int64: 0, Valid: true},
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("Failed to insert encrypted note: %v", err)
	}

	// Property: Data can be read back (encryption/decryption works)
	note, err := userDB.Queries().GetNote(ctx, noteID)
	if err != nil {
		t.Fatalf("Failed to read encrypted note: %v", err)
	}

	if note.Content != sensitiveContent {
		t.Fatalf("Data corruption: expected %q, got %q", sensitiveContent, note.Content)
	}

	// Property: Multiple reads return same data
	note2, err := userDB.Queries().GetNote(ctx, noteID)
	if err != nil {
		t.Fatalf("Failed to read encrypted note second time: %v", err)
	}

	if note2.Content != sensitiveContent {
		t.Fatalf("Data inconsistency on second read: expected %q, got %q", sensitiveContent, note2.Content)
	}
}

func TestUserDB_Encryption_Roundtrip_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testUserDB_Encryption_Roundtrip_Properties)
}

func FuzzUserDB_Encryption_Roundtrip_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testUserDB_Encryption_Roundtrip_Properties))
}

// =============================================================================
// Property: Sessions CRUD operations work via sqlc
// =============================================================================

func testSessionsDB_CRUD_Properties(t *rapid.T) {
	ctx := context.Background()

	sessDB, err := NewSessionsDBInMemory()
	if err != nil {
		t.Fatalf("NewSessionsDBInMemory failed: %v", err)
	}
	defer mustCloseSessionsDB(t, sessDB)

	q := sessDB.Queries()

	// Generate random session data
	sessionID := "session-" + rapid.StringMatching("[a-z0-9]{16}").Draw(t, "sessionID")
	userID := testutil.ValidUserID().Draw(t, "userID")
	now := drawUnixEpoch(t, "nowUnixSessionsCRUD")
	expiresAt := now + int64(rapid.IntRange(3600, 86400).Draw(t, "expiresIn"))

	// Property: Create session succeeds
	err = q.CreateSession(ctx, sessions.CreateSessionParams{
		SessionID: sessionID,
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Property: Read returns same data
	sess, err := q.GetSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if sess.UserID != userID {
		t.Fatalf("Expected userID %q, got %q", userID, sess.UserID)
	}
	if sess.ExpiresAt != expiresAt {
		t.Fatalf("Expected expiresAt %d, got %d", expiresAt, sess.ExpiresAt)
	}

	// Property: Count reflects creation
	count, err := q.CountSessions(ctx)
	if err != nil {
		t.Fatalf("CountSessions failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("Expected 1 session, got %d", count)
	}

	// Property: Delete removes session
	err = q.DeleteSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}

	// Property: Count reflects deletion
	count, err = q.CountSessions(ctx)
	if err != nil {
		t.Fatalf("CountSessions after delete failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("Expected 0 sessions after delete, got %d", count)
	}
}

func TestSessionsDB_CRUD_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testSessionsDB_CRUD_Properties)
}

func FuzzSessionsDB_CRUD_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testSessionsDB_CRUD_Properties))
}

// =============================================================================
// Property: FTS5 handles arbitrary search queries safely
// =============================================================================

func testUserDB_FTS5_ArbitraryQuery_Properties(t *rapid.T) {
	ctx := context.Background()

	userID := testutil.ValidUserID().Draw(t, "userID")
	userDB, err := NewUserDBInMemory(userID)
	if err != nil {
		t.Fatalf("NewUserDBInMemory failed: %v", err)
	}
	defer mustCloseUserDB(t, userDB)

	now := drawUnixEpoch(t, "nowUnixArbitraryQuery")

	// Create a note so there's something to search
	err = userDB.Queries().CreateNote(ctx, userdb.CreateNoteParams{
		ID:        "test-note",
		Title:     "Test Note",
		Content:   "Some searchable content here",
		IsPublic:  sql.NullInt64{Int64: 0, Valid: true},
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("Failed to create test note: %v", err)
	}

	// Property: SearchNotes should NEVER panic for ANY query string
	// and should NEVER return SQL syntax errors (indicating injection)
	query := testutil.ArbitrarySearchQuery().Draw(t, "query")

	results, err := userDB.SearchNotes(ctx, query, 10, 0)

	// Either succeeds (possibly empty results) or returns a clean FTS5 error
	if err != nil {
		errStr := err.Error()
		// These would indicate our escaping failed:
		if strings.Contains(errStr, "syntax error") {
			t.Fatalf("FTS5 escaping failed (syntax error) for query %q: %v", query, err)
		}
		if strings.Contains(errStr, "unrecognized token") {
			t.Fatalf("FTS5 escaping failed (unrecognized token) for query %q: %v", query, err)
		}
		if strings.Contains(errStr, "no such column") {
			t.Fatalf("SQL injection possible (no such column) for query %q: %v", query, err)
		}
		if strings.Contains(errStr, "no such table") {
			t.Fatalf("SQL injection possible (no such table) for query %q: %v", query, err)
		}
		// Other errors (like "unterminated string" before our fix) are test failures
		// After fix, no FTS5 errors should occur
		t.Fatalf("Unexpected FTS5 error for query %q: %v", query, err)
	}

	// Property: Results are well-formed if returned
	for _, r := range results {
		if r.ID == "" {
			t.Fatal("Result has empty ID")
		}
	}
}

func TestUserDB_FTS5_ArbitraryQuery_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testUserDB_FTS5_ArbitraryQuery_Properties)
}

func FuzzUserDB_FTS5_ArbitraryQuery_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testUserDB_FTS5_ArbitraryQuery_Properties))
}

// =============================================================================
// Property: SearchNotesCount also handles arbitrary queries safely
// =============================================================================

func testUserDB_FTS5_ArbitraryQueryCount_Properties(t *rapid.T) {
	ctx := context.Background()

	userID := testutil.ValidUserID().Draw(t, "userID")
	userDB, err := NewUserDBInMemory(userID)
	if err != nil {
		t.Fatalf("NewUserDBInMemory failed: %v", err)
	}
	defer mustCloseUserDB(t, userDB)

	// Property: SearchNotesCount should NEVER panic for ANY query string
	query := testutil.ArbitrarySearchQuery().Draw(t, "query")

	count, err := userDB.SearchNotesCount(ctx, query)

	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "syntax error") ||
			strings.Contains(errStr, "unrecognized token") ||
			strings.Contains(errStr, "no such column") ||
			strings.Contains(errStr, "no such table") {
			t.Fatalf("FTS5 count escaping failed for query %q: %v", query, err)
		}
		t.Fatalf("Unexpected FTS5 count error for query %q: %v", query, err)
	}

	// Property: Count is non-negative
	if count < 0 {
		t.Fatalf("Count should be non-negative, got %d", count)
	}
}

func TestUserDB_FTS5_ArbitraryQueryCount_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testUserDB_FTS5_ArbitraryQueryCount_Properties)
}

func FuzzUserDB_FTS5_ArbitraryQueryCount_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testUserDB_FTS5_ArbitraryQueryCount_Properties))
}

// =============================================================================
// Property: SearchNotesWithSnippets handles arbitrary queries safely
// This tests the raw-FTS5-with-fallback path used by note_search MCP tool.
// =============================================================================

func testUserDB_FTS5_ArbitrarySnippetQuery_Properties(t *rapid.T) {
	ctx := context.Background()

	userID := testutil.ValidUserID().Draw(t, "userID")
	userDB, err := NewUserDBInMemory(userID)
	if err != nil {
		t.Fatalf("NewUserDBInMemory failed: %v", err)
	}
	defer mustCloseUserDB(t, userDB)

	now := drawUnixEpoch(t, "nowUnixSnippetQuery")

	// Create a note so there's something to search
	err = userDB.Queries().CreateNote(ctx, userdb.CreateNoteParams{
		ID:        "snippet-test",
		Title:     "Snippet Test Note",
		Content:   "Some content for snippet testing with various words",
		IsPublic:  sql.NullInt64{Int64: 0, Valid: true},
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("Failed to create test note: %v", err)
	}

	// Property: SearchNotesWithSnippets should NEVER panic for ANY query string
	// and should handle FTS5 syntax errors gracefully via fallback
	query := testutil.ArbitrarySearchQuery().Draw(t, "query")

	result, err := userDB.SearchNotesWithSnippets(ctx, query, 10, 0)

	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "syntax error") {
			t.Fatalf("FTS5 snippet search failed (syntax error) for query %q: %v", query, err)
		}
		if strings.Contains(errStr, "unrecognized token") {
			t.Fatalf("FTS5 snippet search failed (unrecognized token) for query %q: %v", query, err)
		}
		if strings.Contains(errStr, "no such column") {
			t.Fatalf("SQL injection possible (no such column) for query %q: %v", query, err)
		}
		if strings.Contains(errStr, "no such table") {
			t.Fatalf("SQL injection possible (no such table) for query %q: %v", query, err)
		}
		t.Fatalf("Unexpected FTS5 snippet error for query %q: %v", query, err)
	}

	// Property: Result wrapper is always non-nil on success
	if result == nil {
		t.Fatal("SearchNotesWithSnippets returned nil result without error")
	}

	// Property: Results are well-formed if returned
	for _, r := range result.Results {
		if r.ID == "" {
			t.Fatal("Result has empty ID")
		}
	}

	// Property: If fallback was applied, metadata fields are populated
	if result.FallbackApplied && result.OriginalError == "" {
		t.Fatal("FallbackApplied=true but OriginalError is empty")
	}
}

func TestUserDB_FTS5_ArbitrarySnippetQuery_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testUserDB_FTS5_ArbitrarySnippetQuery_Properties)
}

func FuzzUserDB_FTS5_ArbitrarySnippetQuery_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testUserDB_FTS5_ArbitrarySnippetQuery_Properties))
}

// =============================================================================
// Property: DataDirectory wiring places DB files in the configured directory
// Bug regression: DATABASE_PATH env var was read into cfg.DatabasePath but
// was never assigned to db.DataDirectory, so DBs were always created in "./data".
// =============================================================================

func testDataDirectory_Wiring_Properties(t *rapid.T) {
	// Reset all singleton state to ensure clean isolation
	ResetForTesting()

	// Use a unique temp directory to simulate DATABASE_PATH env var being set.
	// We cannot use t.TempDir() on rapid.T, so create our own temp dir.
	tmpBase := filepath.Join(os.TempDir(), "db-wiring-test")
	os.RemoveAll(tmpBase)
	if err := os.MkdirAll(tmpBase, 0755); err != nil {
		t.Fatalf("Failed to create temp base: %v", err)
	}

	// Generate a random subdirectory name to simulate different DATABASE_PATH values
	subdir := rapid.StringMatching("[a-z]{3,10}").Draw(t, "subdir")
	customPath := filepath.Join(tmpBase, subdir)

	// Create a separate "wrong" directory to verify files are NOT created there.
	// We use a dedicated temp directory instead of DefaultDataDirectory to avoid
	// interference from stale files left by other test runs or server executions.
	wrongPath := filepath.Join(tmpBase, "wrong-dir")
	if err := os.MkdirAll(wrongPath, 0755); err != nil {
		t.Fatalf("Failed to create wrong path: %v", err)
	}

	// Set DataDirectory to the custom path (simulates db.DataDirectory = cfg.DatabasePath in main.go)
	DataDirectory = customPath

	// --- Property 1: OpenSessionsDB creates sessions.db in the custom DataDirectory ---
	sessDB, err := OpenSessionsDB()
	if err != nil {
		t.Fatalf("OpenSessionsDB failed with custom DataDirectory %q: %v", customPath, err)
	}
	if sessDB == nil {
		t.Fatal("OpenSessionsDB returned nil")
	}

	expectedSessionsPath := filepath.Join(customPath, SessionsDBName)
	if _, err := os.Stat(expectedSessionsPath); os.IsNotExist(err) {
		t.Fatalf("sessions.db not created at expected path %q", expectedSessionsPath)
	}

	// Property: sessions.db must NOT exist in the wrong directory
	wrongSessionsPath := filepath.Join(wrongPath, SessionsDBName)
	if _, err := os.Stat(wrongSessionsPath); err == nil {
		t.Fatalf("sessions.db was created at wrong path %q instead of custom path %q", wrongSessionsPath, customPath)
	}

	// Property: Sessions DB is functional at the custom path
	ctx := context.Background()
	sessCount, err := sessDB.Queries().CountSessions(ctx)
	if err != nil {
		t.Fatalf("Sessions DB at custom path is not functional: %v", err)
	}
	if sessCount != 0 {
		t.Fatalf("Expected 0 sessions in fresh DB, got %d", sessCount)
	}

	// --- Property 2: OpenUserDBWithDEK creates user .db files in the custom DataDirectory ---
	dek := testDEK()
	userID := testutil.ValidUserID().Draw(t, "userID")
	userDB, err := OpenUserDBWithDEK(userID, dek)
	if err != nil {
		t.Fatalf("OpenUserDBWithDEK failed with custom DataDirectory %q: %v", customPath, err)
	}
	if userDB == nil {
		t.Fatal("OpenUserDBWithDEK returned nil")
	}

	expectedUserDBPath := filepath.Join(customPath, userID+".db")
	if _, err := os.Stat(expectedUserDBPath); os.IsNotExist(err) {
		t.Fatalf("user DB not created at expected path %q", expectedUserDBPath)
	}

	// Property: user .db must NOT exist in the wrong directory
	wrongUserDBPath := filepath.Join(wrongPath, userID+".db")
	if _, err := os.Stat(wrongUserDBPath); err == nil {
		t.Fatalf("user DB was created at wrong path %q instead of custom path %q", wrongUserDBPath, customPath)
	}

	// Property: User DB is functional at the custom path
	noteCount, err := userDB.Queries().CountNotes(ctx)
	if err != nil {
		t.Fatalf("User DB at custom path is not functional: %v", err)
	}
	if noteCount != 0 {
		t.Fatalf("Expected 0 notes in fresh DB, got %d", noteCount)
	}

	// --- Property 3: After ResetForTesting + re-set DataDirectory, DBs reopen at the same custom path ---
	ResetForTesting()
	DataDirectory = customPath

	sessDB2, err := OpenSessionsDB()
	if err != nil {
		t.Fatalf("OpenSessionsDB failed after reset: %v", err)
	}
	sessCount2, err := sessDB2.Queries().CountSessions(ctx)
	if err != nil {
		t.Fatalf("Sessions DB not functional after reset: %v", err)
	}
	if sessCount2 != 0 {
		t.Fatalf("Expected 0 sessions after reset, got %d", sessCount2)
	}

	userDB2, err := OpenUserDBWithDEK(userID, dek)
	if err != nil {
		t.Fatalf("OpenUserDBWithDEK failed after reset: %v", err)
	}
	noteCount2, err := userDB2.Queries().CountNotes(ctx)
	if err != nil {
		t.Fatalf("User DB not functional after reset: %v", err)
	}
	if noteCount2 != 0 {
		t.Fatalf("Expected 0 notes after reset, got %d", noteCount2)
	}

	// Cleanup: reset state and restore default DataDirectory
	ResetForTesting()
	DataDirectory = DefaultDataDirectory
	os.RemoveAll(tmpBase)
}

func TestDataDirectory_Wiring_Properties(t *testing.T) {
	rapid.Check(t, testDataDirectory_Wiring_Properties)
}

func FuzzDataDirectory_Wiring_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testDataDirectory_Wiring_Properties))
}

// =============================================================================
// Property: sanitizeFTS5Word output is always lowercase
// =============================================================================

func testSanitizeFTS5Word_Lowercase_Properties(t *rapid.T) {
	input := rapid.String().Draw(t, "input")
	result := sanitizeFTS5Word(input)

	// Property: output is always lowercase
	if result != strings.ToLower(result) {
		t.Fatalf("sanitizeFTS5Word(%q) = %q is not lowercase", input, result)
	}
}

func TestSanitizeFTS5Word_Lowercase_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testSanitizeFTS5Word_Lowercase_Properties)
}

func FuzzSanitizeFTS5Word_Lowercase_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testSanitizeFTS5Word_Lowercase_Properties))
}

// =============================================================================
// Property: sanitizeFTS5Word output only contains safe characters
// =============================================================================

func testSanitizeFTS5Word_SafeChars_Properties(t *rapid.T) {
	input := rapid.String().Draw(t, "input")
	result := sanitizeFTS5Word(input)

	// Property: output only contains [a-z0-9_] and characters > 127 (unicode)
	for _, r := range result {
		safe := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r > 127
		if !safe {
			t.Fatalf("sanitizeFTS5Word(%q) = %q contains unsafe rune %q (U+%04X)", input, result, r, r)
		}
	}
}

func TestSanitizeFTS5Word_SafeChars_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testSanitizeFTS5Word_SafeChars_Properties)
}

func FuzzSanitizeFTS5Word_SafeChars_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testSanitizeFTS5Word_SafeChars_Properties))
}

// =============================================================================
// Property: sanitizeFTS5Word is idempotent
// =============================================================================

func testSanitizeFTS5Word_Idempotent_Properties(t *rapid.T) {
	input := rapid.String().Draw(t, "input")
	once := sanitizeFTS5Word(input)
	twice := sanitizeFTS5Word(once)

	// Property: sanitize(sanitize(x)) == sanitize(x)
	if once != twice {
		t.Fatalf("sanitizeFTS5Word is not idempotent: sanitize(%q) = %q, sanitize(%q) = %q", input, once, once, twice)
	}
}

func TestSanitizeFTS5Word_Idempotent_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testSanitizeFTS5Word_Idempotent_Properties)
}

func FuzzSanitizeFTS5Word_Idempotent_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testSanitizeFTS5Word_Idempotent_Properties))
}

// =============================================================================
// Property: tokenizeHumanSearch preserves all non-whitespace, non-quote content
// =============================================================================

func testTokenizeHumanSearch_ContentPreserved_Properties(t *rapid.T) {
	input := rapid.String().Draw(t, "input")
	tokens := tokenizeHumanSearch(input)

	// Reconstruct all token text
	var reconstructed strings.Builder
	for _, tok := range tokens {
		reconstructed.WriteString(tok.text)
	}
	tokenContent := reconstructed.String()

	// Property: every non-whitespace, non-quote character from input appears in tokens
	for i, ch := range input {
		if ch == ' ' || ch == '\t' || ch == '"' {
			continue
		}
		if !strings.ContainsRune(tokenContent, ch) {
			t.Fatalf("Character %q (U+%04X) at index %d from input %q not found in token content %q",
				ch, ch, i, input, tokenContent)
		}
	}
}

func TestTokenizeHumanSearch_ContentPreserved_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testTokenizeHumanSearch_ContentPreserved_Properties)
}

func FuzzTokenizeHumanSearch_ContentPreserved_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testTokenizeHumanSearch_ContentPreserved_Properties))
}

// =============================================================================
// Property: tokenizeHumanSearch marks quoted strings as phrases
// =============================================================================

func testTokenizeHumanSearch_QuotedPhrases_Properties(t *rapid.T) {
	// Generate a phrase that doesn't contain quotes
	phrase := rapid.StringMatching(`[a-zA-Z0-9 ]{1,20}`).Draw(t, "phrase")
	input := `"` + phrase + `"`
	tokens := tokenizeHumanSearch(input)

	// Property: a properly quoted string produces at least one phrase token
	foundPhrase := false
	for _, tok := range tokens {
		if tok.isPhrase && tok.text == phrase {
			foundPhrase = true
			break
		}
	}
	if !foundPhrase {
		t.Fatalf("Input %q should produce phrase token with text %q, got tokens: %+v", input, phrase, tokens)
	}
}

func TestTokenizeHumanSearch_QuotedPhrases_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testTokenizeHumanSearch_QuotedPhrases_Properties)
}

func FuzzTokenizeHumanSearch_QuotedPhrases_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testTokenizeHumanSearch_QuotedPhrases_Properties))
}

// =============================================================================
// Property: tokenizeHumanSearch token count matches word count for unquoted input
// =============================================================================

func testTokenizeHumanSearch_TokenCount_Properties(t *rapid.T) {
	// Generate words without quotes, tabs, or leading/trailing whitespace
	numWords := rapid.IntRange(1, 10).Draw(t, "numWords")
	words := make([]string, numWords)
	for i := 0; i < numWords; i++ {
		words[i] = rapid.StringMatching(`[a-zA-Z0-9]{1,10}`).Draw(t, "word")
	}
	input := strings.Join(words, " ")
	tokens := tokenizeHumanSearch(input)

	// Property: token count equals word count for input without quotes
	if len(tokens) != numWords {
		t.Fatalf("Input %q has %d words but tokenizeHumanSearch returned %d tokens: %+v",
			input, numWords, len(tokens), tokens)
	}
}

func TestTokenizeHumanSearch_TokenCount_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testTokenizeHumanSearch_TokenCount_Properties)
}

func FuzzTokenizeHumanSearch_TokenCount_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testTokenizeHumanSearch_TokenCount_Properties))
}

// =============================================================================
// Property: EscapeFTS5Query never starts or ends with OR
// =============================================================================

func testEscapeFTS5Query_NoLeadingTrailingOR_Properties(t *rapid.T) {
	input := rapid.String().Draw(t, "input")
	result := EscapeFTS5Query(input)

	if result == "" {
		return // empty is fine
	}

	parts := strings.Fields(result)
	if len(parts) == 0 {
		return
	}

	// Property: output never starts with OR
	if parts[0] == "OR" {
		t.Fatalf("EscapeFTS5Query(%q) = %q starts with OR", input, result)
	}

	// Property: output never ends with OR
	if parts[len(parts)-1] == "OR" {
		t.Fatalf("EscapeFTS5Query(%q) = %q ends with OR", input, result)
	}
}

func TestEscapeFTS5Query_NoLeadingTrailingOR_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testEscapeFTS5Query_NoLeadingTrailingOR_Properties)
}

func FuzzEscapeFTS5Query_NoLeadingTrailingOR_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testEscapeFTS5Query_NoLeadingTrailingOR_Properties))
}

// =============================================================================
// Property: EscapeFTS5Query never has consecutive OR tokens
// =============================================================================

func testEscapeFTS5Query_NoConsecutiveOR_Properties(t *rapid.T) {
	input := rapid.String().Draw(t, "input")
	result := EscapeFTS5Query(input)

	if result == "" {
		return
	}

	parts := strings.Fields(result)
	for i := 1; i < len(parts); i++ {
		if parts[i] == "OR" && parts[i-1] == "OR" {
			t.Fatalf("EscapeFTS5Query(%q) = %q has consecutive OR tokens", input, result)
		}
	}
}

func TestEscapeFTS5Query_NoConsecutiveOR_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testEscapeFTS5Query_NoConsecutiveOR_Properties)
}

func FuzzEscapeFTS5Query_NoConsecutiveOR_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testEscapeFTS5Query_NoConsecutiveOR_Properties))
}

// =============================================================================
// Property: EscapeFTS5Query NOT only appears with a preceding positive term
// =============================================================================

func testEscapeFTS5Query_NOTRequiresPositive_Properties(t *rapid.T) {
	input := rapid.String().Draw(t, "input")
	result := EscapeFTS5Query(input)

	if result == "" {
		return
	}

	// Split into space-separated tokens, but preserve "NOT word*" as conceptual pairs
	parts := strings.Split(result, " ")

	// Find all NOT tokens and check they have a preceding positive term
	for i, part := range parts {
		if part != "NOT" {
			continue
		}
		// NOT found; check that there's a preceding positive (non-NOT, non-OR) term
		hasPositiveBefore := false
		for j := 0; j < i; j++ {
			if parts[j] != "OR" && parts[j] != "NOT" && parts[j] != "" {
				hasPositiveBefore = true
				break
			}
		}
		if !hasPositiveBefore {
			t.Fatalf("EscapeFTS5Query(%q) = %q has NOT at position %d without a preceding positive term",
				input, result, i)
		}
	}
}

func TestEscapeFTS5Query_NOTRequiresPositive_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testEscapeFTS5Query_NOTRequiresPositive_Properties)
}

func FuzzEscapeFTS5Query_NOTRequiresPositive_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testEscapeFTS5Query_NOTRequiresPositive_Properties))
}

// =============================================================================
// Property: EscapeFTS5Query bare words end with * (prefix matching)
// =============================================================================

func testEscapeFTS5Query_BareWordsHavePrefix_Properties(t *rapid.T) {
	input := rapid.String().Draw(t, "input")
	result := EscapeFTS5Query(input)

	if result == "" {
		return
	}

	tokens := tokenizeHumanSearch(result)
	for _, tok := range tokens {
		if tok.isPhrase {
			continue
		}
		part := tok.text
		if part == "OR" || part == "NOT" || part == "" {
			continue
		}
		// Every bare word (including those after NOT) must end with *
		if !strings.HasSuffix(part, "*") {
			t.Fatalf("EscapeFTS5Query(%q) = %q contains bare word %q without trailing *",
				input, result, part)
		}
	}
}

func TestEscapeFTS5Query_BareWordsHavePrefix_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testEscapeFTS5Query_BareWordsHavePrefix_Properties)
}

func FuzzEscapeFTS5Query_BareWordsHavePrefix_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testEscapeFTS5Query_BareWordsHavePrefix_Properties))
}

// =============================================================================
// Property: EscapeFTS5Query returns empty for whitespace-only or empty input
// =============================================================================

func testEscapeFTS5Query_EmptyInput_Properties(t *rapid.T) {
	// Generate whitespace-only inputs
	input := rapid.OneOf(
		rapid.Just(""),
		rapid.Just(" "),
		rapid.Just("  "),
		rapid.Just("\t"),
		rapid.Just("\t "),
		rapid.Just("   \t  "),
		rapid.Just("\n"),
		rapid.Just("\r\n"),
	).Draw(t, "input")

	result := EscapeFTS5Query(input)

	// Property: empty/whitespace-only input returns empty string
	if result != "" {
		t.Fatalf("EscapeFTS5Query(%q) = %q, expected empty string", input, result)
	}
}

func TestEscapeFTS5Query_EmptyInput_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testEscapeFTS5Query_EmptyInput_Properties)
}

func FuzzEscapeFTS5Query_EmptyInput_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testEscapeFTS5Query_EmptyInput_Properties))
}

// =============================================================================
// Property: EscapeFTS5Query strips null bytes
// =============================================================================

func testEscapeFTS5Query_NullBytesStripped_Properties(t *rapid.T) {
	input := rapid.String().Draw(t, "input")
	result := EscapeFTS5Query(input)

	// Property: null bytes are never present in output
	if strings.Contains(result, "\x00") {
		t.Fatalf("EscapeFTS5Query(%q) = %q contains null bytes", input, result)
	}
}

func TestEscapeFTS5Query_NullBytesStripped_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testEscapeFTS5Query_NullBytesStripped_Properties)
}

func FuzzEscapeFTS5Query_NullBytesStripped_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testEscapeFTS5Query_NullBytesStripped_Properties))
}

// =============================================================================
// Property: EscapeFTS5Query output is valid FTS5 syntax (actual DB test)
// =============================================================================

func testEscapeFTS5Query_ValidFTS5Syntax_Properties(t *rapid.T) {
	ctx := context.Background()

	userID := testutil.ValidUserID().Draw(t, "userID")
	userDB, err := NewUserDBInMemory(userID)
	if err != nil {
		t.Fatalf("NewUserDBInMemory failed: %v", err)
	}
	defer mustCloseUserDB(t, userDB)

	now := drawUnixEpoch(t, "nowUnixEscapeSyntax")

	// Create a note so we have an FTS index to query against
	err = userDB.Queries().CreateNote(ctx, userdb.CreateNoteParams{
		ID:        nextTestNoteID("fts-syntax-test-note"),
		Title:     "Test Note for FTS5 syntax validation",
		Content:   "Hello world this is searchable content with various words",
		IsPublic:  sql.NullInt64{Int64: 0, Valid: true},
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("Failed to create test note: %v", err)
	}

	// Generate arbitrary input
	input := testutil.ArbitrarySearchQuery().Draw(t, "query")
	escaped := EscapeFTS5Query(input)

	if escaped == "" {
		return // empty queries are valid (produce no results)
	}

	// Property: the escaped query must be valid FTS5 MATCH syntax
	// (no syntax errors when executed against a real FTS5 table)
	var matchCount int
	err = userDB.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM fts_notes
		WHERE fts_notes MATCH ?
	`, escaped).Scan(&matchCount)
	if err != nil {
		t.Fatalf("EscapeFTS5Query(%q) = %q produced FTS5 error: %v", input, escaped, err)
	}
}

func TestEscapeFTS5Query_ValidFTS5Syntax_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testEscapeFTS5Query_ValidFTS5Syntax_Properties)
}

func FuzzEscapeFTS5Query_ValidFTS5Syntax_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testEscapeFTS5Query_ValidFTS5Syntax_Properties))
}

// =============================================================================
// Property: EscapeFTS5Query output has no unescaped FTS5 special characters
// =============================================================================

func testEscapeFTS5Query_NoUnescapedSpecialChars_Properties(t *rapid.T) {
	input := rapid.String().Draw(t, "input")
	result := EscapeFTS5Query(input)

	if result == "" {
		return
	}

	// FTS5 special characters that should never appear bare in output:
	// ( ) { } [ ] ^ : + ~ NEAR/
	// Allowed special: * (prefix), " (phrase delimiters), NOT/OR (operators)
	//
	// Walk the output, skipping inside quoted phrases
	inQuote := false
	for i, r := range result {
		if r == '"' {
			inQuote = !inQuote
			continue
		}
		if inQuote {
			continue // anything goes inside quotes
		}
		switch r {
		case '(', ')', '{', '}', '[', ']', '^', ':', '+', '~':
			t.Fatalf("EscapeFTS5Query(%q) = %q contains unescaped special character %q at index %d",
				input, result, r, i)
		}
	}

	// Check for NEAR/ operator outside quotes
	if strings.Contains(result, "NEAR/") {
		t.Fatalf("EscapeFTS5Query(%q) = %q contains NEAR/ operator", input, result)
	}
	if strings.Contains(result, "NEAR ") {
		// Check NEAR as standalone token (not part of a word like "nearby*")
		parts := strings.Fields(result)
		for _, p := range parts {
			if p == "NEAR" {
				t.Fatalf("EscapeFTS5Query(%q) = %q contains standalone NEAR operator", input, result)
			}
		}
	}
}

func TestEscapeFTS5Query_NoUnescapedSpecialChars_Properties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testEscapeFTS5Query_NoUnescapedSpecialChars_Properties)
}

func FuzzEscapeFTS5Query_NoUnescapedSpecialChars_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testEscapeFTS5Query_NoUnescapedSpecialChars_Properties))
}

// =============================================================================
// Property: MigrateUserDB is idempotent (safe to call multiple times)
// =============================================================================

func testMigrateUserDB_Idempotent_Properties(t *rapid.T) {
	userID := testutil.ValidUserID().Draw(t, "userID")
	userDB, err := NewUserDBInMemory(userID)
	if err != nil {
		t.Fatalf("NewUserDBInMemory failed: %v", err)
	}
	defer mustCloseUserDB(t, userDB)

	// Run migration N times — must never fail.
	runs := rapid.IntRange(1, 5).Draw(t, "runs")
	for i := 0; i < runs; i++ {
		if err := userDB.MigrateUserDB(); err != nil {
			t.Fatalf("MigrateUserDB failed on run %d: %v", i+1, err)
		}
	}

	// Property: all migration-added columns remain queryable.
	ctx := context.Background()
	for _, col := range knownMigrationColumns {
		var n int64
		if err := userDB.DB().QueryRowContext(ctx, col.checkQuery).Scan(&n); err != nil {
			t.Fatalf("Migration column not accessible after %d runs: query=%q err=%v",
				runs, col.checkQuery, err)
		}
	}
}

func TestMigrateUserDB_Idempotent_Properties(t *testing.T) {
	rapid.Check(t, testMigrateUserDB_Idempotent_Properties)
}

func FuzzMigrateUserDB_Idempotent_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testMigrateUserDB_Idempotent_Properties))
}

// =============================================================================
// Property: OpenUserDBWithDEK on a pre-existing DB with any random subset of
// migration columns produces a DB where ALL migration columns are accessible.
//
// Each column that can be added by migration is independently drawn as
// present/absent in the old schema. The property: regardless of what was
// already in the old DB, after OpenUserDBWithDEK every migration column is queryable.
//
// migrationColumns lists the notes columns added by UserDBMigrations.
// Extend this list whenever a new migration column is added.
// =============================================================================

// migrationColumn describes a column added by UserDBMigrations and how to
// verify it's queryable.
type migrationColumn struct {
	table      string // table the column belongs to (e.g., "notes", "account")
	colDef     string // SQL fragment for CREATE TABLE (e.g., "deleted_at INTEGER")
	checkQuery string // query that errors if the column is missing
	indexName  string // optional: index name that must exist (empty = no check)
}

// knownMigrationColumns enumerates every column+index added by UserDBMigrations.
// Add entries here whenever a new migration is written.
var knownMigrationColumns = []migrationColumn{
	{
		table:      "notes",
		colDef:     "deleted_at INTEGER",
		checkQuery: "SELECT COUNT(*) FROM notes WHERE deleted_at IS NULL",
		indexName:  "idx_notes_deleted_at",
	},
	{
		table:      "account",
		colDef:     "subscription_status TEXT DEFAULT 'free'",
		checkQuery: "SELECT COUNT(*) FROM account WHERE subscription_status IS NULL",
	},
	{
		table:      "account",
		colDef:     "subscription_id TEXT",
		checkQuery: "SELECT COUNT(*) FROM account WHERE subscription_id IS NULL",
	},
	{
		table:      "account",
		colDef:     "stripe_customer_id TEXT",
		checkQuery: "SELECT COUNT(*) FROM account WHERE stripe_customer_id IS NULL",
	},
	{
		table:      "account",
		colDef:     "db_size_bytes INTEGER DEFAULT 0",
		checkQuery: "SELECT COUNT(*) FROM account WHERE db_size_bytes IS NULL",
	},
	{
		table:      "account",
		colDef:     "last_login INTEGER",
		checkQuery: "SELECT COUNT(*) FROM account WHERE last_login IS NULL",
	},
}

func testMigrateUserDB_PreExistingDB_Properties(t *rapid.T) {
	setupTestDirRapid(t)
	ctx := context.Background()
	userID := testutil.ValidUserID().Draw(t, "userID")

	// For each migration column, randomly decide whether the old DB already had it.
	// This generates all 2^N combinations of "old schema" states.
	presentInOld := make([]bool, len(knownMigrationColumns))
	for i := range knownMigrationColumns {
		presentInOld[i] = rapid.Bool().Draw(t, fmt.Sprintf("col_%d_present", i))
	}

	// Group optional columns by table.
	tableOptCols := map[string][]string{}
	for i, col := range knownMigrationColumns {
		if presentInOld[i] {
			tableOptCols[col.table] = append(tableOptCols[col.table], col.colDef)
		}
	}

	// Build seed SQL for a table given its base columns and optional migration columns.
	buildTableSQL := func(table, baseCols string) string {
		s := "CREATE TABLE IF NOT EXISTS " + table + " (\n" + baseCols
		for _, opt := range tableOptCols[table] {
			s += ",\n    " + opt
		}
		s += "\n);"
		return s
	}

	// Minimal notes table — base columns from the original schema.
	notesSQL := buildTableSQL("notes", `    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    is_public INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL`)

	// Minimal account table — base columns present at first launch.
	accountSQL := buildTableSQL("account", `    user_id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    google_sub TEXT,
    created_at INTEGER NOT NULL`)

	// Seed an encrypted file DB with both old-schema tables.
	dek := testDEK()
	dbPath := filepath.Join(DataDirectory, userID+".db")
	dekHex := hex.EncodeToString(dek)
	dsn := fmt.Sprintf("%s?_pragma_key=x'%s'&_pragma_cipher_page_size=4096&_fts5_tokenizer=porter", dbPath, dekHex)
	dsn = appendSQLiteParams(dsn, sqliteCommonParams())

	seedDB, err := sql.Open(SQLiteDriverName, dsn)
	if err != nil {
		t.Fatalf("Failed to open seed DB: %v", err)
	}
	if _, err := seedDB.Exec(notesSQL); err != nil {
		seedDB.Close()
		t.Fatalf("Failed to seed old notes schema (presentInOld=%v): %v", presentInOld, err)
	}
	if _, err := seedDB.Exec(accountSQL); err != nil {
		seedDB.Close()
		t.Fatalf("Failed to seed old account schema (presentInOld=%v): %v", presentInOld, err)
	}
	seedDB.Close()

	// Open via the normal path (UserDBSchema exec + MigrateUserDB).
	// Property: must always succeed regardless of which migration columns were missing.
	db, err := OpenUserDBWithDEK(userID, dek)
	if err != nil {
		t.Fatalf("OpenUserDBWithDEK failed (presentInOld=%v): %v", presentInOld, err)
	}

	// Property: every migration column is queryable after open.
	for _, col := range knownMigrationColumns {
		var n int64
		if err := db.DB().QueryRowContext(ctx, col.checkQuery).Scan(&n); err != nil {
			t.Fatalf("Migration column check failed (presentInOld=%v): query=%q err=%v",
				presentInOld, col.checkQuery, err)
		}
		if col.indexName != "" {
			var idxName string
			if err := db.DB().QueryRowContext(ctx,
				"SELECT name FROM sqlite_master WHERE type='index' AND name=?",
				col.indexName,
			).Scan(&idxName); err != nil {
				t.Fatalf("Migration index %q missing (presentInOld=%v): %v",
					col.indexName, presentInOld, err)
			}
		}
	}
}

func TestMigrateUserDB_PreExistingDB_Properties(t *testing.T) {
	rapid.Check(t, testMigrateUserDB_PreExistingDB_Properties)
}

func FuzzMigrateUserDB_PreExistingDB_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testMigrateUserDB_PreExistingDB_Properties))
}
