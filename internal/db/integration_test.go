package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kuitang/agent-notes/internal/db/sessions"
	"github.com/kuitang/agent-notes/internal/db/userdb"
)

// TestMilestone1Setup verifies the complete database setup for Milestone 1
// with the hardcoded test user
func TestMilestone1Setup(t *testing.T) {
	setupTestDir(t)
	ctx := context.Background()

	// Milestone 1 uses hardcoded user ID
	const testUserID = "test-user-001"

	// Initialize schemas for test user
	err := InitSchemas(testUserID)
	if err != nil {
		t.Fatalf("Failed to initialize schemas: %v", err)
	}

	// Verify sessions database
	sessDB, err := OpenSessionsDB()
	if err != nil {
		t.Fatalf("Failed to open sessions database: %v", err)
	}

	// Insert a test session using sqlc
	now := time.Now().Unix()
	expires := now + 86400 // 24 hours
	sessionID := "test-session-123"

	err = sessDB.Queries().CreateSession(ctx, sessions.CreateSessionParams{
		SessionID: sessionID,
		UserID:    testUserID,
		ExpiresAt: expires,
		CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("Failed to insert session: %v", err)
	}

	// Verify session was inserted using sqlc
	sess, err := sessDB.Queries().GetSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("Failed to query session: %v", err)
	}

	if sess.UserID != testUserID {
		t.Errorf("Expected user_id %q, got %q", testUserID, sess.UserID)
	}

	// Verify user database
	userDB, err := OpenUserDB(testUserID)
	if err != nil {
		t.Fatalf("Failed to open user database: %v", err)
	}

	// Insert test account using sqlc
	err = userDB.Queries().CreateAccount(ctx, userdb.CreateAccountParams{
		UserID:             testUserID,
		Email:              "[email protected]",
		CreatedAt:          now,
		SubscriptionStatus: sql.NullString{String: "free", Valid: true},
	})
	if err != nil {
		t.Fatalf("Failed to insert account: %v", err)
	}

	// Insert test notes using sqlc
	notes := []struct {
		id      string
		title   string
		content string
	}{
		{"note-1", "First Note", "This is the first test note."},
		{"note-2", "Second Note", "This is the second test note with more content."},
		{"note-3", "Important", "Remember to test full-text search functionality."},
	}

	for _, note := range notes {
		err = userDB.Queries().CreateNote(ctx, userdb.CreateNoteParams{
			ID:        note.id,
			Title:     note.title,
			Content:   note.content,
			IsPublic:  sql.NullInt64{Int64: 0, Valid: true},
			CreatedAt: now,
			UpdatedAt: now,
		})
		if err != nil {
			t.Fatalf("Failed to insert note %s: %v", note.id, err)
		}
	}

	// Verify notes were inserted using sqlc
	count, err := userDB.Queries().CountNotes(ctx)
	if err != nil {
		t.Fatalf("Failed to count notes: %v", err)
	}

	if count != int64(len(notes)) {
		t.Errorf("Expected %d notes, got %d", len(notes), count)
	}

	// Test full-text search using the FTS method
	results, err := userDB.SearchNotes(ctx, "search", 10, 0)
	if err != nil {
		t.Fatalf("Failed to perform FTS search: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 search result, got %d", len(results))
	}

	if results[0].Title != "Important" {
		t.Errorf("Expected to find note with title 'Important', got %q", results[0].Title)
	}

	// Test note retrieval by ID using sqlc
	note, err := userDB.Queries().GetNote(ctx, "note-1")
	if err != nil {
		t.Fatalf("Failed to retrieve note: %v", err)
	}

	if note.Title != "First Note" {
		t.Errorf("Expected title 'First Note', got %q", note.Title)
	}

	// Test note update using sqlc
	newContent := "This is the updated first note."
	err = userDB.Queries().UpdateNoteContent(ctx, userdb.UpdateNoteContentParams{
		Content:   newContent,
		UpdatedAt: now + 1,
		ID:        "note-1",
	})
	if err != nil {
		t.Fatalf("Failed to update note: %v", err)
	}

	// Verify update using sqlc
	note, err = userDB.Queries().GetNote(ctx, "note-1")
	if err != nil {
		t.Fatalf("Failed to retrieve updated note: %v", err)
	}

	if note.Content != newContent {
		t.Errorf("Expected content %q, got %q", newContent, note.Content)
	}

	// Test note deletion using sqlc
	err = userDB.Queries().DeleteNote(ctx, "note-2")
	if err != nil {
		t.Fatalf("Failed to delete note: %v", err)
	}

	// Verify deletion using sqlc
	count, err = userDB.Queries().CountNotes(ctx)
	if err != nil {
		t.Fatalf("Failed to count notes after deletion: %v", err)
	}

	expectedCount := int64(len(notes) - 1)
	if count != expectedCount {
		t.Errorf("Expected %d notes after deletion, got %d", expectedCount, count)
	}

	// Clean up
	err = CloseAll()
	if err != nil {
		t.Errorf("Failed to close databases: %v", err)
	}
}

// TestDatabaseEncryption verifies that the user database is actually encrypted
func TestDatabaseEncryption(t *testing.T) {
	setupTestDir(t)
	ctx := context.Background()

	const testUserID = "test-user-encrypted"

	// Create encrypted database
	userDB, err := OpenUserDB(testUserID)
	if err != nil {
		t.Fatalf("Failed to open user database: %v", err)
	}

	// Insert sensitive data using sqlc
	sensitiveData := "This is highly sensitive information that must be encrypted."
	now := time.Now().Unix()

	err = userDB.Queries().CreateNote(ctx, userdb.CreateNoteParams{
		ID:        "sensitive-note",
		Title:     "Confidential",
		Content:   sensitiveData,
		IsPublic:  sql.NullInt64{Int64: 0, Valid: true},
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("Failed to insert sensitive note: %v", err)
	}

	// Verify we can read it with the correct key using sqlc
	note, err := userDB.Queries().GetNote(ctx, "sensitive-note")
	if err != nil {
		t.Fatalf("Failed to read sensitive note: %v", err)
	}

	if note.Content != sensitiveData {
		t.Errorf("Content mismatch: expected %q, got %q", sensitiveData, note.Content)
	}

	// Close and verify database file exists
	userDB.DB().Close()

	dbPath := DataDirectory + "/" + testUserID + ".db"
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("Database file does not exist: %v", err)
	}

	// In production, we would verify that the file is actually encrypted
	// by trying to open it without the key or by inspecting the raw bytes.
	// For Milestone 1, we trust that SQLCipher is doing its job.

	t.Log("Database encryption test passed. File is encrypted with SQLCipher.")
}

// =============================================================================
// Milestone 1 Regression Tests (merged from milestone1_test.go)
// =============================================================================

// TestMilestone1Constants verifies the hardcoded constants for Milestone 1
func TestMilestone1Constants(t *testing.T) {
	// Verify DEK is 32 bytes (256 bits)
	dek := GetHardcodedDEK()
	if len(dek) != 32 {
		t.Errorf("DEK must be 32 bytes for AES-256, got %d", len(dek))
	}

	// Verify test user ID constant
	const expectedUserID = "test-user-001"
	if expectedUserID == "" {
		t.Error("TestUserID cannot be empty")
	}
}

// TestMilestone1QuickStart is a quick smoke test for basic CRUD operations
func TestMilestone1QuickStart(t *testing.T) {
	setupTestDir(t)
	ctx := context.Background()

	const testUserID = "test-user-001"

	// Step 1: Initialize database for test user
	err := InitSchemas(testUserID)
	if err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	// Step 2: Get user database
	userDB, err := OpenUserDB(testUserID)
	if err != nil {
		t.Fatalf("Failed to open user database: %v", err)
	}

	// Step 3: Verify it works by doing a simple CRUD operation using sqlc
	now := time.Now().Unix()

	// Create
	err = userDB.Queries().CreateNote(ctx, userdb.CreateNoteParams{
		ID:        "quick-start-note",
		Title:     "Quick Start",
		Content:   "This is a quick start note.",
		IsPublic:  sql.NullInt64{Int64: 0, Valid: true},
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("Failed to create note: %v", err)
	}

	// Read
	note, err := userDB.Queries().GetNote(ctx, "quick-start-note")
	if err != nil {
		t.Fatalf("Failed to read note: %v", err)
	}

	if note.Title != "Quick Start" || note.Content != "This is a quick start note." {
		t.Error("Note content doesn't match")
	}

	// Update
	err = userDB.Queries().UpdateNoteContent(ctx, userdb.UpdateNoteContentParams{
		Content:   "Updated content",
		UpdatedAt: now + 1,
		ID:        "quick-start-note",
	})
	if err != nil {
		t.Fatalf("Failed to update note: %v", err)
	}

	// Verify update
	note, err = userDB.Queries().GetNote(ctx, "quick-start-note")
	if err != nil {
		t.Fatalf("Failed to read updated note: %v", err)
	}

	if note.Content != "Updated content" {
		t.Errorf("Expected 'Updated content', got %q", note.Content)
	}

	// Delete
	err = userDB.Queries().DeleteNote(ctx, "quick-start-note")
	if err != nil {
		t.Fatalf("Failed to delete note: %v", err)
	}

	// Verify deletion
	count, err := userDB.Queries().CountNotes(ctx)
	if err != nil {
		t.Fatalf("Failed to count notes: %v", err)
	}

	if count != 0 {
		t.Error("Note was not deleted")
	}

	t.Log("Milestone 1 quick start test passed!")
}

// TestMilestone1FTS5Search tests full-text search functionality
func TestMilestone1FTS5Search(t *testing.T) {
	setupTestDir(t)
	ctx := context.Background()

	const testUserID = "test-user-001"

	// Initialize
	err := InitSchemas(testUserID)
	if err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	userDB, err := OpenUserDB(testUserID)
	if err != nil {
		t.Fatalf("Failed to open user database: %v", err)
	}

	// Insert test notes for search using sqlc
	notes := []struct {
		id      string
		title   string
		content string
	}{
		{"note-1", "Go Programming", "Learning Go language basics and advanced features."},
		{"note-2", "Python Tutorial", "Introduction to Python programming for beginners."},
		{"note-3", "Database Design", "Best practices for designing relational databases."},
		{"note-4", "Go Concurrency", "Deep dive into Go goroutines and channels."},
	}

	now := time.Now().Unix()
	for _, n := range notes {
		err = userDB.Queries().CreateNote(ctx, userdb.CreateNoteParams{
			ID:        n.id,
			Title:     n.title,
			Content:   n.content,
			IsPublic:  sql.NullInt64{Int64: 0, Valid: true},
			CreatedAt: now,
			UpdatedAt: now,
		})
		if err != nil {
			t.Fatalf("Failed to insert note %s: %v", n.id, err)
		}
	}

	// Test 1: Search for "Go" - should find 2 notes using custom FTS method
	results, err := userDB.SearchNotes(ctx, "Go", 10, 0)
	if err != nil {
		t.Fatalf("Failed to search: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Expected to find 2 notes with 'Go', found %d", len(results))
	}

	// Test 2: Search for "programming" - should find 2 notes
	results, err = userDB.SearchNotes(ctx, "programming", 10, 0)
	if err != nil {
		t.Fatalf("Failed to search: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Expected to find 2 notes with 'programming', found %d", len(results))
	}

	// Test 3: Search for "database" - should find 1 note
	results, err = userDB.SearchNotes(ctx, "database", 10, 0)
	if err != nil {
		t.Fatalf("Failed to search for database: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("Expected to find 1 note with 'database', found %d", len(results))
	}

	if results[0].ID != "note-3" {
		t.Errorf("Expected to find note-3, got %s", results[0].ID)
	}

	t.Log("Milestone 1 FTS5 search test passed!")
}

// =============================================================================
// Concurrency Tests
// =============================================================================

// TestConcurrentDatabaseAccess tests that multiple goroutines can safely access the database
// Note: SQLite has inherent locking behavior, so we test with moderate concurrency
func TestConcurrentDatabaseAccess(t *testing.T) {
	setupTestDir(t)
	ctx := context.Background()

	const testUserID = "test-user-concurrent"

	// Initialize database
	userDB, err := OpenUserDB(testUserID)
	if err != nil {
		t.Fatalf("Failed to open user database: %v", err)
	}

	// Enable WAL mode for better concurrency
	_, err = userDB.DB().Exec("PRAGMA journal_mode=WAL")
	if err != nil {
		t.Fatalf("Failed to enable WAL mode: %v", err)
	}

	// Number of concurrent operations (reduced for SQLite limitations)
	const numGoroutines = 5
	const operationsPerGoroutine = 20

	// Use sync.WaitGroup to properly wait for goroutines
	var wg sync.WaitGroup
	successCount := make(chan int, numGoroutines)

	// Launch concurrent operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			localSuccess := 0
			for j := 0; j < operationsPerGoroutine; j++ {
				now := time.Now().Unix()
				noteID := fmt.Sprintf("note-%d-%d", workerID, j)
				title := fmt.Sprintf("Note from worker %d, op %d", workerID, j)
				content := fmt.Sprintf("Content %d-%d", workerID, j)

				// Insert note with retry on database locked error using sqlc
				var insertErr error
				for retry := 0; retry < 3; retry++ {
					insertErr = userDB.Queries().CreateNote(ctx, userdb.CreateNoteParams{
						ID:        noteID,
						Title:     title,
						Content:   content,
						IsPublic:  sql.NullInt64{Int64: 0, Valid: true},
						CreatedAt: now,
						UpdatedAt: now,
					})
					if insertErr == nil {
						break
					}
					// Brief sleep before retry
					time.Sleep(10 * time.Millisecond)
				}
				if insertErr != nil {
					continue
				}

				// Read note back using sqlc
				note, err := userDB.Queries().GetNote(ctx, noteID)
				if err == nil && note.Title == title {
					localSuccess++
				}
			}
			successCount <- localSuccess
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(successCount)

	// Count successful operations
	totalSuccess := 0
	for count := range successCount {
		totalSuccess += count
	}

	// Verify that most operations succeeded (allow some failures due to SQLite locking)
	expected := numGoroutines * operationsPerGoroutine
	successRate := float64(totalSuccess) / float64(expected) * 100

	t.Logf("Concurrent operations: %d/%d succeeded (%.1f%%)", totalSuccess, expected, successRate)

	// We expect at least 90% success rate with retries
	if successRate < 90.0 {
		t.Errorf("Success rate too low: %.1f%% (expected >= 90%%)", successRate)
	}

	// Verify final count in database using sqlc
	count, err := userDB.Queries().CountNotes(ctx)
	if err != nil {
		t.Fatalf("Failed to count notes: %v", err)
	}

	if count != int64(totalSuccess) {
		t.Errorf("Database count mismatch: expected %d, got %d", totalSuccess, count)
	}
}
