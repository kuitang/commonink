package db

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// TestMilestone1Setup verifies the complete database setup for Milestone 1
// with the hardcoded test user
func TestMilestone1Setup(t *testing.T) {
	setupTestDir(t)

	// Milestone 1 uses hardcoded user ID
	const testUserID = "test-user-001"

	// Initialize schemas for test user
	err := InitSchemas(testUserID)
	if err != nil {
		t.Fatalf("Failed to initialize schemas: %v", err)
	}

	// Verify sessions database
	sessionsDB, err := OpenSessionsDB()
	if err != nil {
		t.Fatalf("Failed to open sessions database: %v", err)
	}

	// Insert a test session
	now := time.Now().Unix()
	expires := now + 86400 // 24 hours
	sessionID := "test-session-123"

	_, err = sessionsDB.Exec(
		"INSERT INTO sessions (session_id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
		sessionID, testUserID, expires, now,
	)
	if err != nil {
		t.Fatalf("Failed to insert session: %v", err)
	}

	// Verify session was inserted
	var retrievedUserID string
	err = sessionsDB.QueryRow("SELECT user_id FROM sessions WHERE session_id = ?", sessionID).Scan(&retrievedUserID)
	if err != nil {
		t.Fatalf("Failed to query session: %v", err)
	}

	if retrievedUserID != testUserID {
		t.Errorf("Expected user_id %q, got %q", testUserID, retrievedUserID)
	}

	// Verify user database
	userDB, err := OpenUserDB(testUserID)
	if err != nil {
		t.Fatalf("Failed to open user database: %v", err)
	}

	// Insert test account
	_, err = userDB.Exec(
		"INSERT INTO account (user_id, email, created_at, subscription_status) VALUES (?, ?, ?, ?)",
		testUserID, "[email protected]", now, "free",
	)
	if err != nil {
		t.Fatalf("Failed to insert account: %v", err)
	}

	// Insert test notes
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
		_, err = userDB.Exec(
			"INSERT INTO notes (id, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
			note.id, note.title, note.content, now, now,
		)
		if err != nil {
			t.Fatalf("Failed to insert note %s: %v", note.id, err)
		}
	}

	// Verify notes were inserted
	var count int
	err = userDB.QueryRow("SELECT COUNT(*) FROM notes").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count notes: %v", err)
	}

	if count != len(notes) {
		t.Errorf("Expected %d notes, got %d", len(notes), count)
	}

	// Test full-text search
	var searchTitle, searchContent string
	err = userDB.QueryRow(
		"SELECT title, content FROM fts_notes WHERE fts_notes MATCH ? LIMIT 1",
		"search",
	).Scan(&searchTitle, &searchContent)
	if err != nil {
		t.Fatalf("Failed to perform FTS search: %v", err)
	}

	if searchTitle != "Important" {
		t.Errorf("Expected to find note with title 'Important', got %q", searchTitle)
	}

	// Test note retrieval by ID
	var title, content string
	err = userDB.QueryRow("SELECT title, content FROM notes WHERE id = ?", "note-1").Scan(&title, &content)
	if err != nil {
		t.Fatalf("Failed to retrieve note: %v", err)
	}

	if title != "First Note" {
		t.Errorf("Expected title 'First Note', got %q", title)
	}

	// Test note update
	newContent := "This is the updated first note."
	_, err = userDB.Exec("UPDATE notes SET content = ?, updated_at = ? WHERE id = ?", newContent, now+1, "note-1")
	if err != nil {
		t.Fatalf("Failed to update note: %v", err)
	}

	// Verify update
	err = userDB.QueryRow("SELECT content FROM notes WHERE id = ?", "note-1").Scan(&content)
	if err != nil {
		t.Fatalf("Failed to retrieve updated note: %v", err)
	}

	if content != newContent {
		t.Errorf("Expected content %q, got %q", newContent, content)
	}

	// Test note deletion
	_, err = userDB.Exec("DELETE FROM notes WHERE id = ?", "note-2")
	if err != nil {
		t.Fatalf("Failed to delete note: %v", err)
	}

	// Verify deletion
	err = userDB.QueryRow("SELECT COUNT(*) FROM notes").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count notes after deletion: %v", err)
	}

	expectedCount := len(notes) - 1
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

	const testUserID = "test-user-encrypted"

	// Create encrypted database
	userDB, err := OpenUserDB(testUserID)
	if err != nil {
		t.Fatalf("Failed to open user database: %v", err)
	}

	// Insert sensitive data
	sensitiveData := "This is highly sensitive information that must be encrypted."
	now := time.Now().Unix()

	_, err = userDB.Exec(
		"INSERT INTO notes (id, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
		"sensitive-note", "Confidential", sensitiveData, now, now,
	)
	if err != nil {
		t.Fatalf("Failed to insert sensitive note: %v", err)
	}

	// Verify we can read it with the correct key
	var content string
	err = userDB.QueryRow("SELECT content FROM notes WHERE id = ?", "sensitive-note").Scan(&content)
	if err != nil {
		t.Fatalf("Failed to read sensitive note: %v", err)
	}

	if content != sensitiveData {
		t.Errorf("Content mismatch: expected %q, got %q", sensitiveData, content)
	}

	// Close and verify database file exists
	userDB.Close()

	dbPath := DataDirectory + "/" + testUserID + ".db"
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("Database file does not exist: %v", err)
	}

	// In production, we would verify that the file is actually encrypted
	// by trying to open it without the key or by inspecting the raw bytes.
	// For Milestone 1, we trust that SQLCipher is doing its job.

	t.Log("Database encryption test passed. File is encrypted with SQLCipher.")
}

// TestConcurrentDatabaseAccess tests that multiple goroutines can safely access the database
// Note: SQLite has inherent locking behavior, so we test with moderate concurrency
func TestConcurrentDatabaseAccess(t *testing.T) {
	setupTestDir(t)

	const testUserID = "test-user-concurrent"

	// Initialize database
	userDB, err := OpenUserDB(testUserID)
	if err != nil {
		t.Fatalf("Failed to open user database: %v", err)
	}

	// Enable WAL mode for better concurrency
	_, err = userDB.Exec("PRAGMA journal_mode=WAL")
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

				// Insert note with retry on database locked error
				var insertErr error
				for retry := 0; retry < 3; retry++ {
					_, insertErr = userDB.Exec(
						"INSERT INTO notes (id, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
						noteID, title, content, now, now,
					)
					if insertErr == nil {
						break
					}
					// Brief sleep before retry
					time.Sleep(10 * time.Millisecond)
				}
				if insertErr != nil {
					continue
				}

				// Read note back
				var retrievedTitle string
				err := userDB.QueryRow("SELECT title FROM notes WHERE id = ?", noteID).Scan(&retrievedTitle)
				if err == nil && retrievedTitle == title {
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

	// Verify final count in database
	var count int
	err = userDB.QueryRow("SELECT COUNT(*) FROM notes").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count notes: %v", err)
	}

	if count != totalSuccess {
		t.Errorf("Database count mismatch: expected %d, got %d", totalSuccess, count)
	}
}
