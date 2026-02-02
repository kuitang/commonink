package db

import (
	"testing"
	"time"
)

// Milestone 1 constants
const (
	// TestUserID is the hardcoded user ID for Milestone 1
	TestUserID = "test-user-001"
)

// TestMilestone1Constants verifies the hardcoded constants for Milestone 1
func TestMilestone1Constants(t *testing.T) {
	// Verify DEK is 32 bytes (256 bits)
	dek := GetHardcodedDEK()
	if len(dek) != 32 {
		t.Errorf("DEK must be 32 bytes for AES-256, got %d", len(dek))
	}

	// Verify test user ID is not empty
	if TestUserID == "" {
		t.Error("TestUserID cannot be empty")
	}
}

// TestMilestone1QuickStart demonstrates the quick start for Milestone 1
func TestMilestone1QuickStart(t *testing.T) {
	setupTestDir(t)

	// Step 1: Initialize database for test user
	err := InitSchemas(TestUserID)
	if err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	// Step 2: Get user database
	db, err := OpenUserDB(TestUserID)
	if err != nil {
		t.Fatalf("Failed to open user database: %v", err)
	}

	// Step 3: Verify it works by doing a simple CRUD operation
	now := time.Now().Unix()

	// Create
	_, err = db.Exec(
		"INSERT INTO notes (id, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
		"quick-start-note", "Quick Start", "This is a quick start note.", now, now,
	)
	if err != nil {
		t.Fatalf("Failed to create note: %v", err)
	}

	// Read
	var title, content string
	err = db.QueryRow("SELECT title, content FROM notes WHERE id = ?", "quick-start-note").Scan(&title, &content)
	if err != nil {
		t.Fatalf("Failed to read note: %v", err)
	}

	if title != "Quick Start" || content != "This is a quick start note." {
		t.Error("Note content doesn't match")
	}

	// Update
	_, err = db.Exec("UPDATE notes SET content = ? WHERE id = ?", "Updated content", "quick-start-note")
	if err != nil {
		t.Fatalf("Failed to update note: %v", err)
	}

	// Verify update
	err = db.QueryRow("SELECT content FROM notes WHERE id = ?", "quick-start-note").Scan(&content)
	if err != nil {
		t.Fatalf("Failed to read updated note: %v", err)
	}

	if content != "Updated content" {
		t.Errorf("Expected 'Updated content', got %q", content)
	}

	// Delete
	_, err = db.Exec("DELETE FROM notes WHERE id = ?", "quick-start-note")
	if err != nil {
		t.Fatalf("Failed to delete note: %v", err)
	}

	// Verify deletion
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM notes WHERE id = ?", "quick-start-note").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count notes: %v", err)
	}

	if count != 0 {
		t.Error("Note was not deleted")
	}

	t.Log("Milestone 1 quick start test passed!")
}

// TestMilestone1FTS5Search demonstrates full-text search for Milestone 1
func TestMilestone1FTS5Search(t *testing.T) {
	setupTestDir(t)

	// Initialize
	err := InitSchemas(TestUserID)
	if err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	db, err := OpenUserDB(TestUserID)
	if err != nil {
		t.Fatalf("Failed to open user database: %v", err)
	}

	// Insert test notes for search
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
	for _, note := range notes {
		_, err = db.Exec(
			"INSERT INTO notes (id, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
			note.id, note.title, note.content, now, now,
		)
		if err != nil {
			t.Fatalf("Failed to insert note %s: %v", note.id, err)
		}
	}

	// Test 1: Search for "Go" - should find 2 notes
	// FTS5 virtual table uses rowid, which we need to join with the notes table to get the id
	rows, err := db.Query(`
		SELECT n.id, n.title
		FROM notes n
		JOIN fts_notes f ON n.rowid = f.rowid
		WHERE fts_notes MATCH ?
		ORDER BY rank`, "Go")
	if err != nil {
		t.Fatalf("Failed to search: %v", err)
	}
	defer rows.Close()

	var foundNotes []string
	for rows.Next() {
		var id, title string
		err = rows.Scan(&id, &title)
		if err != nil {
			t.Fatalf("Failed to scan row: %v", err)
		}
		foundNotes = append(foundNotes, id)
	}

	if len(foundNotes) != 2 {
		t.Errorf("Expected to find 2 notes with 'Go', found %d: %v", len(foundNotes), foundNotes)
	}

	// Test 2: Search for "programming" - should find 2 notes
	rows2, err := db.Query(`
		SELECT n.id
		FROM notes n
		JOIN fts_notes f ON n.rowid = f.rowid
		WHERE fts_notes MATCH ?`, "programming")
	if err != nil {
		t.Fatalf("Failed to search: %v", err)
	}
	defer rows2.Close()

	foundNotes = nil
	for rows2.Next() {
		var id string
		err = rows2.Scan(&id)
		if err != nil {
			t.Fatalf("Failed to scan row: %v", err)
		}
		foundNotes = append(foundNotes, id)
	}

	if len(foundNotes) != 2 {
		t.Errorf("Expected to find 2 notes with 'programming', found %d", len(foundNotes))
	}

	// Test 3: Search for "database" - should find 1 note
	var foundID string
	err = db.QueryRow(`
		SELECT n.id
		FROM notes n
		JOIN fts_notes f ON n.rowid = f.rowid
		WHERE fts_notes MATCH ?
		LIMIT 1`, "database").Scan(&foundID)
	if err != nil {
		t.Fatalf("Failed to search for database: %v", err)
	}

	if foundID != "note-3" {
		t.Errorf("Expected to find note-3, got %s", foundID)
	}

	t.Log("Milestone 1 FTS5 search test passed!")
}
