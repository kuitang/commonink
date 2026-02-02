package db_test

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/db/userdb"
)

// ExampleInitSchemas demonstrates how to initialize the database layer
func ExampleInitSchemas() {
	ctx := context.Background()

	// Initialize database for the test user
	err := db.InitSchemas("test-user-001")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Open the user database
	userDB, err := db.OpenUserDB("test-user-001")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Insert a test note using sqlc-generated queries
	now := time.Now().Unix()
	err = userDB.Queries().CreateNote(ctx, userdb.CreateNoteParams{
		ID:        "example-note",
		Title:     "Example Note",
		Content:   "This is an example note.",
		IsPublic:  sql.NullInt64{Int64: 0, Valid: true},
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		fmt.Printf("Error inserting note: %v\n", err)
		return
	}

	// Query the note using sqlc
	note, err := userDB.Queries().GetNote(ctx, "example-note")
	if err != nil {
		fmt.Printf("Error querying note: %v\n", err)
		return
	}

	fmt.Printf("Title: %s\n", note.Title)
	fmt.Printf("Content: %s\n", note.Content)

	// Clean up
	db.CloseAll()

	// Output:
	// Title: Example Note
	// Content: This is an example note.
}

// ExampleOpenUserDB demonstrates opening a user database with encryption
func ExampleOpenUserDB() {
	ctx := context.Background()

	// For this example, use a unique user ID to ensure clean state
	// In production, you would use actual user IDs from your auth system
	userDB, err := db.OpenUserDB("example-user-unique")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// The database is now ready to use with type-safe sqlc queries
	// Connection is cached and reused on subsequent calls
	count, err := userDB.Queries().CountNotes(ctx)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Note count: %d\n", count)

	// Clean up
	db.CloseAll()

	// Output:
	// Note count: 0
}

// ExampleUserDB_SearchNotes demonstrates full-text search using FTS5
func ExampleUserDB_SearchNotes() {
	ctx := context.Background()

	// Initialize database
	userDB, err := db.OpenUserDB("search-example-user")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Insert some notes
	now := time.Now().Unix()
	notes := []struct {
		id, title, content string
	}{
		{"note-1", "Go Tutorial", "Learn Go programming language basics"},
		{"note-2", "Python Basics", "Introduction to Python programming"},
		{"note-3", "Database Tips", "Tips for working with databases"},
	}

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
			fmt.Printf("Error inserting note: %v\n", err)
			return
		}
	}

	// Search for notes containing "programming"
	results, err := userDB.SearchNotes(ctx, "programming", 10, 0)
	if err != nil {
		fmt.Printf("Error searching: %v\n", err)
		return
	}

	fmt.Printf("Found %d notes with 'programming'\n", len(results))

	// Clean up
	db.CloseAll()

	// Output:
	// Found 2 notes with 'programming'
}
