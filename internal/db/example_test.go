package db_test

import (
	"fmt"
	"time"

	"github.com/kuitang/agent-notes/internal/db"
)

// ExampleInitSchemas demonstrates how to initialize the database layer
func ExampleInitSchemas() {
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

	// Insert a test note
	now := time.Now().Unix()
	_, err = userDB.Exec(
		"INSERT INTO notes (id, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
		"example-note", "Example Note", "This is an example note.", now, now,
	)
	if err != nil {
		fmt.Printf("Error inserting note: %v\n", err)
		return
	}

	// Query the note
	var title, content string
	err = userDB.QueryRow("SELECT title, content FROM notes WHERE id = ?", "example-note").Scan(&title, &content)
	if err != nil {
		fmt.Printf("Error querying note: %v\n", err)
		return
	}

	fmt.Printf("Title: %s\n", title)
	fmt.Printf("Content: %s\n", content)

	// Clean up
	db.CloseAll()

	// Output:
	// Title: Example Note
	// Content: This is an example note.
}

// ExampleOpenUserDB demonstrates opening a user database with encryption
func ExampleOpenUserDB() {
	// For this example, use a unique user ID to ensure clean state
	// In production, you would use actual user IDs from your auth system
	userDB, err := db.OpenUserDB("example-user-unique")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// The database is now ready to use
	// Connection is cached and reused on subsequent calls
	var count int
	err = userDB.QueryRow("SELECT COUNT(*) FROM notes").Scan(&count)
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
