package e2e

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kuitang/agent-notes/internal/db"
)

var sharedFixtureSessionTables = []string{
	"sessions",
	"magic_tokens",
	"user_keys",
	"oauth_clients",
	"oauth_tokens",
	"oauth_codes",
	"oauth_consents",
	"short_urls",
}

// resetSharedDBFixtureState clears mutable DB state for a long-lived shared fixture.
// It keeps the open sessions DB handle and server process but removes all test data.
func resetSharedDBFixtureState(tempDir string, sessionsDB *db.SessionsDB) error {
	if sessionsDB == nil {
		return fmt.Errorf("sessionsDB is nil")
	}

	// Other tests may mutate this global. Ensure this fixture stays pinned to its own dir.
	db.DataDirectory = tempDir

	// Drop cached per-user DB handles from prior tests to avoid unbounded growth.
	db.ResetUserDBsForTesting()

	entries, err := os.ReadDir(tempDir)
	if err != nil {
		return fmt.Errorf("read fixture temp dir: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) != ".db" || name == db.SessionsDBName {
			continue
		}
		if err := os.Remove(filepath.Join(tempDir, name)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale user db %q: %w", name, err)
		}
	}

	tx, err := sessionsDB.DB().Begin()
	if err != nil {
		return fmt.Errorf("begin reset transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	for _, table := range sharedFixtureSessionTables {
		if _, err := tx.Exec("DELETE FROM " + table); err != nil {
			return fmt.Errorf("clear %s: %w", table, err)
		}
	}

	// Ignore if sqlite_sequence does not exist.
	_, _ = tx.Exec("DELETE FROM sqlite_sequence WHERE name = 'short_urls'")

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit reset transaction: %w", err)
	}
	return nil
}
