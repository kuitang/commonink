package testdb

import (
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/kuitang/agent-notes/internal/db"
)

// NewUserDBInMemory creates an in-memory encrypted UserDB for tests.
func NewUserDBInMemory(userID string) (*db.UserDB, error) {
	if userID == "" {
		userID = "test-user"
	}

	dekHex := hex.EncodeToString(db.GetHardcodedDEK())
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared&_pragma_key=x'%s'&_pragma_cipher_page_size=4096", userID, dekHex)

	sqlDB, err := sql.Open(db.SQLiteDriverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open in-memory user database: %w", err)
	}

	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetMaxOpenConns(10)

	var sqliteVersion string
	if err := sqlDB.QueryRow("SELECT sqlite_version()").Scan(&sqliteVersion); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("failed to verify in-memory user database: %w", err)
	}

	if err := applyFastSQLitePragmas(sqlDB); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("failed to apply fast SQLite pragmas: %w", err)
	}

	if _, err := sqlDB.Exec(db.UserDBSchema); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("failed to initialize in-memory user schema: %w", err)
	}

	return db.NewUserDBFromSQL(userID, sqlDB), nil
}

// NewSessionsDBInMemory creates an in-memory unencrypted SessionsDB for tests.
func NewSessionsDBInMemory() (*db.SessionsDB, error) {
	sqlDB, err := sql.Open(db.SQLiteDriverName, ":memory:")
	if err != nil {
		return nil, fmt.Errorf("failed to open in-memory sessions database: %w", err)
	}

	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetMaxOpenConns(10)

	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("failed to ping in-memory sessions database: %w", err)
	}

	if err := applyFastSQLitePragmas(sqlDB); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("failed to apply fast SQLite pragmas: %w", err)
	}

	if _, err := sqlDB.Exec(db.SessionsDBSchema); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("failed to initialize in-memory sessions schema: %w", err)
	}

	return db.NewSessionsDBFromSQL(sqlDB), nil
}

func applyFastSQLitePragmas(sqlDB *sql.DB) error {
	pragmas := []string{
		"PRAGMA journal_mode=MEMORY",
		"PRAGMA synchronous=OFF",
		"PRAGMA temp_store=MEMORY",
		"PRAGMA secure_delete=OFF",
	}
	for _, pragma := range pragmas {
		if _, err := sqlDB.Exec(pragma); err != nil {
			return err
		}
	}
	return nil
}
