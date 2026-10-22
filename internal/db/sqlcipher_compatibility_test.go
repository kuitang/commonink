package db

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// This fixture was written by SQLCipher 4.4.2 / SQLite 3.33.0 with the
// production raw-key and 4096-byte page settings. It contains synthetic data.
// It is a compatibility regression corpus, never a production backup.
func TestSQLCipherLegacyFixture_ReadWriteRestore(t *testing.T) {
	rapid.Check(t, testSQLCipherLegacyFixtureReadWriteRestore)
}

func FuzzSQLCipherLegacyFixture_ReadWriteRestore(f *testing.F) {
	f.Add([]byte{0})
	f.Fuzz(rapid.MakeFuzz(testSQLCipherLegacyFixtureReadWriteRestore))
}

func testSQLCipherLegacyFixtureReadWriteRestore(rt *rapid.T) {
	fixture, err := os.ReadFile("testdata/sqlcipher/v4.4.2.db")
	if err != nil {
		rt.Fatal(err)
	}
	if bytes.HasPrefix(fixture, []byte("SQLite format 3")) || bytes.Contains(fixture, []byte("legacy encrypted fixture")) {
		rt.Fatal("legacy fixture must remain encrypted")
	}
	key := hex.EncodeToString(bytes.Repeat([]byte{65}, 32))
	dir, err := os.MkdirTemp("", "commonink-legacy-fuzz-")
	if err != nil {
		rt.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "notes.db")
	if err := os.WriteFile(path, fixture, 0600); err != nil {
		rt.Fatal(err)
	}
	open := func(path, key string) *sql.DB {
		db, err := sql.Open(SQLiteDriverName, fmt.Sprintf("%s?_pragma_key=x'%s'&_pragma_cipher_page_size=4096&%s", path, key, sqliteCommonParams()))
		if err != nil {
			rt.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		return db
	}
	db := open(path, key)
	legacyDB := NewUserDBFromSQL("fixture-user", db)
	if err := legacyDB.MigrateUserDB(); err != nil {
		rt.Fatalf("migrate legacy triggers: %v", err)
	}
	if err := legacyDB.MigrateUserDB(); err != nil {
		rt.Fatalf("repeat migration: %v", err)
	}
	if _, err := db.Exec("UPDATE notes SET title='updatedtoken', content='updated content' WHERE id='legacy-empty'"); err != nil {
		rt.Fatalf("update legacy empty-token note: %v", err)
	}
	if _, err := db.Exec("UPDATE notes SET title='newtoken' WHERE id='legacy-search'"); err != nil {
		rt.Fatalf("update legacy indexed note: %v", err)
	}
	var updatedHits, oldHits int
	if err := db.QueryRow("SELECT count(*) FROM fts_notes WHERE fts_notes MATCH 'updatedtoken'").Scan(&updatedHits); err != nil || updatedHits != 1 {
		rt.Fatalf("updated index hits=%d err=%v", updatedHits, err)
	}
	if err := db.QueryRow("SELECT count(*) FROM fts_notes WHERE fts_notes MATCH 'oldtoken'").Scan(&oldHits); err != nil || oldHits != 0 {
		rt.Fatalf("old index hits=%d err=%v", oldHits, err)
	}
	if _, err := db.Exec("UPDATE notes SET title=' ', content='' WHERE id='legacy-search'"); err != nil {
		rt.Fatalf("nonempty to empty update: %v", err)
	}
	if _, err := db.Exec("UPDATE notes SET title='restoredtoken', content='again' WHERE id='legacy-search'"); err != nil {
		rt.Fatalf("empty to nonempty update: %v", err)
	}
	if err := db.QueryRow("SELECT count(*) FROM fts_notes WHERE fts_notes MATCH 'restoredtoken'").Scan(&updatedHits); err != nil || updatedHits != 1 {
		rt.Fatalf("replacement index hits=%d err=%v", updatedHits, err)
	}
	if _, err := db.Exec("DELETE FROM notes WHERE id='legacy-search'"); err != nil {
		rt.Fatal(err)
	}
	if err := db.QueryRow("SELECT count(*) FROM fts_notes WHERE fts_notes MATCH 'restoredtoken'").Scan(&updatedHits); err != nil || updatedHits != 0 {
		rt.Fatalf("deleted index hits=%d err=%v", updatedHits, err)
	}
	if _, err := db.Exec("INSERT INTO fts_notes(fts_notes, rank) VALUES('integrity-check', 1)"); err != nil {
		rt.Fatalf("FTS external content consistency: %v", err)
	}

	var content, cipher, version string
	if err := db.QueryRow("SELECT content FROM legacy_notes WHERE id='fixture-note'").Scan(&content); err != nil {
		rt.Fatalf("read old encrypted database: %v", err)
	}
	if content != "legacy encrypted fixture: naïve λ cats running" {
		rt.Fatalf("legacy content changed: %q", content)
	}
	if err := db.QueryRow("PRAGMA cipher_version").Scan(&cipher); err != nil {
		rt.Fatal(err)
	}
	if !strings.HasPrefix(cipher, "4.17.") {
		rt.Fatalf("unexpected SQLCipher: %q", cipher)
	}
	if err := db.QueryRow("SELECT sqlite_version()").Scan(&version); err != nil {
		rt.Fatal(err)
	}
	if version != "3.53.3" {
		rt.Fatalf("unexpected SQLite: %q", version)
	}
	var hits int
	if err := db.QueryRow("SELECT count(*) FROM legacy_fts WHERE legacy_fts MATCH ?", "run").Scan(&hits); err != nil || hits != 1 {
		rt.Fatalf("legacy FTS5 query: hits=%d err=%v", hits, err)
	}
	written := rapid.String().Draw(rt, "new-content")
	if _, err := db.Exec("INSERT INTO legacy_notes VALUES(?, ?)", "new-note", written); err != nil {
		rt.Fatal(err)
	}
	var integrity string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		rt.Fatalf("integrity=%q error=%v", integrity, err)
	}
	if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		rt.Fatal(err)
	}
	if err := db.Close(); err != nil {
		rt.Fatal(err)
	}
	backup, err := os.ReadFile(path)
	if err != nil {
		rt.Fatal(err)
	}
	restored := filepath.Join(dir, "restored.db")
	if err := os.WriteFile(restored, backup, 0600); err != nil {
		rt.Fatal(err)
	}
	restoredDB := open(restored, key)
	if err := NewUserDBFromSQL("restored-user", restoredDB).MigrateUserDB(); err != nil {
		rt.Fatalf("restored migration idempotency: %v", err)
	}
	if err := restoredDB.QueryRow("SELECT title FROM notes WHERE id='legacy-empty'").Scan(&content); err != nil || content != "updatedtoken" {
		rt.Fatalf("restored legacy production notes: %v", err)
	}

	if err := restoredDB.QueryRow("SELECT content FROM legacy_notes WHERE id='new-note'").Scan(&content); err != nil || content != written {
		rt.Fatalf("restored content mismatch: %v", err)
	}
	restoredDB.Close()
	wrongKeyDB := open(restored, hex.EncodeToString(bytes.Repeat([]byte{66}, 32)))
	if err := wrongKeyDB.QueryRow("SELECT content FROM legacy_notes").Scan(&content); err == nil {
		rt.Fatal("wrong encryption key must fail")
	}
	wrongKeyDB.Close()
}

func TestSQLCipherLegacyFTSMigration_RollsBackOnRebuildFailure(t *testing.T) {
	fixture, err := os.ReadFile("testdata/sqlcipher/v4.4.2.db")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "failure.db")
	if err := os.WriteFile(path, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	key := hex.EncodeToString(bytes.Repeat([]byte{65}, 32))
	database, err := sql.Open(SQLiteDriverName, fmt.Sprintf("%s?_pragma_key=x'%s'&_pragma_cipher_page_size=4096", path, key))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	if _, err := database.Exec("CREATE TRIGGER inject_rebuild_failure BEFORE DELETE ON fts_notes_data BEGIN SELECT RAISE(ABORT, 'injected rebuild failure'); END;"); err != nil {
		t.Fatal(err)
	}
	user := NewUserDBFromSQL("fixture-user", database)
	if err := user.MigrateUserDB(); err == nil || !strings.Contains(err.Error(), "rebuild FTS index") {
		t.Fatalf("expected rebuild failure, got %v", err)
	}
	var version int
	if err := database.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 0 {
		t.Fatalf("failed migration changed version: %d, %v", version, err)
	}
	var trigger string
	if err := database.QueryRow("SELECT sql FROM sqlite_master WHERE name='notes_au'").Scan(&trigger); err != nil || !strings.Contains(trigger, "UPDATE fts_notes SET") {
		t.Fatalf("failed migration changed original trigger: %v", err)
	}
	if _, err := database.Exec("DROP TRIGGER inject_rebuild_failure"); err != nil {
		t.Fatal(err)
	}
	if err := user.MigrateUserDB(); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE notes SET title='recovered' WHERE id='legacy-empty'"); err != nil {
		t.Fatal(err)
	}
}
