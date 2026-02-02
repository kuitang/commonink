package crypto

import (
	"bytes"
	"os"
	"testing"

	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/db/testutil"
	"pgregory.net/rapid"
)

// setupTestDB creates a fresh sessions database for testing.
// It sets the data directory to a temp directory and returns a cleanup function.
func setupTestDB(t testing.TB) *db.SessionsDB {
	t.Helper()

	// Reset database state from previous tests
	db.ResetForTesting()

	// Use a temp directory for this test
	tmpDir := t.TempDir()
	db.DataDirectory = tmpDir

	// Open sessions database
	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		t.Fatalf("failed to open sessions database: %v", err)
	}

	return sessionsDB
}

// TestKeyManager_GetOrCreate_Roundtrip tests that GetOrCreateUserDEK returns a valid DEK
// and subsequent calls return the same DEK.
func TestKeyManager_GetOrCreate_Roundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Setup fresh DB per test run to avoid conflicts
		db.ResetForTesting()
		tmpDir, err := os.MkdirTemp("", "keymanager-test-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)
		db.DataDirectory = tmpDir

		sessionsDB, err := db.OpenSessionsDB()
		if err != nil {
			t.Fatalf("failed to open sessions database: %v", err)
		}

		masterKey := rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "masterKey")
		userID := testutil.ValidUserID().Draw(t, "userID")

		km := NewKeyManager(masterKey, sessionsDB)

		// First call creates DEK
		dek1, err := km.GetOrCreateUserDEK(userID)
		if err != nil {
			t.Fatalf("first GetOrCreateUserDEK failed: %v", err)
		}

		// DEK should be 32 bytes
		if len(dek1) != DEKSize {
			t.Fatalf("DEK has wrong length: got %d, want %d", len(dek1), DEKSize)
		}

		// Second call should return same DEK
		dek2, err := km.GetOrCreateUserDEK(userID)
		if err != nil {
			t.Fatalf("second GetOrCreateUserDEK failed: %v", err)
		}

		if !bytes.Equal(dek1, dek2) {
			t.Fatalf("GetOrCreateUserDEK returned different DEKs: %x != %x", dek1, dek2)
		}
	})
}

// TestKeyManager_GetUserDEK_AfterCreate tests that GetUserDEK returns the same
// DEK that GetOrCreateUserDEK created.
func TestKeyManager_GetUserDEK_AfterCreate(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		db.ResetForTesting()
		tmpDir, err := os.MkdirTemp("", "keymanager-test-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)
		db.DataDirectory = tmpDir

		sessionsDB, err := db.OpenSessionsDB()
		if err != nil {
			t.Fatalf("failed to open sessions database: %v", err)
		}

		masterKey := rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "masterKey")
		userID := testutil.ValidUserID().Draw(t, "userID")

		km := NewKeyManager(masterKey, sessionsDB)

		// Create DEK
		createdDEK, err := km.GetOrCreateUserDEK(userID)
		if err != nil {
			t.Fatalf("GetOrCreateUserDEK failed: %v", err)
		}

		// Get DEK should return same value
		gotDEK, err := km.GetUserDEK(userID)
		if err != nil {
			t.Fatalf("GetUserDEK failed: %v", err)
		}

		if !bytes.Equal(createdDEK, gotDEK) {
			t.Fatalf("GetUserDEK returned different DEK: %x != %x", createdDEK, gotDEK)
		}
	})
}

// TestKeyManager_GetUserDEK_NotFound tests that GetUserDEK returns ErrUserKeyNotFound
// for users without keys.
func TestKeyManager_GetUserDEK_NotFound(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		db.ResetForTesting()
		tmpDir, err := os.MkdirTemp("", "keymanager-test-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)
		db.DataDirectory = tmpDir

		sessionsDB, err := db.OpenSessionsDB()
		if err != nil {
			t.Fatalf("failed to open sessions database: %v", err)
		}

		masterKey := rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "masterKey")
		userID := testutil.ValidUserID().Draw(t, "userID")

		km := NewKeyManager(masterKey, sessionsDB)

		// Get DEK for nonexistent user
		_, err = km.GetUserDEK(userID)
		if err == nil {
			t.Fatalf("GetUserDEK should have failed for nonexistent user")
		}
		if err != ErrUserKeyNotFound {
			t.Fatalf("wrong error: got %v, want ErrUserKeyNotFound", err)
		}
	})
}

// TestKeyManager_RotateKEK_PreservesDEK tests that KEK rotation preserves the DEK.
func TestKeyManager_RotateKEK_PreservesDEK(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		db.ResetForTesting()
		tmpDir, err := os.MkdirTemp("", "keymanager-test-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)
		db.DataDirectory = tmpDir

		sessionsDB, err := db.OpenSessionsDB()
		if err != nil {
			t.Fatalf("failed to open sessions database: %v", err)
		}

		masterKey := rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "masterKey")
		userID := testutil.ValidUserID().Draw(t, "userID")

		km := NewKeyManager(masterKey, sessionsDB)

		// Create DEK
		originalDEK, err := km.GetOrCreateUserDEK(userID)
		if err != nil {
			t.Fatalf("GetOrCreateUserDEK failed: %v", err)
		}

		// Rotate KEK
		err = km.RotateUserKEK(userID)
		if err != nil {
			t.Fatalf("RotateUserKEK failed: %v", err)
		}

		// Get DEK should still return the same value
		rotatedDEK, err := km.GetUserDEK(userID)
		if err != nil {
			t.Fatalf("GetUserDEK after rotation failed: %v", err)
		}

		if !bytes.Equal(originalDEK, rotatedDEK) {
			t.Fatalf("DEK changed after rotation: %x != %x", originalDEK, rotatedDEK)
		}
	})
}

// TestKeyManager_RotateKEK_NotFound tests that rotating a nonexistent user's key fails.
func TestKeyManager_RotateKEK_NotFound(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		db.ResetForTesting()
		tmpDir, err := os.MkdirTemp("", "keymanager-test-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)
		db.DataDirectory = tmpDir

		sessionsDB, err := db.OpenSessionsDB()
		if err != nil {
			t.Fatalf("failed to open sessions database: %v", err)
		}

		masterKey := rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "masterKey")
		userID := testutil.ValidUserID().Draw(t, "userID")

		km := NewKeyManager(masterKey, sessionsDB)

		// Rotate nonexistent user's key
		err = km.RotateUserKEK(userID)
		if err == nil {
			t.Fatalf("RotateUserKEK should have failed for nonexistent user")
		}
		if err != ErrUserKeyNotFound {
			t.Fatalf("wrong error: got %v, want ErrUserKeyNotFound", err)
		}
	})
}

// TestKeyManager_MultipleRotations tests that multiple rotations preserve the DEK.
func TestKeyManager_MultipleRotations(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		db.ResetForTesting()
		tmpDir, err := os.MkdirTemp("", "keymanager-test-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)
		db.DataDirectory = tmpDir

		sessionsDB, err := db.OpenSessionsDB()
		if err != nil {
			t.Fatalf("failed to open sessions database: %v", err)
		}

		masterKey := rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "masterKey")
		userID := testutil.ValidUserID().Draw(t, "userID")
		numRotations := rapid.IntRange(1, 10).Draw(t, "numRotations")

		km := NewKeyManager(masterKey, sessionsDB)

		// Create DEK
		originalDEK, err := km.GetOrCreateUserDEK(userID)
		if err != nil {
			t.Fatalf("GetOrCreateUserDEK failed: %v", err)
		}

		// Rotate multiple times
		for i := 0; i < numRotations; i++ {
			err = km.RotateUserKEK(userID)
			if err != nil {
				t.Fatalf("RotateUserKEK iteration %d failed: %v", i, err)
			}
		}

		// DEK should still be the same
		finalDEK, err := km.GetUserDEK(userID)
		if err != nil {
			t.Fatalf("GetUserDEK after rotations failed: %v", err)
		}

		if !bytes.Equal(originalDEK, finalDEK) {
			t.Fatalf("DEK changed after %d rotations: %x != %x", numRotations, originalDEK, finalDEK)
		}
	})
}

// TestKeyManager_DifferentUsers_DifferentDEKs tests that different users get different DEKs.
func TestKeyManager_DifferentUsers_DifferentDEKs(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		db.ResetForTesting()
		tmpDir, err := os.MkdirTemp("", "keymanager-test-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)
		db.DataDirectory = tmpDir

		sessionsDB, err := db.OpenSessionsDB()
		if err != nil {
			t.Fatalf("failed to open sessions database: %v", err)
		}

		masterKey := rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "masterKey")
		userID1 := testutil.ValidUserID().Draw(t, "userID1")
		userID2 := testutil.ValidUserID().Filter(func(s string) bool {
			return s != userID1
		}).Draw(t, "userID2")

		km := NewKeyManager(masterKey, sessionsDB)

		// Create DEKs for both users
		dek1, err := km.GetOrCreateUserDEK(userID1)
		if err != nil {
			t.Fatalf("GetOrCreateUserDEK for user1 failed: %v", err)
		}

		dek2, err := km.GetOrCreateUserDEK(userID2)
		if err != nil {
			t.Fatalf("GetOrCreateUserDEK for user2 failed: %v", err)
		}

		// Different users should have different DEKs (with overwhelming probability)
		if bytes.Equal(dek1, dek2) {
			t.Fatalf("different users got same DEK: userID1=%q, userID2=%q", userID1, userID2)
		}
	})
}

// TestKeyManager_DifferentMasterKeys_DifferentDEKs tests that the same user with
// different master keys gets different decryption results (or errors).
func TestKeyManager_DifferentMasterKeys_DifferentDEKs(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		db.ResetForTesting()
		tmpDir, err := os.MkdirTemp("", "keymanager-test-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)
		db.DataDirectory = tmpDir

		sessionsDB, err := db.OpenSessionsDB()
		if err != nil {
			t.Fatalf("failed to open sessions database: %v", err)
		}

		masterKey1 := rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "masterKey1")
		masterKey2 := rapid.SliceOfN(rapid.Byte(), 32, 32).Filter(func(b []byte) bool {
			return !bytes.Equal(b, masterKey1)
		}).Draw(t, "masterKey2")
		userID := testutil.ValidUserID().Draw(t, "userID")

		// Create DEK with first master key
		km1 := NewKeyManager(masterKey1, sessionsDB)
		dek1, err := km1.GetOrCreateUserDEK(userID)
		if err != nil {
			t.Fatalf("GetOrCreateUserDEK with masterKey1 failed: %v", err)
		}

		// Try to get DEK with second master key
		km2 := NewKeyManager(masterKey2, sessionsDB)
		dek2, err := km2.GetUserDEK(userID)
		if err == nil {
			// If decryption succeeded, the DEK should be garbage (not equal to original)
			if bytes.Equal(dek1, dek2) {
				t.Fatalf("different master keys produced same DEK - this should never happen")
			}
		}
		// err != nil is the expected case (GCM authentication failure)
	})
}
