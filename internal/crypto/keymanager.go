package crypto

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/db/sessions"
)

// ErrUserKeyNotFound is returned when a user's key entry does not exist
var ErrUserKeyNotFound = errors.New("user key not found")

// KeyManager handles envelope encryption for user database keys.
// It manages KEK derivation from a master key and DEK creation/retrieval.
type KeyManager struct {
	masterKey []byte
	db        *db.SessionsDB
}

// NewKeyManager creates a new KeyManager with the provided master key and sessions database.
//
// Parameters:
//   - masterKey: The root secret for deriving KEKs (must be high-entropy, at least 32 bytes)
//   - db: The sessions database for storing encrypted DEKs
//
// Returns:
//   - *KeyManager: A new KeyManager instance
func NewKeyManager(masterKey []byte, db *db.SessionsDB) *KeyManager {
	return &KeyManager{
		masterKey: masterKey,
		db:        db,
	}
}

// GetOrCreateUserDEK retrieves the DEK for a user, creating one if it doesn't exist.
// On first call for a user, generates a new DEK, encrypts it with the KEK, and stores it.
// On subsequent calls, retrieves and decrypts the stored DEK.
//
// Parameters:
//   - userID: The unique identifier for the user
//
// Returns:
//   - []byte: The 32-byte DEK for the user's database encryption
//   - error: Any error during key operations
func (km *KeyManager) GetOrCreateUserDEK(userID string) ([]byte, error) {
	ctx := context.Background()

	// Try to get existing key
	userKey, err := km.db.Queries().GetUserKey(ctx, userID)
	if err == nil {
		// Key exists, derive KEK and decrypt DEK
		kek := DeriveKEK(km.masterKey, userID, int(userKey.KekVersion))
		return DecryptDEK(kek, userKey.EncryptedDek)
	}

	// Check if error is "not found" (sql.ErrNoRows)
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("failed to get user key: %w", err)
	}

	// Key doesn't exist, create new one
	dek, err := GenerateDEK()
	if err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Encrypt DEK with KEK (version 1 for new keys)
	kekVersion := 1
	kek := DeriveKEK(km.masterKey, userID, kekVersion)
	encryptedDEK, err := EncryptDEK(kek, dek)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DEK: %w", err)
	}

	// Store encrypted DEK
	now := time.Now().Unix()
	err = km.db.Queries().CreateUserKey(ctx, sessions.CreateUserKeyParams{
		UserID:       userID,
		KekVersion:   int64(kekVersion),
		EncryptedDek: encryptedDEK,
		CreatedAt:    now,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store user key: %w", err)
	}

	return dek, nil
}

// GetUserDEK retrieves the DEK for an existing user.
// Unlike GetOrCreateUserDEK, this returns an error if the user has no key.
//
// Parameters:
//   - userID: The unique identifier for the user
//
// Returns:
//   - []byte: The 32-byte DEK for the user's database encryption
//   - error: ErrUserKeyNotFound if user has no key, or other errors
func (km *KeyManager) GetUserDEK(userID string) ([]byte, error) {
	ctx := context.Background()

	// Get existing key
	userKey, err := km.db.Queries().GetUserKey(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserKeyNotFound
		}
		return nil, fmt.Errorf("failed to get user key: %w", err)
	}

	// Derive KEK and decrypt DEK
	kek := DeriveKEK(km.masterKey, userID, int(userKey.KekVersion))
	dek, err := DecryptDEK(kek, userKey.EncryptedDek)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	return dek, nil
}

// RotateUserKEK rotates the KEK for a user by incrementing the version.
// This re-encrypts the existing DEK with a new KEK derived using version+1.
// The DEK itself remains unchanged, only its encryption key changes.
//
// Parameters:
//   - userID: The unique identifier for the user
//
// Returns:
//   - error: Any error during rotation
func (km *KeyManager) RotateUserKEK(userID string) error {
	ctx := context.Background()

	// Get current key
	userKey, err := km.db.Queries().GetUserKey(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserKeyNotFound
		}
		return fmt.Errorf("failed to get user key: %w", err)
	}

	// Decrypt DEK with current KEK
	currentKEK := DeriveKEK(km.masterKey, userID, int(userKey.KekVersion))
	dek, err := DecryptDEK(currentKEK, userKey.EncryptedDek)
	if err != nil {
		return fmt.Errorf("failed to decrypt current DEK: %w", err)
	}

	// Encrypt DEK with new KEK (version + 1)
	newVersion := userKey.KekVersion + 1
	newKEK := DeriveKEK(km.masterKey, userID, int(newVersion))
	newEncryptedDEK, err := EncryptDEK(newKEK, dek)
	if err != nil {
		return fmt.Errorf("failed to encrypt DEK with new KEK: %w", err)
	}

	// Update stored key
	now := time.Now().Unix()
	err = km.db.Queries().UpdateUserKey(ctx, sessions.UpdateUserKeyParams{
		UserID:       userID,
		KekVersion:   newVersion,
		EncryptedDek: newEncryptedDEK,
		RotatedAt:    sql.NullInt64{Int64: now, Valid: true},
	})
	if err != nil {
		return fmt.Errorf("failed to update user key: %w", err)
	}

	return nil
}
