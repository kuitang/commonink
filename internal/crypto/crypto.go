// Package crypto provides envelope encryption for per-user database keys.
// It implements a two-tier key hierarchy:
// - KEK (Key Encryption Key): Derived from master key using HKDF-SHA256
// - DEK (Data Encryption Key): Random 32-byte key encrypted with KEK using AES-256-GCM
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// DEKSize is the size of a Data Encryption Key in bytes (256 bits)
	DEKSize = 32

	// KEKSize is the size of a Key Encryption Key in bytes (256 bits)
	KEKSize = 32

	// NonceSize is the size of the AES-GCM nonce in bytes (96 bits)
	NonceSize = 12
)

// DeriveKEK derives a Key Encryption Key from a master key using HKDF-SHA256.
// The info parameter combines user ID and version for domain separation:
// info = "user:" + userID + ":v" + version
//
// Parameters:
//   - masterKey: The root secret (must be high-entropy, at least 32 bytes recommended)
//   - userID: The unique identifier for the user
//   - version: The KEK version (for key rotation support)
//
// Returns:
//   - []byte: A 32-byte KEK derived deterministically from the inputs
func DeriveKEK(masterKey []byte, userID string, version int) []byte {
	// Construct info string for domain separation
	info := fmt.Sprintf("user:%s:v%d", userID, version)

	// Create HKDF reader
	// Salt is nil - using a random master key is sufficient for our use case
	hkdfReader := hkdf.New(sha256.New, masterKey, nil, []byte(info))

	// Read KEK from HKDF
	kek := make([]byte, KEKSize)
	if _, err := io.ReadFull(hkdfReader, kek); err != nil {
		// HKDF should never fail to produce output for valid inputs
		// This would indicate a serious bug
		panic(fmt.Sprintf("HKDF failed: %v", err))
	}

	return kek
}

// GenerateDEK generates a new random Data Encryption Key.
// Uses crypto/rand for cryptographically secure random bytes.
//
// Returns:
//   - []byte: A 32-byte random DEK
//   - error: Any error from the random source
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, DEKSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}
	return dek, nil
}

// EncryptDEK encrypts a DEK using AES-256-GCM with the provided KEK.
// The nonce is randomly generated and prepended to the ciphertext.
// Output format: nonce (12 bytes) || ciphertext || auth tag (16 bytes)
//
// Parameters:
//   - kek: The 32-byte Key Encryption Key
//   - dek: The 32-byte Data Encryption Key to encrypt
//
// Returns:
//   - []byte: The encrypted DEK with prepended nonce (12 + 32 + 16 = 60 bytes)
//   - error: Any encryption error
func EncryptDEK(kek, dek []byte) ([]byte, error) {
	if len(kek) != KEKSize {
		return nil, fmt.Errorf("KEK must be %d bytes, got %d", KEKSize, len(kek))
	}
	if len(dek) != DEKSize {
		return nil, fmt.Errorf("DEK must be %d bytes, got %d", DEKSize, len(dek))
	}

	// Create AES cipher
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt DEK and prepend nonce to the output
	// Output format: nonce (12 bytes) || ciphertext || auth tag (16 bytes)
	ciphertext := gcm.Seal(nil, nonce, dek, nil)
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// DecryptDEK decrypts an encrypted DEK using AES-256-GCM with the provided KEK.
// Expects the input format: nonce (12 bytes) || ciphertext || auth tag (16 bytes)
//
// Parameters:
//   - kek: The 32-byte Key Encryption Key
//   - encryptedDEK: The encrypted DEK (must be at least 12 + 16 = 28 bytes)
//
// Returns:
//   - []byte: The decrypted 32-byte DEK
//   - error: Decryption or authentication error
func DecryptDEK(kek, encryptedDEK []byte) ([]byte, error) {
	if len(kek) != KEKSize {
		return nil, fmt.Errorf("KEK must be %d bytes, got %d", KEKSize, len(kek))
	}

	// Minimum size: nonce (12) + auth tag (16) = 28 bytes
	// With 32-byte DEK, total is 60 bytes
	if len(encryptedDEK) < NonceSize+16 {
		return nil, fmt.Errorf("encrypted DEK too short: got %d bytes, need at least %d", len(encryptedDEK), NonceSize+16)
	}

	// Create AES cipher
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce and ciphertext
	nonce := encryptedDEK[:NonceSize]
	ciphertext := encryptedDEK[NonceSize:]

	// Decrypt
	dek, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	return dek, nil
}
