package crypto

import (
	"bytes"
	"testing"

	"pgregory.net/rapid"
)

// TestCrypto_EncryptDecrypt_Roundtrip tests that encrypting then decrypting a DEK
// returns the original DEK. This is the fundamental correctness property.
func TestCrypto_EncryptDecrypt_Roundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kek := rapid.SliceOfN(rapid.Byte(), KEKSize, KEKSize).Draw(t, "kek")
		dek := rapid.SliceOfN(rapid.Byte(), DEKSize, DEKSize).Draw(t, "dek")

		encrypted, err := EncryptDEK(kek, dek)
		if err != nil {
			t.Fatalf("EncryptDEK failed: %v", err)
		}

		decrypted, err := DecryptDEK(kek, encrypted)
		if err != nil {
			t.Fatalf("DecryptDEK failed: %v", err)
		}

		if !bytes.Equal(dek, decrypted) {
			t.Fatalf("roundtrip failed: got %x, want %x", decrypted, dek)
		}
	})
}

// TestCrypto_KEK_Deterministic tests that DeriveKEK is a pure function:
// the same inputs always produce the same output.
func TestCrypto_KEK_Deterministic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		masterKey := rapid.SliceOfN(rapid.Byte(), 16, 64).Draw(t, "masterKey")
		userID := rapid.String().Draw(t, "userID")
		version := rapid.IntRange(1, 1000).Draw(t, "version")

		kek1 := DeriveKEK(masterKey, userID, version)
		kek2 := DeriveKEK(masterKey, userID, version)

		if !bytes.Equal(kek1, kek2) {
			t.Fatalf("KEK derivation not deterministic: %x != %x", kek1, kek2)
		}
	})
}

// TestCrypto_KEK_DifferentInputs_DifferentOutputs tests that different inputs
// produce different KEKs. This verifies domain separation is working.
func TestCrypto_KEK_DifferentInputs_DifferentOutputs(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		masterKey := rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "masterKey")
		userID1 := rapid.String().Draw(t, "userID1")
		userID2 := rapid.String().Filter(func(s string) bool {
			return s != userID1
		}).Draw(t, "userID2")
		version := rapid.IntRange(1, 1000).Draw(t, "version")

		kek1 := DeriveKEK(masterKey, userID1, version)
		kek2 := DeriveKEK(masterKey, userID2, version)

		if bytes.Equal(kek1, kek2) {
			t.Fatalf("different userIDs produced same KEK: userID1=%q, userID2=%q", userID1, userID2)
		}
	})
}

// TestCrypto_KEK_DifferentVersions_DifferentOutputs tests that different versions
// produce different KEKs for the same user.
func TestCrypto_KEK_DifferentVersions_DifferentOutputs(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		masterKey := rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "masterKey")
		userID := rapid.String().Draw(t, "userID")
		version1 := rapid.IntRange(1, 500).Draw(t, "version1")
		version2 := rapid.IntRange(501, 1000).Draw(t, "version2")

		kek1 := DeriveKEK(masterKey, userID, version1)
		kek2 := DeriveKEK(masterKey, userID, version2)

		if bytes.Equal(kek1, kek2) {
			t.Fatalf("different versions produced same KEK: v%d == v%d", version1, version2)
		}
	})
}

// TestCrypto_WrongKEK_FailsDecrypt tests that decryption with the wrong KEK
// fails (returns an error due to authentication failure).
func TestCrypto_WrongKEK_FailsDecrypt(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kek1 := rapid.SliceOfN(rapid.Byte(), KEKSize, KEKSize).Draw(t, "kek1")
		kek2 := rapid.SliceOfN(rapid.Byte(), KEKSize, KEKSize).Filter(func(b []byte) bool {
			return !bytes.Equal(b, kek1)
		}).Draw(t, "kek2")
		dek := rapid.SliceOfN(rapid.Byte(), DEKSize, DEKSize).Draw(t, "dek")

		// Encrypt with kek1
		encrypted, err := EncryptDEK(kek1, dek)
		if err != nil {
			t.Fatalf("EncryptDEK failed: %v", err)
		}

		// Decrypt with kek2 should fail
		decrypted, err := DecryptDEK(kek2, encrypted)
		if err == nil {
			// If no error, the decrypted value should be wrong
			if bytes.Equal(dek, decrypted) {
				t.Fatalf("wrong KEK decrypted to correct DEK - this should never happen")
			}
		}
		// err != nil is the expected case (GCM authentication failure)
	})
}

// TestCrypto_DEK_Length tests that GenerateDEK produces 32-byte keys.
func TestCrypto_DEK_Length(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		dek, err := GenerateDEK()
		if err != nil {
			t.Fatalf("GenerateDEK failed: %v", err)
		}

		if len(dek) != DEKSize {
			t.Fatalf("DEK has wrong length: got %d, want %d", len(dek), DEKSize)
		}
	})
}

// TestCrypto_KEK_Length tests that DeriveKEK produces 32-byte keys.
func TestCrypto_KEK_Length(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		masterKey := rapid.SliceOfN(rapid.Byte(), 16, 64).Draw(t, "masterKey")
		userID := rapid.String().Draw(t, "userID")
		version := rapid.IntRange(1, 1000).Draw(t, "version")

		kek := DeriveKEK(masterKey, userID, version)

		if len(kek) != KEKSize {
			t.Fatalf("KEK has wrong length: got %d, want %d", len(kek), KEKSize)
		}
	})
}

// TestCrypto_Encryption_NonDeterministic tests that encrypting the same DEK twice
// produces different ciphertexts (due to random nonce).
func TestCrypto_Encryption_NonDeterministic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kek := rapid.SliceOfN(rapid.Byte(), KEKSize, KEKSize).Draw(t, "kek")
		dek := rapid.SliceOfN(rapid.Byte(), DEKSize, DEKSize).Draw(t, "dek")

		encrypted1, err := EncryptDEK(kek, dek)
		if err != nil {
			t.Fatalf("first EncryptDEK failed: %v", err)
		}

		encrypted2, err := EncryptDEK(kek, dek)
		if err != nil {
			t.Fatalf("second EncryptDEK failed: %v", err)
		}

		if bytes.Equal(encrypted1, encrypted2) {
			t.Fatalf("encryption is deterministic - nonce is not random")
		}

		// But both should decrypt to the same DEK
		decrypted1, err := DecryptDEK(kek, encrypted1)
		if err != nil {
			t.Fatalf("first DecryptDEK failed: %v", err)
		}

		decrypted2, err := DecryptDEK(kek, encrypted2)
		if err != nil {
			t.Fatalf("second DecryptDEK failed: %v", err)
		}

		if !bytes.Equal(decrypted1, decrypted2) {
			t.Fatalf("different ciphertexts decrypted to different values")
		}

		if !bytes.Equal(dek, decrypted1) {
			t.Fatalf("decryption returned wrong value")
		}
	})
}

// TestCrypto_InvalidKeySize_RejectsEncrypt tests that EncryptDEK rejects
// invalid key sizes.
func TestCrypto_InvalidKeySize_RejectsEncrypt(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate KEK with wrong size
		wrongSize := rapid.IntRange(1, 100).Filter(func(n int) bool {
			return n != KEKSize
		}).Draw(t, "wrongKEKSize")

		kek := rapid.SliceOfN(rapid.Byte(), wrongSize, wrongSize).Draw(t, "kek")
		dek := rapid.SliceOfN(rapid.Byte(), DEKSize, DEKSize).Draw(t, "dek")

		_, err := EncryptDEK(kek, dek)
		if err == nil {
			t.Fatalf("EncryptDEK accepted invalid KEK size: %d", len(kek))
		}
	})
}

// TestCrypto_InvalidDEKSize_RejectsEncrypt tests that EncryptDEK rejects
// invalid DEK sizes.
func TestCrypto_InvalidDEKSize_RejectsEncrypt(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kek := rapid.SliceOfN(rapid.Byte(), KEKSize, KEKSize).Draw(t, "kek")

		// Generate DEK with wrong size
		wrongSize := rapid.IntRange(1, 100).Filter(func(n int) bool {
			return n != DEKSize
		}).Draw(t, "wrongDEKSize")

		dek := rapid.SliceOfN(rapid.Byte(), wrongSize, wrongSize).Draw(t, "dek")

		_, err := EncryptDEK(kek, dek)
		if err == nil {
			t.Fatalf("EncryptDEK accepted invalid DEK size: %d", len(dek))
		}
	})
}

// TestCrypto_TruncatedCiphertext_FailsDecrypt tests that truncated ciphertext
// is rejected.
func TestCrypto_TruncatedCiphertext_FailsDecrypt(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kek := rapid.SliceOfN(rapid.Byte(), KEKSize, KEKSize).Draw(t, "kek")
		dek := rapid.SliceOfN(rapid.Byte(), DEKSize, DEKSize).Draw(t, "dek")

		encrypted, err := EncryptDEK(kek, dek)
		if err != nil {
			t.Fatalf("EncryptDEK failed: %v", err)
		}

		// Truncate to various sizes less than minimum
		truncateLen := rapid.IntRange(0, NonceSize+15).Draw(t, "truncateLen")
		truncated := encrypted[:truncateLen]

		_, err = DecryptDEK(kek, truncated)
		if err == nil {
			t.Fatalf("DecryptDEK accepted truncated ciphertext of length %d", truncateLen)
		}
	})
}

// TestCrypto_ModifiedCiphertext_FailsDecrypt tests that modified ciphertext
// is rejected (integrity check).
func TestCrypto_ModifiedCiphertext_FailsDecrypt(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kek := rapid.SliceOfN(rapid.Byte(), KEKSize, KEKSize).Draw(t, "kek")
		dek := rapid.SliceOfN(rapid.Byte(), DEKSize, DEKSize).Draw(t, "dek")

		encrypted, err := EncryptDEK(kek, dek)
		if err != nil {
			t.Fatalf("EncryptDEK failed: %v", err)
		}

		// Flip a random bit in the ciphertext (not the nonce, to ensure we test the auth tag)
		modifyPos := rapid.IntRange(NonceSize, len(encrypted)-1).Draw(t, "modifyPos")
		modified := make([]byte, len(encrypted))
		copy(modified, encrypted)
		modified[modifyPos] ^= 0xFF // Flip all bits at this position

		_, err = DecryptDEK(kek, modified)
		if err == nil {
			t.Fatalf("DecryptDEK accepted modified ciphertext")
		}
	})
}
