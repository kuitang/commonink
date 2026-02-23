package auth

import (
	"testing"

	"pgregory.net/rapid"
)

// TestPassword_HashVerify_Roundtrip tests that hashed passwords can be verified.
// Uses FakeInsecureHasher to test the PasswordHasher interface contract without Argon2 overhead.
func TestPassword_HashVerify_Roundtrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var hasher PasswordHasher = FakeInsecureHasher{}
		password := rapid.StringN(8, 100, 200).Draw(t, "password")

		hash, err := hasher.HashPassword(password)
		if err != nil {
			t.Fatalf("HashPassword failed: %v", err)
		}

		if !hasher.VerifyPassword(password, hash) {
			t.Fatalf("VerifyPassword failed for password %q", password)
		}
	})
}

func FuzzPassword_HashVerify_Roundtrip(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(t *rapid.T) {
		var hasher PasswordHasher = FakeInsecureHasher{}
		password := rapid.StringN(8, 100, 200).Draw(t, "password")

		hash, err := hasher.HashPassword(password)
		if err != nil {
			t.Fatalf("HashPassword failed: %v", err)
		}

		if !hasher.VerifyPassword(password, hash) {
			t.Fatalf("VerifyPassword failed for password %q", password)
		}
	}))
}

// TestPassword_WrongPassword_FailsVerify tests that wrong passwords don't verify.
func TestPassword_WrongPassword_FailsVerify(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		var hasher PasswordHasher = FakeInsecureHasher{}
		password1 := rapid.StringN(8, 50, 100).Draw(t, "password1")
		password2 := rapid.StringN(8, 50, 100).Filter(func(s string) bool {
			return s != password1
		}).Draw(t, "password2")

		hash, err := hasher.HashPassword(password1)
		if err != nil {
			t.Fatalf("HashPassword failed: %v", err)
		}

		if hasher.VerifyPassword(password2, hash) {
			t.Fatalf("VerifyPassword should fail for wrong password")
		}
	})
}

func FuzzPassword_WrongPassword_FailsVerify(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(t *rapid.T) {
		var hasher PasswordHasher = FakeInsecureHasher{}
		password1 := rapid.StringN(8, 50, 100).Draw(t, "password1")
		password2 := rapid.StringN(8, 50, 100).Filter(func(s string) bool {
			return s != password1
		}).Draw(t, "password2")

		hash, err := hasher.HashPassword(password1)
		if err != nil {
			t.Fatalf("HashPassword failed: %v", err)
		}

		if hasher.VerifyPassword(password2, hash) {
			t.Fatalf("VerifyPassword should fail for wrong password")
		}
	}))
}

// TestPassword_Argon2_NonDeterministic verifies that real Argon2 hashing uses random salt.
// Single call, not rapid — this is an Argon2-specific property, not an interface contract.
func TestPassword_Argon2_NonDeterministic(t *testing.T) {
	t.Parallel()
	hash1, err := HashPassword("test-password")
	if err != nil {
		t.Fatalf("first HashPassword failed: %v", err)
	}
	hash2, err := HashPassword("test-password")
	if err != nil {
		t.Fatalf("second HashPassword failed: %v", err)
	}
	if hash1 == hash2 {
		t.Fatalf("hashing is deterministic - salt is not random")
	}
}

// TestPassword_Validation tests password strength validation.
func TestPassword_Validation(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Test short passwords fail (passwords with fewer than 8 bytes)
		// We generate short byte slices and convert to string to ensure byte length < 8
		shortBytes := rapid.SliceOfN(rapid.Byte(), 0, 7).Draw(t, "shortBytes")
		shortPassword := string(shortBytes)
		if len(shortPassword) >= 8 {
			// Skip if random bytes happened to form >= 8 byte string
			return
		}
		if err := ValidatePasswordStrength(shortPassword); err == nil {
			t.Fatalf("short password (len=%d) should fail validation", len(shortPassword))
		}
	})
}

// TestPassword_Validation_ValidPasswords tests that valid passwords pass validation.
func TestPassword_Validation_ValidPasswords(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Test valid passwords pass (passwords with 8+ bytes)
		// We generate byte slices with 8-100 bytes to ensure byte length >= 8
		validBytes := rapid.SliceOfN(rapid.Byte(), 8, 100).Draw(t, "validBytes")
		validPassword := string(validBytes)
		if err := ValidatePasswordStrength(validPassword); err != nil {
			t.Fatalf("valid password (len=%d) should pass validation: %v", len(validPassword), err)
		}
	})
}
