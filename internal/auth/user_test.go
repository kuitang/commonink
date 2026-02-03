package auth

import (
	"context"
	"testing"

	"pgregory.net/rapid"
)

// TestPassword_HashVerify_Roundtrip tests that hashed passwords can be verified.
func TestPassword_HashVerify_Roundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate random password (at least 8 chars to pass validation)
		password := rapid.StringN(8, 100, 200).Draw(t, "password")

		hash, err := HashPassword(password)
		if err != nil {
			t.Fatalf("HashPassword failed: %v", err)
		}

		if !VerifyPassword(password, hash) {
			t.Fatalf("VerifyPassword failed for password %q", password)
		}
	})
}

// TestPassword_WrongPassword_FailsVerify tests that wrong passwords don't verify.
func TestPassword_WrongPassword_FailsVerify(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		password1 := rapid.StringN(8, 50, 100).Draw(t, "password1")
		password2 := rapid.StringN(8, 50, 100).Filter(func(s string) bool {
			return s != password1
		}).Draw(t, "password2")

		hash, err := HashPassword(password1)
		if err != nil {
			t.Fatalf("HashPassword failed: %v", err)
		}

		if VerifyPassword(password2, hash) {
			t.Fatalf("VerifyPassword should fail for wrong password")
		}
	})
}

// TestPassword_HashNotDeterministic tests that hashing produces different outputs.
func TestPassword_HashNotDeterministic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		password := rapid.StringN(8, 50, 100).Draw(t, "password")

		hash1, err := HashPassword(password)
		if err != nil {
			t.Fatalf("first HashPassword failed: %v", err)
		}

		hash2, err := HashPassword(password)
		if err != nil {
			t.Fatalf("second HashPassword failed: %v", err)
		}

		if hash1 == hash2 {
			t.Fatalf("hashing is deterministic - salt is not random")
		}
	})
}

// TestPassword_Validation tests password strength validation.
func TestPassword_Validation(t *testing.T) {
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

// TestMockOIDC_Reset tests that MockOIDCClient.Reset() clears all state.
func TestMockOIDC_Reset(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		oidcClient := NewMockOIDCClient()

		// Set up some state
		sub := rapid.StringMatching(`[0-9]{10}`).Draw(rt, "sub")
		emailAddr := rapid.StringMatching(`[a-z]{5}@test\.com`).Draw(rt, "email")
		oidcClient.SetNextSuccess(sub, emailAddr, "Test User", true)
		oidcClient.GetAuthURL("test-state")
		_, _ = oidcClient.ExchangeCode(context.Background(), "test-code")

		// Reset
		oidcClient.Reset()

		// Property: All state should be cleared
		if oidcClient.NextClaims != nil {
			rt.Fatal("NextClaims should be nil after reset")
		}
		if oidcClient.NextError != nil {
			rt.Fatal("NextError should be nil after reset")
		}
		if oidcClient.LastState != "" {
			rt.Fatal("LastState should be empty after reset")
		}
		if oidcClient.LastCode != "" {
			rt.Fatal("LastCode should be empty after reset")
		}
	})
}
