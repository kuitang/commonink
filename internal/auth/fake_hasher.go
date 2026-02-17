package auth

import "strings"

// FakeInsecureHasher implements PasswordHasher with zero crypto overhead.
// Stores passwords as "$fake$<plaintext>" and verifies by string comparison.
// For use in tests ONLY — never in production.
type FakeInsecureHasher struct{}

func (FakeInsecureHasher) HashPassword(password string) (string, error) {
	return "$fake$" + password, nil
}

func (FakeInsecureHasher) VerifyPassword(password, encodedHash string) bool {
	return strings.TrimPrefix(encodedHash, "$fake$") == password
}
