package oauth

import (
	"testing"

	"pgregory.net/rapid"
)

func testFakeInsecureClientSecretHasher_RoundTrip(t *rapid.T) {
	secret := rapid.StringMatching(`[A-Za-z0-9._\-]{1,64}`).Draw(t, "secret")
	hasher := FakeInsecureClientSecretHasher{}

	hash, err := hasher.HashSecret(secret)
	if err != nil {
		t.Fatalf("HashSecret failed: %v", err)
	}
	if err := hasher.VerifySecret(hash, secret); err != nil {
		t.Fatalf("VerifySecret should succeed for matching secret: %v", err)
	}
	if err := hasher.VerifySecret(hash, secret+"x"); err == nil {
		t.Fatal("VerifySecret should fail for mismatched secret")
	}
}

func TestFakeInsecureClientSecretHasher_RoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testFakeInsecureClientSecretHasher_RoundTrip)
}

func TestNewBcryptClientSecretHasher_ClampsInvalidCost(t *testing.T) {
	t.Parallel()
	hasher := NewBcryptClientSecretHasher(-1)
	hash, err := hasher.HashSecret("secret-123")
	if err != nil {
		t.Fatalf("HashSecret failed with clamped default cost: %v", err)
	}
	if err := hasher.VerifySecret(hash, "secret-123"); err != nil {
		t.Fatalf("VerifySecret failed for valid hash: %v", err)
	}
	if err := hasher.VerifySecret(hash, "wrong"); err == nil {
		t.Fatal("VerifySecret should fail for wrong secret")
	}
}
