package oauth

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	// DefaultBcryptClientSecretCost is the production bcrypt cost for OAuth client secrets.
	DefaultBcryptClientSecretCost = 12
)

// ClientSecretHasher hashes and verifies OAuth client_secret values.
type ClientSecretHasher interface {
	HashSecret(secret string) (string, error)
	VerifySecret(hash, secret string) error
}

// BcryptClientSecretHasher implements ClientSecretHasher with bcrypt.
type BcryptClientSecretHasher struct {
	cost int
}

// NewBcryptClientSecretHasher creates a bcrypt-based client secret hasher.
func NewBcryptClientSecretHasher(cost int) BcryptClientSecretHasher {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = DefaultBcryptClientSecretCost
	}
	return BcryptClientSecretHasher{cost: cost}
}

func (h BcryptClientSecretHasher) HashSecret(secret string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), h.cost)
	if err != nil {
		return "", fmt.Errorf("oauth: failed to hash secret: %w", err)
	}
	return string(hash), nil
}

func (h BcryptClientSecretHasher) VerifySecret(hash, secret string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret))
	if err != nil {
		return ErrInvalidClient
	}
	return nil
}

// FakeInsecureClientSecretHasher is a test-only hasher with near-zero CPU cost.
// It is intentionally insecure and must never be used in production.
type FakeInsecureClientSecretHasher struct{}

func (FakeInsecureClientSecretHasher) HashSecret(secret string) (string, error) {
	return "$oauth_fake$" + secret, nil
}

func (FakeInsecureClientSecretHasher) VerifySecret(hash, secret string) error {
	if strings.TrimPrefix(hash, "$oauth_fake$") == secret {
		return nil
	}
	return ErrInvalidClient
}

// HashSecret hashes a client_secret using the default production hasher.
func HashSecret(secret string) (string, error) {
	return NewBcryptClientSecretHasher(DefaultBcryptClientSecretCost).HashSecret(secret)
}

// VerifySecret verifies a plaintext secret against a bcrypt hash.
func VerifySecret(hash, secret string) error {
	return NewBcryptClientSecretHasher(DefaultBcryptClientSecretCost).VerifySecret(hash, secret)
}
