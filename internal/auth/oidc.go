package auth

import (
	"context"
	"errors"
)

// ErrInvalidState is returned when the OAuth state parameter doesn't match.
var ErrInvalidState = errors.New("invalid state parameter")

// ErrCodeExchangeFailed is returned when code exchange fails.
var ErrCodeExchangeFailed = errors.New("code exchange failed")

// Claims contains the ID token claims from OIDC authentication.
type Claims struct {
	Sub           string // Unique identifier from the provider
	Email         string
	Name          string
	EmailVerified bool
}

// OIDCClient defines the interface for OIDC authentication.
// In Milestone 2, only the mock implementation is used.
// Real implementations (e.g., Google) will be added in Milestone 4.
type OIDCClient interface {
	// GetAuthURL returns the URL to redirect the user to for authentication.
	// The state parameter should be a random string for CSRF protection.
	GetAuthURL(state, redirectURL string) string

	// ExchangeCode exchanges an authorization code for ID token claims.
	// Returns the user's claims if successful.
	ExchangeCode(ctx context.Context, code, redirectURL string) (*Claims, error)
}
