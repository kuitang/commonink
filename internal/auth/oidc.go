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

// MockOIDCClient is a mock implementation for testing.
type MockOIDCClient struct {
	// NextClaims is returned by ExchangeCode. Set this before calling ExchangeCode.
	NextClaims *Claims
	// NextError is returned by ExchangeCode if set. Takes precedence over NextClaims.
	NextError error
	// AuthURL is returned by GetAuthURL.
	AuthURL string
	// LastState captures the state passed to GetAuthURL.
	LastState string
	// LastCode captures the code passed to ExchangeCode.
	LastCode string
}

// NewMockOIDCClient creates a new mock OIDC client.
func NewMockOIDCClient() *MockOIDCClient {
	return &MockOIDCClient{
		AuthURL: "https://mock-oidc.example.com/authorize",
	}
}

// GetAuthURL returns a mock authorization URL.
func (m *MockOIDCClient) GetAuthURL(state, _ string) string {
	m.LastState = state
	return m.AuthURL + "?state=" + state
}

// ExchangeCode returns the configured NextClaims or NextError.
func (m *MockOIDCClient) ExchangeCode(ctx context.Context, code, _ string) (*Claims, error) {
	m.LastCode = code
	if m.NextError != nil {
		return nil, m.NextError
	}
	if m.NextClaims == nil {
		return nil, ErrCodeExchangeFailed
	}
	return m.NextClaims, nil
}

// SetNextSuccess configures the mock to return successful claims.
func (m *MockOIDCClient) SetNextSuccess(sub, email, name string, emailVerified bool) {
	m.NextError = nil
	m.NextClaims = &Claims{
		Sub:           sub,
		Email:         email,
		Name:          name,
		EmailVerified: emailVerified,
	}
}

// SetNextError configures the mock to return an error.
func (m *MockOIDCClient) SetNextError(err error) {
	m.NextError = err
	m.NextClaims = nil
}

// Reset clears all captured state and configured responses.
func (m *MockOIDCClient) Reset() {
	m.NextClaims = nil
	m.NextError = nil
	m.LastState = ""
	m.LastCode = ""
}
