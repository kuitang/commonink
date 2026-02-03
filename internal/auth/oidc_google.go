package auth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// GoogleOIDCClient implements the OIDCClient interface using Google's OIDC provider.
type GoogleOIDCClient struct {
	provider    *oidc.Provider
	verifier    *oidc.IDTokenVerifier
	oauthConfig *oauth2.Config
}

// NewGoogleOIDCClient creates a new Google OIDC client.
// It initializes the OIDC provider using Google's well-known endpoint
// (https://accounts.google.com/.well-known/openid-configuration).
func NewGoogleOIDCClient(clientID, clientSecret, redirectURL string) (*GoogleOIDCClient, error) {
	ctx := context.Background()

	// Initialize the OIDC provider using Google's issuer URL
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Create the ID token verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	// Configure OAuth2 with the provider's endpoints
	oauthConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}

	return &GoogleOIDCClient{
		provider:    provider,
		verifier:    verifier,
		oauthConfig: oauthConfig,
	}, nil
}

// GetAuthURL returns the Google authorization URL with the provided state parameter.
// The state parameter should be a random string for CSRF protection.
func (g *GoogleOIDCClient) GetAuthURL(state string) string {
	return g.oauthConfig.AuthCodeURL(state)
}

// ExchangeCode exchanges an authorization code for ID token claims.
// It performs the OAuth2 token exchange, verifies the ID token, and extracts the claims.
func (g *GoogleOIDCClient) ExchangeCode(ctx context.Context, code string) (*Claims, error) {
	// Exchange the authorization code for tokens
	oauth2Token, err := g.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCodeExchangeFailed, err)
	}

	// Extract the ID token from the OAuth2 token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("%w: missing id_token in token response", ErrCodeExchangeFailed)
	}

	// Verify the ID token
	idToken, err := g.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("%w: id_token verification failed: %v", ErrCodeExchangeFailed, err)
	}

	// Extract claims from the ID token
	var googleClaims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := idToken.Claims(&googleClaims); err != nil {
		return nil, fmt.Errorf("%w: failed to parse claims: %v", ErrCodeExchangeFailed, err)
	}

	return &Claims{
		Sub:           googleClaims.Sub,
		Email:         googleClaims.Email,
		Name:          googleClaims.Name,
		EmailVerified: googleClaims.EmailVerified,
	}, nil
}
