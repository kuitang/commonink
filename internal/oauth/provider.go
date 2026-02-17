// Package oauth implements an OAuth 2.1 provider for the agent-notes MCP server.
// It supports public clients (native apps, CLIs) with PKCE and confidential clients
// with client_secret_basic/post authentication.
package oauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/kuitang/agent-notes/internal/db/sessions"
	"golang.org/x/crypto/bcrypt"
)

// Errors returned by the OAuth provider.
var (
	ErrInvalidClient       = errors.New("oauth: invalid client")
	ErrInvalidCode         = errors.New("oauth: invalid or expired authorization code")
	ErrInvalidToken        = errors.New("oauth: invalid or expired token")
	ErrInvalidGrant        = errors.New("oauth: invalid grant")
	ErrInvalidPKCE         = errors.New("oauth: invalid PKCE code_verifier")
	ErrInvalidRedirectURI  = errors.New("oauth: invalid redirect_uri")
	ErrInvalidScope        = errors.New("oauth: invalid scope")
	ErrClientSecretMissing = errors.New("oauth: client_secret required for confidential client")
	ErrCodeExpired         = errors.New("oauth: authorization code expired")
	ErrTokenExpired        = errors.New("oauth: token expired")
)

// TokenType represents the type of access token.
const TokenType = "Bearer"

// Default token lifetimes.
const (
	DefaultAccessTokenLifetime  = 1 * time.Hour
	DefaultRefreshTokenLifetime = 30 * 24 * time.Hour
	DefaultCodeLifetime         = 10 * time.Minute
)

// AccessTokenClaims represents the claims in an access token JWT.
type AccessTokenClaims struct {
	jwt.Claims
	Scope    string `json:"scope,omitempty"`
	Resource string `json:"resource,omitempty"`
	ClientID string `json:"client_id,omitempty"`
}

// Provider is the OAuth 2.1 authorization server implementation.
type Provider struct {
	queries    *sessions.Queries
	issuer     string
	resource   string
	hmacSecret []byte
	signingKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
}

// Config holds the configuration for creating a new Provider.
type Config struct {
	// DB is the database connection for OAuth tables.
	DB *sql.DB
	// Issuer is the OAuth issuer URL (e.g., https://example.com).
	Issuer string
	// Resource is the protected resource identifier (e.g., https://api.example.com).
	Resource string
	// HMACSecret is used for signing opaque tokens (refresh tokens).
	// Must be at least 32 bytes.
	HMACSecret []byte
	// SigningKey is the Ed25519 private key for signing JWTs.
	// If nil, a new key will be generated.
	SigningKey ed25519.PrivateKey
	// KeyID is the key identifier for the JWT header.
	// If empty, will be derived from the public key.
	KeyID string
}

// NewProvider creates a new OAuth provider with the given configuration.
func NewProvider(cfg Config) (*Provider, error) {
	if cfg.DB == nil {
		return nil, errors.New("oauth: DB is required")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("oauth: Issuer is required")
	}
	if len(cfg.HMACSecret) < 32 {
		return nil, errors.New("oauth: HMACSecret must be at least 32 bytes")
	}
	signingKey := cfg.SigningKey
	var publicKey ed25519.PublicKey
	if signingKey == nil {
		var err error
		publicKey, signingKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("oauth: failed to generate signing key: %w", err)
		}
	} else {
		publicKey = signingKey.Public().(ed25519.PublicKey)
	}

	keyID := cfg.KeyID
	if keyID == "" {
		// Derive key ID from public key hash
		hash := sha256.Sum256(publicKey)
		keyID = base64.RawURLEncoding.EncodeToString(hash[:8])
	}

	return &Provider{
		queries:    sessions.New(cfg.DB),
		issuer:     cfg.Issuer,
		resource:   cfg.Resource,
		hmacSecret: cfg.HMACSecret,
		signingKey: signingKey,
		publicKey:  publicKey,
		keyID:      keyID,
	}, nil
}

// Queries returns the underlying sessions queries for direct database access.
func (p *Provider) Queries() *sessions.Queries {
	return p.queries
}

// Issuer returns the OAuth issuer URL.
func (p *Provider) Issuer() string {
	return p.issuer
}

// Resource returns the protected resource identifier.
func (p *Provider) Resource() string {
	return p.resource
}

// PublicKey returns the Ed25519 public key for JWT verification.
func (p *Provider) PublicKey() ed25519.PublicKey {
	return p.publicKey
}

// KeyID returns the JWT key identifier.
func (p *Provider) KeyID() string {
	return p.keyID
}

// =============================================================================
// Secure ID/Secret Generation
// =============================================================================

// GenerateSecureID generates a URL-safe random string suitable for client_id
// or authorization codes. Returns a 32-byte (256-bit) random value encoded
// as base64url (43 characters).
func GenerateSecureID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth: failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateSecureSecret generates a URL-safe random string suitable for
// client_secret. Returns a 48-byte (384-bit) random value encoded as
// base64url (64 characters).
func GenerateSecureSecret() (string, error) {
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth: failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// =============================================================================
// Secret Hashing (bcrypt for client_secret)
// =============================================================================

// HashSecret hashes a client_secret using bcrypt with a cost of 12.
// Use this for storing client_secret values.
func HashSecret(secret string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), 12)
	if err != nil {
		return "", fmt.Errorf("oauth: failed to hash secret: %w", err)
	}
	return string(hash), nil
}

// VerifySecret verifies a plaintext secret against a bcrypt hash.
// Returns nil on success, error on failure.
func VerifySecret(hash, secret string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret))
	if err != nil {
		return ErrInvalidClient
	}
	return nil
}

// =============================================================================
// Token Hashing (SHA256 for fast lookups)
// =============================================================================

// HashToken hashes a token (access_token or refresh_token) using SHA256.
// This is fast and suitable for token storage where we need to look up
// tokens frequently. The token is the secret; the hash is stored.
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// =============================================================================
// JWT Signing and Verification
// =============================================================================

// SignAccessToken creates a signed JWT access token with the given claims.
func (p *Provider) SignAccessToken(claims AccessTokenClaims) (string, error) {
	// Set issuer if not already set
	if claims.Issuer == "" {
		claims.Issuer = p.issuer
	}

	// Create signer
	signerOpts := jose.SignerOptions{}
	signerOpts.WithType("at+jwt")
	signerOpts.WithHeader("kid", p.keyID)

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key:       p.signingKey,
	}, &signerOpts)
	if err != nil {
		return "", fmt.Errorf("oauth: failed to create signer: %w", err)
	}

	// Sign the token
	token, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("oauth: failed to sign token: %w", err)
	}

	return token, nil
}

// VerifyAccessToken verifies and parses a JWT access token.
// Returns the claims if valid, or an error if invalid/expired.
func (p *Provider) VerifyAccessToken(token string) (*AccessTokenClaims, error) {
	parsedToken, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	claims := &AccessTokenClaims{}
	if err := parsedToken.Claims(p.publicKey, claims); err != nil {
		return nil, fmt.Errorf("%w: signature verification failed", ErrInvalidToken)
	}

	// Validate standard claims
	expected := jwt.Expected{
		Issuer: p.issuer,
		Time:   time.Now(),
	}

	if err := claims.Validate(expected); err != nil {
		if errors.Is(err, jwt.ErrExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("%w: claims validation failed: %v", ErrInvalidToken, err)
	}

	return claims, nil
}

// =============================================================================
// Client Management
// =============================================================================

// Client represents an OAuth client with parsed fields.
type Client struct {
	ClientID                string
	ClientSecretHash        string // Empty for public clients
	ClientName              string
	RedirectURIs            []string
	IsPublic                bool
	TokenEndpointAuthMethod string // "none" for public, "client_secret_basic" or "client_secret_post" for confidential
	CreatedAt               time.Time
}

// CreateClientParams contains parameters for creating a new OAuth client.
type CreateClientParams struct {
	ClientName              string
	RedirectURIs            []string
	IsPublic                bool
	TokenEndpointAuthMethod string // Optional: defaults to "none" for public, "client_secret_basic" for confidential
}

// CreateClientResult contains the result of creating a new OAuth client.
type CreateClientResult struct {
	ClientID     string
	ClientSecret string // Empty for public clients; only returned once
}

// CreateClient creates a new OAuth client.
func (p *Provider) CreateClient(ctx context.Context, params CreateClientParams) (*CreateClientResult, error) {
	clientID, err := GenerateSecureID()
	if err != nil {
		return nil, err
	}

	var clientSecretHash sql.NullString
	var clientSecret string

	if !params.IsPublic {
		// Confidential client - generate and hash secret
		clientSecret, err = GenerateSecureSecret()
		if err != nil {
			return nil, err
		}
		hash, err := HashSecret(clientSecret)
		if err != nil {
			return nil, err
		}
		clientSecretHash = sql.NullString{String: hash, Valid: true}
	}

	// Default auth method
	authMethod := params.TokenEndpointAuthMethod
	if authMethod == "" {
		if params.IsPublic {
			authMethod = "none"
		} else {
			authMethod = "client_secret_basic"
		}
	}

	// Serialize redirect URIs as JSON array
	redirectURIsJSON := serializeRedirectURIs(params.RedirectURIs)

	isPublic := int64(0)
	if params.IsPublic {
		isPublic = 1
	}

	err = p.queries.CreateOAuthClient(ctx, sessions.CreateOAuthClientParams{
		ClientID:         clientID,
		ClientSecretHash: clientSecretHash,
		ClientName:       sql.NullString{String: params.ClientName, Valid: params.ClientName != ""},
		RedirectUris:     redirectURIsJSON,
		IsPublic:         isPublic,
		TokenEndpointAuthMethod: sql.NullString{
			String: authMethod,
			Valid:  true,
		},
		CreatedAt: time.Now().Unix(),
	})
	if err != nil {
		return nil, fmt.Errorf("oauth: failed to create client: %w", err)
	}

	return &CreateClientResult{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}, nil
}

// GetClient retrieves an OAuth client by client_id.
func (p *Provider) GetClient(ctx context.Context, clientID string) (*Client, error) {
	c, err := p.queries.GetOAuthClient(ctx, clientID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidClient
		}
		return nil, fmt.Errorf("oauth: failed to get client: %w", err)
	}

	return &Client{
		ClientID:                c.ClientID,
		ClientSecretHash:        c.ClientSecretHash.String,
		ClientName:              c.ClientName.String,
		RedirectURIs:            parseRedirectURIs(c.RedirectUris),
		IsPublic:                c.IsPublic == 1,
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod.String,
		CreatedAt:               time.Unix(c.CreatedAt, 0),
	}, nil
}

// ValidateClientRedirectURI checks if the given redirect_uri is valid for the client.
func (p *Provider) ValidateClientRedirectURI(client *Client, redirectURI string) error {
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return nil
		}
	}
	return ErrInvalidRedirectURI
}

// AuthenticateClient authenticates a client using the provided credentials.
// For public clients, only clientID is required.
// For confidential clients, both clientID and clientSecret are required.
func (p *Provider) AuthenticateClient(ctx context.Context, clientID, clientSecret string) (*Client, error) {
	client, err := p.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	if client.IsPublic {
		// Public clients don't need secret authentication
		return client, nil
	}

	// Confidential client - verify secret
	if clientSecret == "" {
		return nil, ErrClientSecretMissing
	}

	if err := VerifySecret(client.ClientSecretHash, clientSecret); err != nil {
		return nil, err
	}

	return client, nil
}

// =============================================================================
// Authorization Code Management
// =============================================================================

// AuthorizationCodeParams contains parameters for creating an authorization code.
type AuthorizationCodeParams struct {
	ClientID            string
	UserID              string
	RedirectURI         string
	Scope               string
	Resource            string
	CodeChallenge       string
	CodeChallengeMethod string // "S256" (required for public clients)
	Lifetime            time.Duration
}

// CreateAuthorizationCode creates a new authorization code.
// Returns the plaintext code (to be sent to the client).
func (p *Provider) CreateAuthorizationCode(ctx context.Context, params AuthorizationCodeParams) (string, error) {
	code, err := GenerateSecureID()
	if err != nil {
		return "", err
	}

	lifetime := params.Lifetime
	if lifetime == 0 {
		lifetime = DefaultCodeLifetime
	}

	codeHash := HashToken(code)
	expiresAt := time.Now().Add(lifetime).Unix()

	err = p.queries.CreateOAuthCode(ctx, sessions.CreateOAuthCodeParams{
		CodeHash:      codeHash,
		ClientID:      params.ClientID,
		UserID:        params.UserID,
		RedirectUri:   params.RedirectURI,
		Scope:         sql.NullString{String: params.Scope, Valid: params.Scope != ""},
		Resource:      sql.NullString{String: params.Resource, Valid: params.Resource != ""},
		CodeChallenge: params.CodeChallenge,
		CodeChallengeMethod: sql.NullString{
			String: params.CodeChallengeMethod,
			Valid:  params.CodeChallengeMethod != "",
		},
		ExpiresAt: expiresAt,
		CreatedAt: time.Now().Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("oauth: failed to create authorization code: %w", err)
	}

	return code, nil
}

// AuthorizationCode represents a retrieved authorization code.
type AuthorizationCode struct {
	ClientID            string
	UserID              string
	RedirectURI         string
	Scope               string
	Resource            string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	CreatedAt           time.Time
}

// GetAuthorizationCode retrieves and validates an authorization code.
// The code is NOT deleted - call DeleteAuthorizationCode after successful token exchange.
func (p *Provider) GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	codeHash := HashToken(code)

	c, err := p.queries.GetValidOAuthCode(ctx, codeHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidCode
		}
		return nil, fmt.Errorf("oauth: failed to get authorization code: %w", err)
	}

	return &AuthorizationCode{
		ClientID:            c.ClientID,
		UserID:              c.UserID,
		RedirectURI:         c.RedirectUri,
		Scope:               c.Scope.String,
		Resource:            c.Resource.String,
		CodeChallenge:       c.CodeChallenge,
		CodeChallengeMethod: c.CodeChallengeMethod.String,
		ExpiresAt:           time.Unix(c.ExpiresAt, 0),
		CreatedAt:           time.Unix(c.CreatedAt, 0),
	}, nil
}

// DeleteAuthorizationCode deletes an authorization code after use.
func (p *Provider) DeleteAuthorizationCode(ctx context.Context, code string) error {
	codeHash := HashToken(code)
	return p.queries.DeleteOAuthCode(ctx, codeHash)
}

// VerifyPKCE verifies the code_verifier against the stored code_challenge.
func VerifyPKCE(codeChallenge, codeChallengeMethod, codeVerifier string) error {
	if codeChallenge == "" {
		// No PKCE required (confidential client)
		return nil
	}

	if codeVerifier == "" {
		return ErrInvalidPKCE
	}

	// Only S256 is supported (per OAuth 2.1)
	if codeChallengeMethod != "S256" && codeChallengeMethod != "" {
		return fmt.Errorf("%w: unsupported code_challenge_method", ErrInvalidPKCE)
	}

	// Compute S256 challenge from verifier
	hash := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(hash[:])

	if computed != codeChallenge {
		return ErrInvalidPKCE
	}

	return nil
}

// =============================================================================
// Token Management
// =============================================================================

// TokenParams contains parameters for creating tokens.
type TokenParams struct {
	ClientID             string
	UserID               string
	Scope                string
	Resource             string
	AccessTokenLifetime  time.Duration
	RefreshTokenLifetime time.Duration
	IncludeRefreshToken  bool
}

// TokenResult contains the result of token creation.
type TokenResult struct {
	AccessToken  string
	RefreshToken string // Empty if not requested
	TokenType    string
	ExpiresIn    int64 // Seconds until access token expires
	Scope        string
}

// CreateTokens creates access and optionally refresh tokens.
func (p *Provider) CreateTokens(ctx context.Context, params TokenParams) (*TokenResult, error) {
	accessLifetime := params.AccessTokenLifetime
	if accessLifetime == 0 {
		accessLifetime = DefaultAccessTokenLifetime
	}

	now := time.Now()
	expiresAt := now.Add(accessLifetime)

	// Generate JWT ID
	jti, err := GenerateSecureID()
	if err != nil {
		return nil, err
	}

	// Build JWT claims
	claims := AccessTokenClaims{
		Claims: jwt.Claims{
			ID:        jti,
			Issuer:    p.issuer,
			Subject:   params.UserID,
			Audience:  jwt.Audience{p.resource},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(expiresAt),
		},
		Scope:    params.Scope,
		Resource: params.Resource,
		ClientID: params.ClientID,
	}

	// Sign the access token
	accessToken, err := p.SignAccessToken(claims)
	if err != nil {
		return nil, err
	}

	// Generate refresh token if requested
	var refreshToken string
	var refreshTokenHash sql.NullString
	if params.IncludeRefreshToken {
		refreshToken, err = GenerateSecureSecret()
		if err != nil {
			return nil, err
		}
		refreshTokenHash = sql.NullString{
			String: HashToken(refreshToken),
			Valid:  true,
		}
	}

	// Store token metadata
	err = p.queries.CreateOAuthToken(ctx, sessions.CreateOAuthTokenParams{
		AccessTokenHash:  HashToken(accessToken),
		RefreshTokenHash: refreshTokenHash,
		ClientID:         params.ClientID,
		UserID:           params.UserID,
		Scope:            sql.NullString{String: params.Scope, Valid: params.Scope != ""},
		Resource:         sql.NullString{String: params.Resource, Valid: params.Resource != ""},
		ExpiresAt:        expiresAt.Unix(),
		CreatedAt:        now.Unix(),
	})
	if err != nil {
		return nil, fmt.Errorf("oauth: failed to store token: %w", err)
	}

	return &TokenResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    TokenType,
		ExpiresIn:    int64(accessLifetime.Seconds()),
		Scope:        params.Scope,
	}, nil
}

// RevokeAccessToken revokes an access token.
func (p *Provider) RevokeAccessToken(ctx context.Context, accessToken string) error {
	return p.queries.DeleteOAuthToken(ctx, HashToken(accessToken))
}

// RefreshTokens exchanges a refresh token for new tokens.
func (p *Provider) RefreshTokens(ctx context.Context, refreshToken string, params TokenParams) (*TokenResult, error) {
	refreshTokenHash := HashToken(refreshToken)

	// Look up the refresh token
	stored, err := p.queries.GetOAuthTokenByRefresh(ctx, sql.NullString{
		String: refreshTokenHash,
		Valid:  true,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("oauth: failed to look up refresh token: %w", err)
	}

	// Verify client matches
	if stored.ClientID != params.ClientID {
		return nil, ErrInvalidClient
	}

	// Delete the old tokens (refresh token rotation)
	if err := p.queries.DeleteOAuthToken(ctx, stored.AccessTokenHash); err != nil {
		return nil, fmt.Errorf("oauth: failed to delete old token: %w", err)
	}

	// Use stored values if not overridden
	if params.UserID == "" {
		params.UserID = stored.UserID
	}
	if params.Scope == "" {
		params.Scope = stored.Scope.String
	}
	if params.Resource == "" {
		params.Resource = stored.Resource.String
	}

	// Create new tokens
	return p.CreateTokens(ctx, params)
}

// =============================================================================
// Cleanup
// =============================================================================

// CleanupExpired removes expired codes and tokens.
func (p *Provider) CleanupExpired(ctx context.Context) error {
	now := time.Now().Unix()

	if err := p.queries.DeleteExpiredOAuthCodes(ctx, now); err != nil {
		return fmt.Errorf("oauth: failed to cleanup expired codes: %w", err)
	}

	if err := p.queries.DeleteExpiredOAuthTokens(ctx, now); err != nil {
		return fmt.Errorf("oauth: failed to cleanup expired tokens: %w", err)
	}

	return nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// serializeRedirectURIs converts a slice of URIs to a JSON-like string.
// For simplicity, we use space-separated values since redirect URIs cannot contain spaces.
func serializeRedirectURIs(uris []string) string {
	return strings.Join(uris, " ")
}

// parseRedirectURIs parses a space-separated string of URIs.
func parseRedirectURIs(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, " ")
}

// ComputePKCEChallenge computes the S256 PKCE challenge from a verifier.
// This is useful for clients generating PKCE parameters.
func ComputePKCEChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// GeneratePKCE generates a PKCE code_verifier and code_challenge.
// Returns (verifier, challenge, error).
func GeneratePKCE() (string, string, error) {
	verifier, err := GenerateSecureSecret()
	if err != nil {
		return "", "", err
	}
	challenge := ComputePKCEChallenge(verifier)
	return verifier, challenge, nil
}

// =============================================================================
// OAuth Metadata (RFC 8414 and RFC 9728)
// =============================================================================

// ProtectedResourceMetadata represents the OAuth Protected Resource Metadata
// per RFC 9728 section 2.
type ProtectedResourceMetadata struct {
	// Resource is the protected resource's identifier (REQUIRED).
	Resource string `json:"resource"`

	// AuthorizationServers lists authorization server issuer identifiers
	// that can be used with this resource (REQUIRED).
	AuthorizationServers []string `json:"authorization_servers"`

	// ScopesSupported lists OAuth scopes usable with this resource (OPTIONAL).
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// ResourceDocumentation is a URL to human-readable documentation (OPTIONAL).
	ResourceDocumentation string `json:"resource_documentation,omitempty"`
}

// AuthServerMetadata represents the OAuth Authorization Server Metadata
// per RFC 8414 section 2.
type AuthServerMetadata struct {
	// Issuer is the authorization server's issuer identifier (REQUIRED).
	Issuer string `json:"issuer"`

	// AuthorizationEndpoint is the URL for authorization requests (REQUIRED).
	AuthorizationEndpoint string `json:"authorization_endpoint"`

	// TokenEndpoint is the URL for token requests (REQUIRED).
	TokenEndpoint string `json:"token_endpoint"`

	// RegistrationEndpoint is the URL for dynamic client registration (OPTIONAL).
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`

	// JWKSUri is the URL for the JSON Web Key Set (OPTIONAL).
	JWKSUri string `json:"jwks_uri,omitempty"`

	// ScopesSupported lists supported OAuth scopes (RECOMMENDED).
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// ResponseTypesSupported lists supported response types (REQUIRED).
	ResponseTypesSupported []string `json:"response_types_supported"`

	// GrantTypesSupported lists supported grant types (OPTIONAL, defaults to ["authorization_code"]).
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`

	// CodeChallengeMethodsSupported lists supported PKCE methods (OPTIONAL).
	// Must include "S256" for ChatGPT/Claude compatibility.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`

	// TokenEndpointAuthMethodsSupported lists supported client authentication methods (OPTIONAL).
	// CRITICAL: Must include "none" for public clients (Claude Code CLI).
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

// JWKS represents a JSON Web Key Set per RFC 7517.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key per RFC 7517.
type JWK struct {
	// Kty is the key type (REQUIRED). "OKP" for Ed25519 keys.
	Kty string `json:"kty"`

	// Use indicates the intended use: "sig" for signing, "enc" for encryption.
	Use string `json:"use,omitempty"`

	// Kid is the key ID (OPTIONAL but RECOMMENDED).
	Kid string `json:"kid,omitempty"`

	// Alg is the algorithm intended for use with the key (OPTIONAL).
	Alg string `json:"alg,omitempty"`

	// Crv is the curve for OKP keys (REQUIRED for OKP keys). "Ed25519" for EdDSA.
	Crv string `json:"crv,omitempty"`

	// X is the public key for OKP keys (REQUIRED for OKP public keys).
	X string `json:"x,omitempty"`
}

// HandleProtectedResourceMetadata handles GET /.well-known/oauth-protected-resource
// per RFC 9728. This endpoint tells clients about the protected resource and
// which authorization servers can issue tokens for it.
func (p *Provider) HandleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metadata := ProtectedResourceMetadata{
		Resource:             p.resource,
		AuthorizationServers: []string{p.issuer},
		ScopesSupported:      []string{"notes:read", "notes:write"},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=3600")
	json.NewEncoder(w).Encode(metadata)
}

// HandleAuthServerMetadata handles GET /.well-known/oauth-authorization-server
// per RFC 8414. This endpoint provides OAuth server configuration to clients.
func (p *Provider) HandleAuthServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metadata := AuthServerMetadata{
		Issuer:                            p.issuer,
		AuthorizationEndpoint:             p.issuer + "/oauth/authorize",
		TokenEndpoint:                     p.issuer + "/oauth/token",
		RegistrationEndpoint:              p.issuer + "/oauth/register",
		JWKSUri:                           p.issuer + "/.well-known/jwks.json",
		ScopesSupported:                   []string{"notes:read", "notes:write"},
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic", "none"},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=3600")
	json.NewEncoder(w).Encode(metadata)
}

// HandleJWKS handles GET /.well-known/jwks.json
// per RFC 7517. This endpoint publishes the public key(s) for token verification.
func (p *Provider) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Ed25519 key as OKP type per RFC 8037
	jwk := JWK{
		Kty: "OKP",
		Use: "sig",
		Kid: p.keyID,
		Alg: "EdDSA",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(p.publicKey),
	}

	jwks := JWKS{
		Keys: []JWK{jwk},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=3600")
	json.NewEncoder(w).Encode(jwks)
}

// RegisterMetadataRoutes registers all OAuth metadata routes on the given mux.
func (p *Provider) RegisterMetadataRoutes(mux *http.ServeMux) {
	// Root paths (standard)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", p.HandleProtectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", p.HandleAuthServerMetadata)
	mux.HandleFunc("GET /.well-known/jwks.json", p.HandleJWKS)

	// Sub-path variants per RFC 9728 (Claude tries these first for /mcp endpoint)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", p.HandleProtectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server/mcp", p.HandleAuthServerMetadata)

	// OpenID Connect Discovery fallbacks (some clients try these)
	mux.HandleFunc("GET /.well-known/openid-configuration", p.HandleAuthServerMetadata)
	mux.HandleFunc("GET /.well-known/openid-configuration/mcp", p.HandleAuthServerMetadata)
	mux.HandleFunc("GET /mcp/.well-known/openid-configuration", p.HandleAuthServerMetadata)
}
