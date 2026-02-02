// Package auth provides authentication middleware for the agent-notes server.
package auth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
)

// OAuth middleware context keys (separate from session-based auth).
type oauthContextKey string

const (
	oauthUserIDKey   oauthContextKey = "oauth_user_id"
	oauthScopeKey    oauthContextKey = "oauth_scope"
	oauthClientIDKey oauthContextKey = "oauth_client_id"
)

// Token verification errors.
var (
	ErrNoToken           = errors.New("auth: no access token provided")
	ErrMalformedToken    = errors.New("auth: malformed access token")
	ErrInvalidSignature  = errors.New("auth: invalid token signature")
	ErrTokenExpired      = errors.New("auth: token expired")
	ErrTokenNotYetValid  = errors.New("auth: token not yet valid")
	ErrInvalidIssuer     = errors.New("auth: invalid token issuer")
	ErrInvalidAudience   = errors.New("auth: invalid token audience")
	ErrInsufficientScope = errors.New("auth: insufficient scope")
)

// TokenClaims represents the verified claims from an OAuth access token.
type TokenClaims struct {
	Subject   string    // sub (user_id)
	Audience  string    // aud (resource)
	Issuer    string    // iss
	Scope     string    // scope
	ClientID  string    // client_id
	ExpiresAt time.Time // exp
	IssuedAt  time.Time // iat
	TokenID   string    // jti
}

// TokenVerifier verifies OAuth access tokens (JWTs).
type TokenVerifier struct {
	issuer    string
	resource  string
	publicKey ed25519.PublicKey
}

// NewTokenVerifier creates a new TokenVerifier.
//
// Parameters:
//   - issuer: Expected issuer (iss claim) - must match the OAuth provider's issuer
//   - resource: Expected audience (aud claim) - the protected resource identifier
//   - publicKey: Ed25519 public key for JWT signature verification
func NewTokenVerifier(issuer, resource string, publicKey ed25519.PublicKey) *TokenVerifier {
	return &TokenVerifier{
		issuer:    issuer,
		resource:  resource,
		publicKey: publicKey,
	}
}

// VerifyToken verifies an OAuth access token and returns the claims.
//
// Verification steps (per OAuth 2.1 / MCP spec):
// 1. Parse and verify JWT signature using Ed25519
// 2. Check iss matches expected issuer
// 3. Check aud matches expected resource
// 4. Check exp > now (not expired)
// 5. Check iat <= now (not issued in future)
// 6. Return claims on success
func (v *TokenVerifier) VerifyToken(ctx context.Context, token string) (*TokenClaims, error) {
	// 1. Parse JWT and verify signature
	parsedToken, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedToken, err)
	}

	// Extract raw claims for verification
	var rawClaims struct {
		jwt.Claims
		Scope    string `json:"scope,omitempty"`
		Resource string `json:"resource,omitempty"`
		ClientID string `json:"client_id,omitempty"`
	}

	if err := parsedToken.Claims(v.publicKey, &rawClaims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	now := time.Now()

	// 2. Check issuer
	if rawClaims.Issuer != v.issuer {
		return nil, fmt.Errorf("%w: expected %q, got %q", ErrInvalidIssuer, v.issuer, rawClaims.Issuer)
	}

	// 3. Check audience contains expected resource
	audienceValid := false
	for _, aud := range rawClaims.Audience {
		if aud == v.resource {
			audienceValid = true
			break
		}
	}
	if !audienceValid {
		return nil, fmt.Errorf("%w: expected %q in audience", ErrInvalidAudience, v.resource)
	}

	// 4. Check expiration (exp > now)
	if rawClaims.Expiry == nil {
		return nil, fmt.Errorf("%w: missing exp claim", ErrMalformedToken)
	}
	expiresAt := rawClaims.Expiry.Time()
	if now.After(expiresAt) {
		return nil, fmt.Errorf("%w: expired at %v", ErrTokenExpired, expiresAt)
	}

	// 5. Check issued-at (iat <= now)
	var issuedAt time.Time
	if rawClaims.IssuedAt != nil {
		issuedAt = rawClaims.IssuedAt.Time()
		if issuedAt.After(now.Add(time.Minute)) { // Allow 1 minute clock skew
			return nil, fmt.Errorf("%w: issued at %v", ErrTokenNotYetValid, issuedAt)
		}
	}

	// 6. Return verified claims
	audience := ""
	if len(rawClaims.Audience) > 0 {
		audience = rawClaims.Audience[0]
	}

	return &TokenClaims{
		Subject:   rawClaims.Subject,
		Audience:  audience,
		Issuer:    rawClaims.Issuer,
		Scope:     rawClaims.Scope,
		ClientID:  rawClaims.ClientID,
		ExpiresAt: expiresAt,
		IssuedAt:  issuedAt,
		TokenID:   rawClaims.ID,
	}, nil
}

// HasScope checks if the given scope is present in the claims.
// Scopes are space-separated per OAuth 2.1 spec.
func (c *TokenClaims) HasScope(scope string) bool {
	scopes := strings.Fields(c.Scope)
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// =============================================================================
// HTTP Middleware
// =============================================================================

// OAuthMiddleware returns HTTP middleware that extracts and validates Bearer tokens.
//
// Behavior:
// 1. Extract Authorization: Bearer <token> header
// 2. If no token and required=true: return 401 with WWW-Authenticate header
// 3. If token present: verify it using TokenVerifier
// 4. On success: add claims to request context (user_id, scope, client_id)
// 5. On failure: return 401 with WWW-Authenticate header
func OAuthMiddleware(verifier *TokenVerifier, resourceMetadataURL string, required bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := extractBearerToken(r)
			if err != nil {
				if required {
					writeWWWAuthenticate(w, resourceMetadataURL, "missing_token", err.Error())
					return
				}
				// Optional auth - continue without token
				next.ServeHTTP(w, r)
				return
			}

			claims, err := verifier.VerifyToken(r.Context(), token)
			if err != nil {
				errorType := "invalid_token"
				if errors.Is(err, ErrTokenExpired) {
					errorType = "invalid_token"
				} else if errors.Is(err, ErrInsufficientScope) {
					errorType = "insufficient_scope"
				}
				writeWWWAuthenticate(w, resourceMetadataURL, errorType, err.Error())
				return
			}

			// Add claims to context
			ctx := context.WithValue(r.Context(), oauthUserIDKey, claims.Subject)
			ctx = context.WithValue(ctx, oauthScopeKey, claims.Scope)
			ctx = context.WithValue(ctx, oauthClientIDKey, claims.ClientID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractBearerToken extracts the Bearer token from the Authorization header.
func extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoToken
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", fmt.Errorf("%w: expected Bearer scheme", ErrMalformedToken)
	}

	token := strings.TrimPrefix(authHeader, bearerPrefix)
	if token == "" {
		return "", ErrNoToken
	}

	return token, nil
}

// writeWWWAuthenticate writes a 401 response with WWW-Authenticate header.
// Format per RFC 6750 and MCP spec:
// Bearer resource_metadata="<url>", error="<error>", error_description="<desc>"
func writeWWWAuthenticate(w http.ResponseWriter, resourceMetadataURL, errorType, errorDesc string) {
	challenge := fmt.Sprintf(`Bearer resource_metadata="%s", error="%s", error_description="%s"`,
		resourceMetadataURL, errorType, errorDesc)
	w.Header().Set("WWW-Authenticate", challenge)
	w.WriteHeader(http.StatusUnauthorized)
}

// =============================================================================
// Context Helpers
// =============================================================================

// UserIDFromContext retrieves the user ID (sub claim) from the request context.
// Returns the user ID and true if present, or empty string and false if not authenticated.
func UserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(oauthUserIDKey).(string)
	return userID, ok && userID != ""
}

// ScopeFromContext retrieves the scope from the request context.
// Returns the space-separated scope string and true if present.
func ScopeFromContext(ctx context.Context) (string, bool) {
	scope, ok := ctx.Value(oauthScopeKey).(string)
	return scope, ok
}

// ClientIDFromContext retrieves the client ID from the request context.
// Returns the client ID and true if present.
func ClientIDFromContext(ctx context.Context) (string, bool) {
	clientID, ok := ctx.Value(oauthClientIDKey).(string)
	return clientID, ok && clientID != ""
}

// IsOAuthAuthenticated checks if the context has OAuth authentication.
func IsOAuthAuthenticated(ctx context.Context) bool {
	_, ok := UserIDFromContext(ctx)
	return ok
}

// =============================================================================
// Scope Checking Middleware
// =============================================================================

// RequireScope returns middleware that requires a specific scope.
// Must be used after OAuthMiddleware.
func RequireScope(scope, resourceMetadataURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scopeStr, ok := ScopeFromContext(r.Context())
			if !ok {
				writeWWWAuthenticate(w, resourceMetadataURL, "insufficient_scope",
					fmt.Sprintf("scope %q required", scope))
				return
			}

			scopes := strings.Fields(scopeStr)
			hasScope := false
			for _, s := range scopes {
				if s == scope {
					hasScope = true
					break
				}
			}

			if !hasScope {
				writeWWWAuthenticate(w, resourceMetadataURL, "insufficient_scope",
					fmt.Sprintf("scope %q required", scope))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
