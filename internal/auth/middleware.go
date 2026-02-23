package auth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/urlutil"
)

// =============================================================================
// Context Keys
// =============================================================================

// contextKey is a private type for auth context keys to prevent collisions.
type contextKey string

const (
	userIDKey contextKey = "userID"
	userDBKey contextKey = "userDB"
	isPaidKey contextKey = "isPaid"
)

// oauthContextKey is a private type for OAuth-specific context keys.
type oauthContextKey string

const (
	oauthUserIDKey   oauthContextKey = "oauth_user_id"
	oauthScopeKey    oauthContextKey = "oauth_scope"
	oauthClientIDKey oauthContextKey = "oauth_client_id"
)

// =============================================================================
// Token Verification Interfaces & Types
// =============================================================================

// OAuthTokenVerifier is an interface for verifying OAuth JWT access tokens.
// This is implemented by oauth.Provider.
type OAuthTokenVerifier interface {
	VerifyAccessToken(token string) (claims *OAuthTokenClaims, err error)
}

// OAuthTokenClaims holds the claims extracted from an OAuth JWT.
// This matches the claims structure used by oauth.Provider.
type OAuthTokenClaims struct {
	Subject  string // user_id (sub claim)
	ClientID string // client_id
	Scope    string // scope
}

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
// TokenVerifier - Ed25519 JWT Verification
// =============================================================================

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

// =============================================================================
// Middleware - Unified Auth Middleware
// =============================================================================

// Middleware provides authentication middleware for HTTP handlers.
type Middleware struct {
	sessionService      *SessionService
	keyManager          *crypto.KeyManager
	oauthVerifier       OAuthTokenVerifier
	resourceMetadataURL string
	clock               Clock
}

// NewMiddleware creates a new auth middleware.
func NewMiddleware(sessionService *SessionService, keyManager *crypto.KeyManager) *Middleware {
	return &Middleware{
		sessionService: sessionService,
		keyManager:     keyManager,
		clock:          realClock{},
	}
}

// SetClock replaces the clock used by the middleware. Intended for testing.
func (m *Middleware) SetClock(c Clock) {
	m.clock = c
}

// WithOAuthVerifier adds an OAuth token verifier to the middleware.
// This enables Bearer token authentication with OAuth JWTs for the MCP endpoint.
func (m *Middleware) WithOAuthVerifier(verifier OAuthTokenVerifier, resourceMetadataURL string) *Middleware {
	m.oauthVerifier = verifier
	m.resourceMetadataURL = resourceMetadataURL
	return m
}

// RequireAuth is middleware that requires valid authentication.
// Supports session cookies, API Keys, and OAuth JWT tokens.
// Returns 401 Unauthorized if no valid authentication is present.
//
// T2a fix: When a Bearer token is presented that is not an API key and
// oauthVerifier is nil, we return 401 immediately rather than silently
// falling through to session auth. A caller that explicitly presents a
// Bearer token expects token-based auth; falling through masks config errors.
func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var userID string
		var userDB *db.UserDB
		var err error

		// Check for Bearer token first (API Key or OAuth JWT)
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")

			// Check if it's an API Key
			if IsAPIKeyToken(token) {
				userID, userDB, err = m.authenticateWithAPIKey(r.Context(), token)
				if err != nil {
					m.writeUnauthorized(w, r, "invalid_token", "Invalid API key")
					return
				}
			} else if m.oauthVerifier != nil {
				// Try OAuth JWT verification
				userID, userDB, err = m.authenticateWithOAuthJWT(r.Context(), token)
				if err != nil {
					log.Printf("[AUTH] OAuth JWT verification failed: %v", err)
					m.writeUnauthorized(w, r, "invalid_token", err.Error())
					return
				}
			} else {
				// T2a: Bearer token presented but no OAuth verifier configured.
				// Hard 401 - never fall through to session auth when a token
				// is explicitly presented.
				log.Printf("[AUTH] Bearer token presented but OAuth verifier not configured")
				m.writeUnauthorized(w, r, "invalid_token", "Bearer token authentication not available")
				return
			}
		}

		// If not authenticated via token, try session cookie
		if userID == "" {
			sessionID, err := GetFromRequest(r)
			if err != nil {
				m.writeUnauthorized(w, r, "missing_token", "No valid authentication provided")
				return
			}

			// Validate session
			userID, err = m.sessionService.Validate(r.Context(), sessionID)
			if err != nil {
				m.writeUnauthorized(w, r, "invalid_token", "Invalid or expired session")
				return
			}

			// Get or create user DEK and open database
			dek, err := m.keyManager.GetOrCreateUserDEK(userID)
			if err != nil {
				log.Printf("[AUTH] GetOrCreateUserDEK failed for user %s: %v", userID, err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			// Open user database with DEK
			userDB, err = db.OpenUserDBWithDEK(userID, dek)
			if err != nil {
				log.Printf("[AUTH] OpenUserDBWithDEK failed for user %s: %v", userID, err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
		}

		// Cache isPaid from the account's subscription status to avoid an
		// extra DB query per request in rate-limiting middleware.
		isPaid := false
		if userDB != nil {
			account, err := userDB.Queries().GetAccount(r.Context(), userID)
			if err == nil && account.SubscriptionStatus.Valid && account.SubscriptionStatus.String == "active" {
				isPaid = true
			}
		}

		// Add user info to context
		ctx := context.WithValue(r.Context(), userIDKey, userID)
		ctx = context.WithValue(ctx, userDBKey, userDB)
		ctx = context.WithValue(ctx, isPaidKey, isPaid)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireBearerAuth is middleware that requires valid Bearer token authentication.
// Only accepts Authorization: Bearer (API Key or OAuth JWT). Cookie/session auth
// is NOT accepted. Use this for MCP endpoints (T2c).
func (m *Middleware) RequireBearerAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			m.writeUnauthorized(w, r, "missing_token", "Bearer token required")
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		var userID string
		var userDB *db.UserDB
		var err error

		if IsAPIKeyToken(token) {
			userID, userDB, err = m.authenticateWithAPIKey(r.Context(), token)
			if err != nil {
				m.writeUnauthorized(w, r, "invalid_token", "Invalid API key")
				return
			}
		} else if m.oauthVerifier != nil {
			userID, userDB, err = m.authenticateWithOAuthJWT(r.Context(), token)
			if err != nil {
				log.Printf("[AUTH] OAuth JWT verification failed (bearer-only): %v", err)
				m.writeUnauthorized(w, r, "invalid_token", err.Error())
				return
			}
		} else {
			log.Printf("[AUTH] Bearer token presented but OAuth verifier not configured (bearer-only)")
			m.writeUnauthorized(w, r, "invalid_token", "Bearer token authentication not available")
			return
		}

		// Cache isPaid from the account's subscription status.
		isPaid := false
		if userDB != nil {
			account, err := userDB.Queries().GetAccount(r.Context(), userID)
			if err == nil && account.SubscriptionStatus.Valid && account.SubscriptionStatus.String == "active" {
				isPaid = true
			}
		}

		// Add user info to context
		ctx := context.WithValue(r.Context(), userIDKey, userID)
		ctx = context.WithValue(ctx, userDBKey, userDB)
		ctx = context.WithValue(ctx, isPaidKey, isPaid)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authenticateWithOAuthJWT validates an OAuth JWT token and returns the user ID and database.
func (m *Middleware) authenticateWithOAuthJWT(ctx context.Context, token string) (string, *db.UserDB, error) {
	claims, err := m.oauthVerifier.VerifyAccessToken(token)
	if err != nil {
		return "", nil, err
	}

	userID := claims.Subject
	if userID == "" {
		return "", nil, fmt.Errorf("token has no subject claim")
	}

	// Get or create user DEK and open database
	dek, err := m.keyManager.GetOrCreateUserDEK(userID)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get user DEK: %w", err)
	}

	// Open user database with DEK
	userDB, err := db.OpenUserDBWithDEK(userID, dek)
	if err != nil {
		return "", nil, fmt.Errorf("failed to open user database: %w", err)
	}

	return userID, userDB, nil
}

// writeUnauthorized writes a 401 response with WWW-Authenticate header per RFC 6750.
func (m *Middleware) writeUnauthorized(w http.ResponseWriter, r *http.Request, errorType, errorDesc string) {
	if m.resourceMetadataURL != "" {
		resourceMetadataURL := m.resourceMetadataURL
		if strings.HasPrefix(resourceMetadataURL, "/") {
			origin := urlutil.OriginFromRequest(r, "")
			resourceMetadataURL = origin + resourceMetadataURL
		}
		challenge := fmt.Sprintf(`Bearer resource_metadata="%s", error="%s", error_description="%s"`,
			resourceMetadataURL, errorType, errorDesc)
		w.Header().Set("WWW-Authenticate", challenge)
	} else {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s", error_description="%s"`, errorType, errorDesc))
	}
	http.Error(w, "Unauthorized: "+errorDesc, http.StatusUnauthorized)
}

// RequireAuthWithRedirect is middleware for web pages that redirects to login
// instead of returning 401 when authentication fails.
// Use this for HTML pages, use RequireAuth for API endpoints.
func (m *Middleware) RequireAuthWithRedirect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var userID string
		var userDB *db.UserDB

		// Try session cookie authentication
		sessionID, err := GetFromRequest(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// Validate session
		userID, err = m.sessionService.Validate(r.Context(), sessionID)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// Get or create user DEK and open database
		dek, err := m.keyManager.GetOrCreateUserDEK(userID)
		if err != nil {
			log.Printf("[AUTH] GetOrCreateUserDEK failed for user %s: %v", userID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Open user database with DEK
		userDB, err = db.OpenUserDBWithDEK(userID, dek)
		if err != nil {
			log.Printf("[AUTH] OpenUserDBWithDEK failed for user %s: %v", userID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Cache isPaid from the account's subscription status.
		isPaid := false
		if userDB != nil {
			account, err := userDB.Queries().GetAccount(r.Context(), userID)
			if err == nil && account.SubscriptionStatus.Valid && account.SubscriptionStatus.String == "active" {
				isPaid = true
			}
		}

		// Add user info to context
		ctx := context.WithValue(r.Context(), userIDKey, userID)
		ctx = context.WithValue(ctx, userDBKey, userDB)
		ctx = context.WithValue(ctx, isPaidKey, isPaid)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authenticateWithAPIKey validates an API Key and returns the user ID and their database.
func (m *Middleware) authenticateWithAPIKey(ctx context.Context, token string) (string, *db.UserDB, error) {
	// Parse the API Key to extract user ID and token part
	userID, tokenPart, ok := ParseAPIKeyToken(token)
	if !ok {
		return "", nil, ErrAPIKeyNotFound
	}

	// Get or create user DEK and open database
	dek, err := m.keyManager.GetOrCreateUserDEK(userID)
	if err != nil {
		return "", nil, err
	}

	// Open user database with DEK
	userDB, err := db.OpenUserDBWithDEK(userID, dek)
	if err != nil {
		return "", nil, err
	}

	// Validate the API Key against the user's database
	_, err = ValidateAPIKeyWithDB(ctx, userDB, tokenPart, m.clock.Now())
	if err != nil {
		return "", nil, err
	}

	return userID, userDB, nil
}

// OptionalAuth is middleware that adds user info to context if present.
// Does not require authentication - continues with or without a session.
func (m *Middleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to get session ID from cookie
		sessionID, err := GetFromRequest(r)
		if err != nil {
			// No session, continue without user context
			next.ServeHTTP(w, r)
			return
		}

		// Try to validate session
		userID, err := m.sessionService.Validate(r.Context(), sessionID)
		if err != nil {
			// Invalid session, continue without user context
			next.ServeHTTP(w, r)
			return
		}

		// Try to get user DEK and open database
		dek, err := m.keyManager.GetOrCreateUserDEK(userID)
		if err != nil {
			// Error getting DEK, continue without user context
			next.ServeHTTP(w, r)
			return
		}

		userDB, err := db.OpenUserDBWithDEK(userID, dek)
		if err != nil {
			// Error opening DB, continue without user context
			next.ServeHTTP(w, r)
			return
		}

		// Cache isPaid from the account's subscription status.
		isPaid := false
		account, acctErr := userDB.Queries().GetAccount(r.Context(), userID)
		if acctErr == nil && account.SubscriptionStatus.Valid && account.SubscriptionStatus.String == "active" {
			isPaid = true
		}

		// Add user info to context
		ctx := context.WithValue(r.Context(), userIDKey, userID)
		ctx = context.WithValue(ctx, userDBKey, userDB)
		ctx = context.WithValue(ctx, isPaidKey, isPaid)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// =============================================================================
// Standalone OAuth Middleware (for use without Middleware struct)
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
// Context Helpers (unified)
// =============================================================================

// GetUserID retrieves the user ID from the request context.
// Returns empty string if no user is authenticated.
func GetUserID(ctx context.Context) string {
	userID, _ := ctx.Value(userIDKey).(string)
	return userID
}

// GetUserDB retrieves the user's database from the request context.
// Returns nil if no user is authenticated.
func GetUserDB(ctx context.Context) *db.UserDB {
	userDB, _ := ctx.Value(userDBKey).(*db.UserDB)
	return userDB
}

// GetIsPaid returns whether the authenticated user has an active paid subscription.
// Returns false if not authenticated or if the subscription lookup was not cached.
func GetIsPaid(ctx context.Context) bool {
	paid, _ := ctx.Value(isPaidKey).(bool)
	return paid
}

// IsAuthenticated checks if the context has an authenticated user.
func IsAuthenticated(ctx context.Context) bool {
	return GetUserID(ctx) != ""
}

// UserIDFromContext retrieves the user ID (sub claim) from the OAuth context.
// Returns the user ID and true if present, or empty string and false if not authenticated.
func UserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(oauthUserIDKey).(string)
	return userID, ok && userID != ""
}

// ScopeFromContext retrieves the scope from the OAuth context.
// Returns the space-separated scope string and true if present.
func ScopeFromContext(ctx context.Context) (string, bool) {
	scope, ok := ctx.Value(oauthScopeKey).(string)
	return scope, ok
}

// ClientIDFromContext retrieves the client ID from the OAuth context.
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
