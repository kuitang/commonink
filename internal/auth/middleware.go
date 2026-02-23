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
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/obs"
	"github.com/kuitang/agent-notes/internal/urlutil"
)

// =============================================================================
// Context Keys
// =============================================================================

// Context keys for session-based auth data.
type contextKey string

const (
	userIDKey contextKey = "userID"
	userDBKey contextKey = "userDB"
	isPaidKey contextKey = "isPaid"
)

// Context keys for OAuth token-based auth data (separate from session-based auth).
type oauthContextKey string

const (
	oauthUserIDKey   oauthContextKey = "oauth_user_id"
	oauthScopeKey    oauthContextKey = "oauth_scope"
	oauthClientIDKey oauthContextKey = "oauth_client_id"
)

// =============================================================================
// Token Verification Errors
// =============================================================================

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

// =============================================================================
// OAuth Token Verifier (standalone JWT verification)
// =============================================================================

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
// OAuthTokenVerifier Interface (used by Middleware struct for integrated auth)
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

// =============================================================================
// Session/API Key Middleware (Middleware struct)
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
					obs.From(r.Context()).With("pkg", "auth").Debug("oauth_jwt_verify_failed", "error", err.Error())
					m.writeUnauthorized(w, r, "invalid_token", err.Error())
					return
				}
			} else {
				// Bearer token presented but not an API key and no OAuth verifier configured
				m.writeUnauthorized(w, r, "invalid_token", "Unrecognized bearer token")
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
				obs.From(r.Context()).With("pkg", "auth").Debug("dek_creation_failed", "user_id", userID, "error", err.Error())
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			// Open user database with DEK
			userDB, err = db.OpenUserDBWithDEK(userID, dek)
			if err != nil {
				obs.From(r.Context()).With("pkg", "auth").Debug("user_db_open_failed", "user_id", userID, "error", err.Error())
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
		}

		// Add user info to context (including cached paid status to avoid per-request DB query)
		ctx := context.WithValue(r.Context(), userIDKey, userID)
		ctx = context.WithValue(ctx, userDBKey, userDB)
		ctx = context.WithValue(ctx, isPaidKey, isPaidFromDB(ctx, userID, userDB))

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

// RequireBearerAuth is middleware that requires valid Bearer token authentication only.
// Unlike RequireAuth, this does NOT accept session cookies.
// Use this for MCP endpoints where only API keys and OAuth JWTs should be accepted.
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
				obs.From(r.Context()).With("pkg", "auth").Debug("oauth_jwt_verify_failed", "error", err.Error())
				m.writeUnauthorized(w, r, "invalid_token", err.Error())
				return
			}
		} else {
			m.writeUnauthorized(w, r, "invalid_token", "Unrecognized bearer token")
			return
		}

		ctx := context.WithValue(r.Context(), userIDKey, userID)
		ctx = context.WithValue(ctx, userDBKey, userDB)
		ctx = context.WithValue(ctx, isPaidKey, isPaidFromDB(ctx, userID, userDB))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
			obs.From(r.Context()).With("pkg", "auth").Debug("dek_creation_failed", "user_id", userID, "error", err.Error())
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Open user database with DEK
		userDB, err = db.OpenUserDBWithDEK(userID, dek)
		if err != nil {
			obs.From(r.Context()).With("pkg", "auth").Debug("user_db_open_failed", "user_id", userID, "error", err.Error())
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Add user info to context (including cached paid status to avoid per-request DB query)
		ctx := context.WithValue(r.Context(), userIDKey, userID)
		ctx = context.WithValue(ctx, userDBKey, userDB)
		ctx = context.WithValue(ctx, isPaidKey, isPaidFromDB(ctx, userID, userDB))

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

		// Add user info to context (including cached paid status to avoid per-request DB query)
		ctx := context.WithValue(r.Context(), userIDKey, userID)
		ctx = context.WithValue(ctx, userDBKey, userDB)
		ctx = context.WithValue(ctx, isPaidKey, isPaidFromDB(ctx, userID, userDB))

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// isPaidFromDB queries the user's subscription status from their database.
// Returns true only if the account has an active subscription.
func isPaidFromDB(ctx context.Context, userID string, userDB *db.UserDB) bool {
	if userDB == nil || userID == "" {
		return false
	}
	account, err := userDB.Queries().GetAccount(ctx, userID)
	if err != nil {
		return false
	}
	return account.SubscriptionStatus.Valid && account.SubscriptionStatus.String == "active"
}

// =============================================================================
// Standalone OAuth HTTP Middleware (uses TokenVerifier directly)
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

// GetIsPaid retrieves the cached paid status from the request context.
// Returns false if no user is authenticated or if status was not cached.
func GetIsPaid(ctx context.Context) bool {
	paid, _ := ctx.Value(isPaidKey).(bool)
	return paid
}

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

// IsAuthenticated checks if the context has an authenticated user.
func IsAuthenticated(ctx context.Context) bool {
	return GetUserID(ctx) != ""
}

// UserIDFromContext retrieves the OAuth user ID (sub claim) from the request context.
// Returns the user ID and true if present, or empty string and false if not authenticated.
func UserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(oauthUserIDKey).(string)
	return userID, ok && userID != ""
}

// ScopeFromContext retrieves the OAuth scope from the request context.
// Returns the space-separated scope string and true if present.
func ScopeFromContext(ctx context.Context) (string, bool) {
	scope, ok := ctx.Value(oauthScopeKey).(string)
	return scope, ok
}

// ClientIDFromContext retrieves the OAuth client ID from the request context.
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
