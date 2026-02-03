package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
)

// Context keys for auth data
type contextKey string

const (
	userIDKey contextKey = "userID"
	userDBKey contextKey = "userDB"
)

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

// Middleware provides authentication middleware for HTTP handlers.
type Middleware struct {
	sessionService      *SessionService
	keyManager          *crypto.KeyManager
	oauthVerifier       OAuthTokenVerifier
	resourceMetadataURL string
}

// NewMiddleware creates a new auth middleware.
func NewMiddleware(sessionService *SessionService, keyManager *crypto.KeyManager) *Middleware {
	return &Middleware{
		sessionService: sessionService,
		keyManager:     keyManager,
	}
}

// WithOAuthVerifier adds an OAuth token verifier to the middleware.
// This enables Bearer token authentication with OAuth JWTs for the MCP endpoint.
func (m *Middleware) WithOAuthVerifier(verifier OAuthTokenVerifier, resourceMetadataURL string) *Middleware {
	m.oauthVerifier = verifier
	m.resourceMetadataURL = resourceMetadataURL
	return m
}

// RequireAuth is middleware that requires valid authentication.
// Supports session cookies, Personal Access Tokens (PAT), and OAuth JWT tokens.
// Returns 401 Unauthorized if no valid authentication is present.
func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var userID string
		var userDB *db.UserDB
		var err error

		// Check for Bearer token first (PAT or OAuth JWT)
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")

			// Check if it's a PAT
			if IsPATToken(token) {
				userID, userDB, err = m.authenticateWithPAT(r.Context(), token)
				if err != nil {
					m.writeUnauthorized(w, "invalid_token", "Invalid personal access token")
					return
				}
			} else if m.oauthVerifier != nil {
				// Try OAuth JWT verification
				userID, userDB, err = m.authenticateWithOAuthJWT(r.Context(), token)
				if err != nil {
					fmt.Printf("[AUTH] OAuth JWT verification failed: %v\n", err)
					m.writeUnauthorized(w, "invalid_token", err.Error())
					return
				}
			}
		}

		// If not authenticated via token, try session cookie
		if userID == "" {
			sessionID, err := GetFromRequest(r)
			if err != nil {
				m.writeUnauthorized(w, "missing_token", "No valid authentication provided")
				return
			}

			// Validate session
			userID, err = m.sessionService.Validate(r.Context(), sessionID)
			if err != nil {
				m.writeUnauthorized(w, "invalid_token", "Invalid or expired session")
				return
			}

			// Get or create user DEK and open database
			dek, err := m.keyManager.GetOrCreateUserDEK(userID)
			if err != nil {
				// Log error for debugging
				fmt.Printf("[AUTH] GetOrCreateUserDEK failed for user %s: %v\n", userID, err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			// Open user database with DEK
			userDB, err = db.OpenUserDBWithDEK(userID, dek)
			if err != nil {
				// Log error for debugging
				fmt.Printf("[AUTH] OpenUserDBWithDEK failed for user %s: %v\n", userID, err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
		}

		// Add user info to context
		ctx := context.WithValue(r.Context(), userIDKey, userID)
		ctx = context.WithValue(ctx, userDBKey, userDB)

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
func (m *Middleware) writeUnauthorized(w http.ResponseWriter, errorType, errorDesc string) {
	if m.resourceMetadataURL != "" {
		challenge := fmt.Sprintf(`Bearer resource_metadata="%s", error="%s", error_description="%s"`,
			m.resourceMetadataURL, errorType, errorDesc)
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
			fmt.Printf("[AUTH] GetOrCreateUserDEK failed for user %s: %v\n", userID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Open user database with DEK
		userDB, err = db.OpenUserDBWithDEK(userID, dek)
		if err != nil {
			fmt.Printf("[AUTH] OpenUserDBWithDEK failed for user %s: %v\n", userID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Add user info to context
		ctx := context.WithValue(r.Context(), userIDKey, userID)
		ctx = context.WithValue(ctx, userDBKey, userDB)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authenticateWithPAT validates a PAT and returns the user ID and their database.
func (m *Middleware) authenticateWithPAT(ctx context.Context, token string) (string, *db.UserDB, error) {
	// Parse the PAT to extract user ID and token part
	userID, tokenPart, ok := ParsePATToken(token)
	if !ok {
		return "", nil, ErrPATNotFound
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

	// Validate the PAT against the user's database
	_, err = ValidatePATWithDB(ctx, userDB, tokenPart)
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

		// Add user info to context
		ctx := context.WithValue(r.Context(), userIDKey, userID)
		ctx = context.WithValue(ctx, userDBKey, userDB)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
