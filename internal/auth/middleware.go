package auth

import (
	"context"
	"net/http"

	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
)

// Context keys for auth data
type contextKey string

const (
	userIDKey contextKey = "userID"
	userDBKey contextKey = "userDB"
)

// Middleware provides authentication middleware for HTTP handlers.
type Middleware struct {
	sessionService *SessionService
	keyManager     *crypto.KeyManager
}

// NewMiddleware creates a new auth middleware.
func NewMiddleware(sessionService *SessionService, keyManager *crypto.KeyManager) *Middleware {
	return &Middleware{
		sessionService: sessionService,
		keyManager:     keyManager,
	}
}

// RequireAuth is middleware that requires a valid session.
// Returns 401 Unauthorized if no valid session is present.
func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get session ID from cookie
		sessionID, err := GetFromRequest(r)
		if err != nil {
			http.Error(w, "Unauthorized: no session", http.StatusUnauthorized)
			return
		}

		// Validate session
		userID, err := m.sessionService.Validate(r.Context(), sessionID)
		if err != nil {
			http.Error(w, "Unauthorized: invalid session", http.StatusUnauthorized)
			return
		}

		// Get or create user DEK and open database
		dek, err := m.keyManager.GetOrCreateUserDEK(userID)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Open user database with DEK
		userDB, err := db.OpenUserDBWithDEK(userID, dek)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Add user info to context
		ctx := context.WithValue(r.Context(), userIDKey, userID)
		ctx = context.WithValue(ctx, userDBKey, userDB)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
