package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/db/sessions"
)

// Session errors
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
)

// Session configuration
const (
	SessionDuration   = 30 * 24 * time.Hour // 30 days
	SessionIDLength   = 32                  // 256 bits
	SessionCookieName = "session_id"
)

// Session represents an active user session.
type Session struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// SessionService handles session management.
type SessionService struct {
	db *db.SessionsDB
}

// NewSessionService creates a new session service.
func NewSessionService(sessionsDB *db.SessionsDB) *SessionService {
	return &SessionService{
		db: sessionsDB,
	}
}

// Create creates a new session for a user.
// Returns the session ID which should be stored in a cookie.
func (s *SessionService) Create(ctx context.Context, userID string) (string, error) {
	// Generate cryptographically secure session ID
	sessionID, err := generateSessionID()
	if err != nil {
		return "", fmt.Errorf("generate session ID: %w", err)
	}

	// Calculate expiry
	now := time.Now()
	expiresAt := now.Add(SessionDuration)

	// Store session
	err = s.db.Queries().UpsertSession(ctx, sessions.UpsertSessionParams{
		SessionID: sessionID,
		UserID:    userID,
		ExpiresAt: expiresAt.Unix(),
		CreatedAt: now.Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("store session: %w", err)
	}

	return sessionID, nil
}

// Validate checks if a session is valid and returns the user ID.
func (s *SessionService) Validate(ctx context.Context, sessionID string) (string, error) {
	session, err := s.db.Queries().GetValidSession(ctx, sessionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrSessionNotFound
		}
		return "", fmt.Errorf("get session: %w", err)
	}

	return session.UserID, nil
}

// Delete removes a session (logout).
func (s *SessionService) Delete(ctx context.Context, sessionID string) error {
	err := s.db.Queries().DeleteSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// DeleteByUserID removes all sessions for a user.
func (s *SessionService) DeleteByUserID(ctx context.Context, userID string) error {
	err := s.db.Queries().DeleteSessionsByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("delete user sessions: %w", err)
	}
	return nil
}

// Cleanup removes all expired sessions.
// This should be called periodically by a background goroutine.
func (s *SessionService) Cleanup(ctx context.Context) error {
	err := s.db.Queries().DeleteExpiredSessionsNow(ctx)
	if err != nil {
		return fmt.Errorf("cleanup expired sessions: %w", err)
	}
	return nil
}

// Cookie helpers

// SetCookie sets the session cookie on the response.
func SetCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // Requires HTTPS
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(SessionDuration.Seconds()),
	})
}

// ClearCookie removes the session cookie.
func ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // Delete immediately
	})
}

// GetFromRequest retrieves the session ID from the request cookie.
func GetFromRequest(r *http.Request) (string, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return "", ErrSessionNotFound
		}
		return "", err
	}
	return cookie.Value, nil
}

// Helper functions

func generateSessionID() (string, error) {
	bytes := make([]byte, SessionIDLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
