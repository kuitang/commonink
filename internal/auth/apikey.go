// Package auth provides API Key management for programmatic API access.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/db/userdb"
)

// API Key related errors.
var (
	ErrAPIKeyNotFound     = errors.New("apikey: token not found")
	ErrAPIKeyExpired      = errors.New("apikey: token expired")
	ErrAPIKeyInvalidScope = errors.New("apikey: invalid scope")
	ErrInvalidAPIKeyName  = errors.New("apikey: name is required")
	ErrInvalidExpiry      = errors.New("apikey: invalid expiry (max 1 year)")
)

const (
	// APIKeyTokenBytes is the number of random bytes for API key generation (48 bytes = 64 chars base64url).
	APIKeyTokenBytes = 48

	// MaxAPIKeyExpiry is the maximum token validity period (1 year).
	MaxAPIKeyExpiry = 365 * 24 * time.Hour

	// APIKeyPrefix is the prefix for API key tokens to distinguish them from other tokens.
	// Format: agentnotes_key_{user_id}_{random_token}
	APIKeyPrefix = "agentnotes_key_"
)

// IsAPIKeyToken checks if a token looks like an API key based on its prefix.
func IsAPIKeyToken(token string) bool {
	return strings.HasPrefix(token, APIKeyPrefix)
}

// ParseAPIKeyToken extracts the user ID and token hash source from an API key.
// API key format: agentnotes_key_{user_id}_{random_token}
// User ID format: user-{UUID} where UUID is 36 characters (8-4-4-4-12 hex with hyphens)
// Token part: 64 characters (48 bytes base64url encoded, may contain underscores)
func ParseAPIKeyToken(token string) (userID, tokenPart string, ok bool) {
	if !strings.HasPrefix(token, APIKeyPrefix) {
		return "", "", false
	}

	// Remove prefix
	remainder := token[len(APIKeyPrefix):]

	// User ID is in format "user-{UUID}" where UUID is 36 chars
	// So userID is 5 ("user-") + 36 (UUID) = 41 chars
	// Then there's an underscore separator, then the 64-char base64url token
	const userIDLength = 41 // "user-" (5) + UUID (36)

	// Check minimum length: userID (41) + underscore (1) + token (at least 1)
	if len(remainder) < userIDLength+2 {
		return "", "", false
	}

	// Check that there's an underscore after the userID
	if remainder[userIDLength] != '_' {
		return "", "", false
	}

	userID = remainder[:userIDLength]
	tokenPart = remainder[userIDLength+1:]

	// Validate userID format starts with "user-"
	if !strings.HasPrefix(userID, "user-") {
		return "", "", false
	}

	if userID == "" || tokenPart == "" {
		return "", "", false
	}

	return userID, tokenPart, true
}

// APIKey represents an API Key with its metadata.
type APIKey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Scope      string     `json:"scope"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// CreateAPIKeyRequest is the request body for creating a new API Key.
type CreateAPIKeyRequest struct {
	Name      string `json:"name"`
	Scope     string `json:"scope,omitempty"` // Default: "read_write"
	ExpiresIn int64  `json:"expires_in"`      // Seconds until expiry, max 1 year
	Email     string `json:"email"`           // Required for password re-auth
	Password  string `json:"password"`        // Required for password re-auth
}

// CreateAPIKeyResponse is the response when creating a new API Key.
// The Token field is only returned once - it cannot be retrieved later.
type CreateAPIKeyResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Token     string    `json:"token"` // Only returned once!
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// ListAPIKeysResponse is the response for listing API Keys.
type ListAPIKeysResponse struct {
	Tokens []APIKey `json:"tokens"`
}

// APIKeyHandler provides HTTP handlers for API Key management.
type APIKeyHandler struct {
	userService *UserService
}

// NewAPIKeyHandler creates a new API Key handler.
func NewAPIKeyHandler(userService *UserService) *APIKeyHandler {
	return &APIKeyHandler{
		userService: userService,
	}
}

// CreateAPIKey handles POST /api/keys - creates a new API Key.
// Requires password re-authentication for security.
func (h *APIKeyHandler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	userDB := GetUserDB(r.Context())
	if userDB == nil {
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	userID := GetUserID(r.Context())
	if userID == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate name
	if req.Name == "" {
		writeJSONError(w, http.StatusBadRequest, "token name is required")
		return
	}

	// Validate email and password for re-authentication
	if req.Email == "" || req.Password == "" {
		writeJSONError(w, http.StatusBadRequest, "email and password are required for re-authentication")
		return
	}

	// Verify password (in production, this would verify against stored hash)
	// For now, we verify the email matches the current user
	account, err := userDB.Queries().GetAccount(r.Context(), userID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		writeJSONError(w, http.StatusInternalServerError, "failed to verify credentials")
		return
	}

	// Verify email matches
	if account.Email != req.Email {
		writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Verify password if hash exists
	if account.PasswordHash.Valid && account.PasswordHash.String != "" {
		if !VerifyPassword(req.Password, account.PasswordHash.String) {
			writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
	}
	// Note: If no password hash exists (e.g., Google OAuth user), we allow API key creation
	// since they've authenticated via session

	// Validate expiry
	if req.ExpiresIn <= 0 {
		req.ExpiresIn = int64(MaxAPIKeyExpiry.Seconds()) // Default to max
	}
	if time.Duration(req.ExpiresIn)*time.Second > MaxAPIKeyExpiry {
		writeJSONError(w, http.StatusBadRequest, "expiry cannot exceed 1 year")
		return
	}

	// Default scope
	if req.Scope == "" {
		req.Scope = "read_write"
	}

	// Generate secure token
	token, err := generateAPIKeyToken()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	// Hash token for storage
	tokenHash := hashAPIKeyToken(token)

	// Create API key record
	now := time.Now()
	keyID := uuid.New().String()
	expiresAt := now.Add(time.Duration(req.ExpiresIn) * time.Second)

	err = userDB.Queries().CreateAPIKey(r.Context(), userdb.CreateAPIKeyParams{
		ID:        keyID,
		Name:      req.Name,
		TokenHash: tokenHash,
		Scope:     sql.NullString{String: req.Scope, Valid: true},
		ExpiresAt: expiresAt.Unix(),
		CreatedAt: now.Unix(),
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to create token")
		return
	}

	// Return response with plaintext token (shown only once)
	// Format: agentnotes_key_{user_id}_{random_token}
	fullToken := fmt.Sprintf("%s%s_%s", APIKeyPrefix, userID, token)
	resp := CreateAPIKeyResponse{
		ID:        keyID,
		Name:      req.Name,
		Token:     fullToken,
		Scope:     req.Scope,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// ListAPIKeys handles GET /api/keys - lists all API Keys for the user.
// Token values are never returned, only metadata.
func (h *APIKeyHandler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	userDB := GetUserDB(r.Context())
	if userDB == nil {
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	rows, err := userDB.Queries().ListAPIKeys(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to list tokens")
		return
	}

	keys := make([]APIKey, 0, len(rows))
	for _, row := range rows {
		key := APIKey{
			ID:        row.ID,
			Name:      row.Name,
			Scope:     row.Scope.String,
			ExpiresAt: time.Unix(row.ExpiresAt, 0),
			CreatedAt: time.Unix(row.CreatedAt, 0),
		}
		if row.LastUsedAt.Valid {
			t := time.Unix(row.LastUsedAt.Int64, 0)
			key.LastUsedAt = &t
		}
		keys = append(keys, key)
	}

	resp := ListAPIKeysResponse{Tokens: keys}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// RevokeAPIKey handles DELETE /api/keys/{id} - revokes an API Key.
func (h *APIKeyHandler) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	userDB := GetUserDB(r.Context())
	if userDB == nil {
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	keyID := r.PathValue("id")
	if keyID == "" {
		writeJSONError(w, http.StatusBadRequest, "token ID is required")
		return
	}

	// Verify the API key exists and belongs to this user
	_, err := userDB.Queries().GetAPIKeyByID(r.Context(), keyID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "token not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "failed to find token")
		return
	}

	// Delete the API key
	err = userDB.Queries().DeleteAPIKey(r.Context(), keyID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to revoke token")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ValidateAPIKeyWithDB validates an API Key against the user's database and returns the scope if valid.
// This is used by the middleware to authenticate API requests when the userDB is already open.
func ValidateAPIKeyWithDB(ctx context.Context, userDB *db.UserDB, tokenPart string) (string, error) {
	// Hash the token part
	tokenHash := hashAPIKeyToken(tokenPart)

	// Look up the API key
	key, err := userDB.Queries().GetAPIKeyByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrAPIKeyNotFound
		}
		return "", fmt.Errorf("failed to validate API key: %w", err)
	}

	// Check expiry
	if time.Now().Unix() > key.ExpiresAt {
		return "", ErrAPIKeyExpired
	}

	// Update last used timestamp
	_ = userDB.Queries().UpdateAPIKeyLastUsed(ctx, userdb.UpdateAPIKeyLastUsedParams{
		LastUsedAt: sql.NullInt64{Int64: time.Now().Unix(), Valid: true},
		ID:         key.ID,
	})

	scope := key.Scope.String
	if scope == "" {
		scope = "read_write"
	}

	return scope, nil
}

// Helper functions

func generateAPIKeyToken() (string, error) {
	bytes := make([]byte, APIKeyTokenBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func hashAPIKeyToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.URLEncoding.EncodeToString(hash[:])
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
