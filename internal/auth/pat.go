// Package auth provides Personal Access Token (PAT) management for programmatic API access.
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

// PAT-related errors.
var (
	ErrPATNotFound     = errors.New("pat: token not found")
	ErrPATExpired      = errors.New("pat: token expired")
	ErrPATInvalidScope = errors.New("pat: invalid scope")
	ErrInvalidPATName  = errors.New("pat: name is required")
	ErrInvalidExpiry   = errors.New("pat: invalid expiry (max 1 year)")
)

const (
	// PATTokenBytes is the number of random bytes for PAT generation (48 bytes = 64 chars base64url).
	PATTokenBytes = 48

	// MaxPATExpiry is the maximum token validity period (1 year).
	MaxPATExpiry = 365 * 24 * time.Hour

	// PATPrefix is the prefix for PAT tokens to distinguish them from other tokens.
	// Format: agentnotes_pat_{user_id}_{random_token}
	PATPrefix = "agentnotes_pat_"
)

// IsPATToken checks if a token looks like a PAT based on its prefix.
func IsPATToken(token string) bool {
	return strings.HasPrefix(token, PATPrefix)
}

// ParsePATToken extracts the user ID and token hash source from a PAT.
// PAT format: agentnotes_pat_{user_id}_{random_token}
// User ID format: user-{UUID} where UUID is 36 characters (8-4-4-4-12 hex with hyphens)
// Token part: 64 characters (48 bytes base64url encoded, may contain underscores)
func ParsePATToken(token string) (userID, tokenPart string, ok bool) {
	if !strings.HasPrefix(token, PATPrefix) {
		return "", "", false
	}

	// Remove prefix
	remainder := token[len(PATPrefix):]

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

// PAT represents a Personal Access Token with its metadata.
type PAT struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Scope      string     `json:"scope"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// CreatePATRequest is the request body for creating a new PAT.
type CreatePATRequest struct {
	Name      string `json:"name"`
	Scope     string `json:"scope,omitempty"` // Default: "read_write"
	ExpiresIn int64  `json:"expires_in"`      // Seconds until expiry, max 1 year
	Email     string `json:"email"`           // Required for password re-auth
	Password  string `json:"password"`        // Required for password re-auth
}

// CreatePATResponse is the response when creating a new PAT.
// The Token field is only returned once - it cannot be retrieved later.
type CreatePATResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Token     string    `json:"token"` // Only returned once!
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// ListPATsResponse is the response for listing PATs.
type ListPATsResponse struct {
	Tokens []PAT `json:"tokens"`
}

// PATHandler provides HTTP handlers for PAT management.
type PATHandler struct {
	userService *UserService
}

// NewPATHandler creates a new PAT handler.
func NewPATHandler(userService *UserService) *PATHandler {
	return &PATHandler{
		userService: userService,
	}
}

// CreatePAT handles POST /api/tokens - creates a new Personal Access Token.
// Requires password re-authentication for security.
func (h *PATHandler) CreatePAT(w http.ResponseWriter, r *http.Request) {
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

	var req CreatePATRequest
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
	// Note: If no password hash exists (e.g., Google OAuth user), we allow PAT creation
	// since they've authenticated via session

	// Validate expiry
	if req.ExpiresIn <= 0 {
		req.ExpiresIn = int64(MaxPATExpiry.Seconds()) // Default to max
	}
	if time.Duration(req.ExpiresIn)*time.Second > MaxPATExpiry {
		writeJSONError(w, http.StatusBadRequest, "expiry cannot exceed 1 year")
		return
	}

	// Default scope
	if req.Scope == "" {
		req.Scope = "read_write"
	}

	// Generate secure token
	token, err := generatePATToken()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	// Hash token for storage
	tokenHash := hashPATToken(token)

	// Create PAT record
	now := time.Now()
	patID := uuid.New().String()
	expiresAt := now.Add(time.Duration(req.ExpiresIn) * time.Second)

	err = userDB.Queries().CreatePAT(r.Context(), userdb.CreatePATParams{
		ID:        patID,
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
	// Format: agentnotes_pat_{user_id}_{random_token}
	fullToken := fmt.Sprintf("%s%s_%s", PATPrefix, userID, token)
	resp := CreatePATResponse{
		ID:        patID,
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

// ListPATs handles GET /api/tokens - lists all PATs for the user.
// Token values are never returned, only metadata.
func (h *PATHandler) ListPATs(w http.ResponseWriter, r *http.Request) {
	userDB := GetUserDB(r.Context())
	if userDB == nil {
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	rows, err := userDB.Queries().ListPATs(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to list tokens")
		return
	}

	pats := make([]PAT, 0, len(rows))
	for _, row := range rows {
		pat := PAT{
			ID:        row.ID,
			Name:      row.Name,
			Scope:     row.Scope.String,
			ExpiresAt: time.Unix(row.ExpiresAt, 0),
			CreatedAt: time.Unix(row.CreatedAt, 0),
		}
		if row.LastUsedAt.Valid {
			t := time.Unix(row.LastUsedAt.Int64, 0)
			pat.LastUsedAt = &t
		}
		pats = append(pats, pat)
	}

	resp := ListPATsResponse{Tokens: pats}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// RevokePAT handles DELETE /api/tokens/{id} - revokes a PAT.
func (h *PATHandler) RevokePAT(w http.ResponseWriter, r *http.Request) {
	userDB := GetUserDB(r.Context())
	if userDB == nil {
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	patID := r.PathValue("id")
	if patID == "" {
		writeJSONError(w, http.StatusBadRequest, "token ID is required")
		return
	}

	// Verify the PAT exists and belongs to this user
	_, err := userDB.Queries().GetPATByID(r.Context(), patID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "token not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "failed to find token")
		return
	}

	// Delete the PAT
	err = userDB.Queries().DeletePAT(r.Context(), patID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to revoke token")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ValidatePATWithDB validates a PAT against the user's database and returns the scope if valid.
// This is used by the middleware to authenticate API requests when the userDB is already open.
func ValidatePATWithDB(ctx context.Context, userDB *db.UserDB, tokenPart string) (string, error) {
	// Hash the token part
	tokenHash := hashPATToken(tokenPart)

	// Look up the PAT
	pat, err := userDB.Queries().GetPATByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrPATNotFound
		}
		return "", fmt.Errorf("failed to validate PAT: %w", err)
	}

	// Check expiry
	if time.Now().Unix() > pat.ExpiresAt {
		return "", ErrPATExpired
	}

	// Update last used timestamp
	_ = userDB.Queries().UpdatePATLastUsed(ctx, userdb.UpdatePATLastUsedParams{
		LastUsedAt: sql.NullInt64{Int64: time.Now().Unix(), Valid: true},
		ID:         pat.ID,
	})

	scope := pat.Scope.String
	if scope == "" {
		scope = "read_write"
	}

	return scope, nil
}

// Helper functions

func generatePATToken() (string, error) {
	bytes := make([]byte, PATTokenBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func hashPATToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.URLEncoding.EncodeToString(hash[:])
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
