// Package web provides PAT (Personal Access Token) management handlers.
package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/db/userdb"
)

// TokenSettingsData contains data for the token settings page.
type TokenSettingsData struct {
	PageData
	Tokens   []auth.PAT
	NewToken string // Only set when a token was just created
	BaseURL  string
}

// HandleTokenSettings handles GET /settings/tokens - shows token management page.
func (h *WebHandler) HandleTokenSettings(w http.ResponseWriter, r *http.Request) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// List existing tokens
	rows, err := userDB.Queries().ListPATs(r.Context())
	if err != nil {
		h.renderer.RenderError(w, http.StatusInternalServerError, "Failed to load tokens")
		return
	}

	tokens := make([]auth.PAT, 0, len(rows))
	for _, row := range rows {
		pat := auth.PAT{
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
		tokens = append(tokens, pat)
	}

	// Check for new token in query params (from redirect after creation)
	newToken := r.URL.Query().Get("new_token")

	data := TokenSettingsData{
		PageData: PageData{
			Title: "Personal Access Tokens",
			User:  &auth.User{ID: auth.GetUserID(r.Context())},
		},
		Tokens:   tokens,
		NewToken: newToken,
		BaseURL:  h.baseURL,
	}

	// Check for error in query params
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		data.Error = errMsg
	}

	if err := h.renderer.Render(w, "settings/tokens.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleCreateToken handles POST /settings/tokens - creates a new PAT.
func (h *WebHandler) HandleCreateToken(w http.ResponseWriter, r *http.Request) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	userID := auth.GetUserID(r.Context())
	if userID == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/settings/tokens?error=Invalid+form+data", http.StatusFound)
		return
	}

	name := r.FormValue("name")
	scope := r.FormValue("scope")
	expiresInStr := r.FormValue("expires_in")
	email := r.FormValue("email")
	password := r.FormValue("password")

	// Validate required fields
	if name == "" {
		http.Redirect(w, r, "/settings/tokens?error=Token+name+is+required", http.StatusFound)
		return
	}

	if email == "" || password == "" {
		http.Redirect(w, r, "/settings/tokens?error=Email+and+password+required+for+authentication", http.StatusFound)
		return
	}

	// Verify credentials
	account, err := userDB.Queries().GetAccount(r.Context(), userID)
	if err != nil {
		http.Redirect(w, r, "/settings/tokens?error=Failed+to+verify+credentials", http.StatusFound)
		return
	}

	if account.Email != email {
		http.Redirect(w, r, "/settings/tokens?error=Invalid+credentials", http.StatusFound)
		return
	}

	// Verify password if hash exists
	if account.PasswordHash.Valid && account.PasswordHash.String != "" {
		if !auth.VerifyPassword(password, account.PasswordHash.String) {
			http.Redirect(w, r, "/settings/tokens?error=Invalid+credentials", http.StatusFound)
			return
		}
	}

	// Parse expiration
	expiresIn := int64(31536000) // Default 1 year
	if expiresInStr != "" {
		if parsed, err := strconv.ParseInt(expiresInStr, 10, 64); err == nil && parsed > 0 {
			expiresIn = parsed
		}
	}

	// Default scope
	if scope == "" {
		scope = "read_write"
	}

	// Create the PAT
	token, _, err := createPATForUser(r.Context(), userDB, userID, name, scope, expiresIn)
	if err != nil {
		http.Redirect(w, r, "/settings/tokens?error=Failed+to+create+token", http.StatusFound)
		return
	}

	// Redirect back to settings with the new token displayed
	http.Redirect(w, r, "/settings/tokens?new_token="+token, http.StatusFound)
}

// createPATForUser creates a PAT and returns the full token string.
func createPATForUser(ctx context.Context, userDB *db.UserDB, userID, name, scope string, expiresIn int64) (string, string, error) {
	// Generate secure token
	tokenBytes := make([]byte, auth.PATTokenBytes)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", err
	}
	tokenPart := base64.URLEncoding.EncodeToString(tokenBytes)

	// Hash token for storage
	hash := sha256.Sum256([]byte(tokenPart))
	tokenHash := base64.URLEncoding.EncodeToString(hash[:])

	// Create PAT record
	now := time.Now()
	patID := uuid.New().String()
	expiresAt := now.Add(time.Duration(expiresIn) * time.Second)

	err := userDB.Queries().CreatePAT(ctx, userdb.CreatePATParams{
		ID:        patID,
		Name:      name,
		TokenHash: tokenHash,
		Scope:     sql.NullString{String: scope, Valid: true},
		ExpiresAt: expiresAt.Unix(),
		CreatedAt: now.Unix(),
	})
	if err != nil {
		return "", "", err
	}

	// Return full token: agentnotes_pat_{user_id}_{random_token}
	fullToken := auth.PATPrefix + userID + "_" + tokenPart
	return fullToken, patID, nil
}

// HandleRevokeToken handles POST /settings/tokens/{id}/revoke - revokes a PAT.
func (h *WebHandler) HandleRevokeToken(w http.ResponseWriter, r *http.Request) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	patID := r.PathValue("id")
	if patID == "" {
		http.Redirect(w, r, "/settings/tokens?error=Token+ID+required", http.StatusFound)
		return
	}

	// Verify the PAT exists
	_, err := userDB.Queries().GetPATByID(r.Context(), patID)
	if err != nil {
		http.Redirect(w, r, "/settings/tokens?error=Token+not+found", http.StatusFound)
		return
	}

	// Delete the PAT
	if err := userDB.Queries().DeletePAT(r.Context(), patID); err != nil {
		http.Redirect(w, r, "/settings/tokens?error=Failed+to+revoke+token", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/settings/tokens", http.StatusFound)
}
