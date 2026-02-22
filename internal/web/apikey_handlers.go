// Package web provides API Key management handlers.
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

// APIKeySettingsData contains data for the API key settings page.
type APIKeySettingsData struct {
	PageData
	Tokens   []auth.APIKey
	NewToken string // Only set when a token was just created
	BaseURL  string
}

// APIKeyNewData contains data for the new API key creation page.
type APIKeyNewData struct {
	PageData
	BaseURL string
}

// APIKeyCreatedData contains data for the API key created confirmation page.
type APIKeyCreatedData struct {
	PageData
	Token     string
	TokenName string
	BaseURL   string
}

// HandleAPIKeySettings handles GET /settings/api-keys - shows API key management page.
func (h *WebHandler) HandleAPIKeySettings(w http.ResponseWriter, r *http.Request) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// List existing API keys
	rows, err := userDB.Queries().ListAPIKeys(r.Context())
	if err != nil {
		h.renderer.RenderError(w, http.StatusInternalServerError, "Failed to load API keys")
		return
	}

	keys := make([]auth.APIKey, 0, len(rows))
	for _, row := range rows {
		key := auth.APIKey{
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

	data := APIKeySettingsData{
		PageData: PageData{
			Title: "API Keys",
			User:  &auth.User{ID: auth.GetUserID(r.Context())},
		},
		Tokens:  keys,
		BaseURL: h.baseURL,
	}

	// Check for error in query params
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		data.Error = errMsg
	}

	if err := h.renderer.Render(w, "settings/api-keys.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleNewAPIKeyPage handles GET /settings/api-keys/new - shows the new API key creation form.
func (h *WebHandler) HandleNewAPIKeyPage(w http.ResponseWriter, r *http.Request) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	data := APIKeyNewData{
		PageData: PageData{
			Title: "Create New API Key",
			User:  &auth.User{ID: auth.GetUserID(r.Context())},
		},
		BaseURL: h.baseURL,
	}

	// Check for error in query params
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		data.Error = errMsg
	}

	if err := h.renderer.Render(w, "api-keys/new.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleCreateAPIKey handles POST /api-keys - creates a new API key.
func (h *WebHandler) HandleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
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
		http.Redirect(w, r, "/settings/api-keys/new?error=Invalid+form+data", http.StatusFound)
		return
	}

	name := r.FormValue("name")
	scope := r.FormValue("scope")
	expiresInStr := r.FormValue("expires_in")
	email := r.FormValue("email")
	password := r.FormValue("password")

	errRedirect := "/settings/api-keys/new?error="

	// Validate required fields
	if name == "" {
		http.Redirect(w, r, errRedirect+"API+key+name+is+required", http.StatusFound)
		return
	}

	if email == "" || password == "" {
		http.Redirect(w, r, errRedirect+"Email+and+password+are+required", http.StatusFound)
		return
	}
	account, err := userDB.Queries().GetAccount(r.Context(), userID)
	if err != nil {
		http.Redirect(w, r, errRedirect+"Invalid+credentials", http.StatusFound)
		return
	}
	if account.Email != email {
		http.Redirect(w, r, errRedirect+"Invalid+credentials", http.StatusFound)
		return
	}
	if account.PasswordHash.Valid && account.PasswordHash.String != "" {
		if !h.authService.VerifyPasswordHash(password, account.PasswordHash.String) {
			http.Redirect(w, r, errRedirect+"Invalid+credentials", http.StatusFound)
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

	// Create the API Key
	token, _, err := createAPIKeyForUser(r.Context(), userDB, userID, name, scope, expiresIn)
	if err != nil {
		http.Redirect(w, r, errRedirect+"Failed+to+create+API+key", http.StatusFound)
		return
	}

	// Render the API key created page (shows token only once)
	data := APIKeyCreatedData{
		PageData: PageData{
			Title: "API Key Created",
			User:  &auth.User{ID: userID},
		},
		Token:     token,
		TokenName: name,
		BaseURL:   h.baseURL,
	}

	if err := h.renderer.Render(w, "api-keys/created.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// createAPIKeyForUser creates an API Key and returns the full token string.
func createAPIKeyForUser(ctx context.Context, userDB *db.UserDB, userID, name, scope string, expiresIn int64) (string, string, error) {
	// Generate secure token
	tokenBytes := make([]byte, auth.APIKeyTokenBytes)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", err
	}
	tokenPart := base64.URLEncoding.EncodeToString(tokenBytes)

	// Hash token for storage
	hash := sha256.Sum256([]byte(tokenPart))
	tokenHash := base64.URLEncoding.EncodeToString(hash[:])

	// Create API Key record
	now := time.Now()
	keyID := uuid.New().String()
	expiresAt := now.Add(time.Duration(expiresIn) * time.Second)

	err := userDB.Queries().CreateAPIKey(ctx, userdb.CreateAPIKeyParams{
		ID:        keyID,
		Name:      name,
		TokenHash: tokenHash,
		Scope:     sql.NullString{String: scope, Valid: true},
		ExpiresAt: expiresAt.Unix(),
		CreatedAt: now.Unix(),
	})
	if err != nil {
		return "", "", err
	}

	// Return full token: agentnotes_key_{user_id}_{random_token}
	fullToken := auth.APIKeyPrefix + userID + "_" + tokenPart
	return fullToken, keyID, nil
}

// HandleRevokeAPIKey handles POST /api-keys/{id}/revoke - revokes an API key.
func (h *WebHandler) HandleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	keyID := r.PathValue("id")
	if keyID == "" {
		http.Redirect(w, r, "/settings/api-keys?error=API+key+ID+required", http.StatusFound)
		return
	}

	// Verify the API Key exists
	_, err := userDB.Queries().GetAPIKeyByID(r.Context(), keyID)
	if err != nil {
		http.Redirect(w, r, "/settings/api-keys?error=API+key+not+found", http.StatusFound)
		return
	}

	// Delete the API Key
	if err := userDB.Queries().DeleteAPIKey(r.Context(), keyID); err != nil {
		http.Redirect(w, r, "/settings/api-keys?error=Failed+to+revoke+API+key", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/settings/api-keys", http.StatusFound)
}
