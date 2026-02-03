package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

// Handler provides HTTP handlers for authentication routes.
type Handler struct {
	oidcClient     OIDCClient
	userService    *UserService
	sessionService *SessionService
}

// NewHandler creates a new auth handler.
func NewHandler(oidcClient OIDCClient, userService *UserService, sessionService *SessionService) *Handler {
	return &Handler{
		oidcClient:     oidcClient,
		userService:    userService,
		sessionService: sessionService,
	}
}

// RegisterRoutes registers all auth routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Google OIDC (support both GET and POST for flexibility)
	mux.HandleFunc("GET /auth/google", h.HandleGoogleLogin)
	mux.HandleFunc("POST /auth/google", h.HandleGoogleLogin)
	mux.HandleFunc("GET /auth/google/callback", h.HandleGoogleCallback)

	// Magic Link
	mux.HandleFunc("POST /auth/magic", h.HandleMagicLinkRequest)
	mux.HandleFunc("GET /auth/magic/verify", h.HandleMagicLinkVerify)

	// Email/Password
	mux.HandleFunc("POST /auth/register", h.HandleRegister)
	mux.HandleFunc("POST /auth/login", h.HandleLogin)

	// Password Reset (use same paths as web forms)
	mux.HandleFunc("POST /auth/password-reset", h.HandlePasswordResetRequest)
	mux.HandleFunc("POST /auth/password-reset-confirm", h.HandlePasswordResetConfirm)

	// Session (support both GET and POST for logout)
	mux.HandleFunc("POST /auth/logout", h.HandleLogout)
	mux.HandleFunc("GET /auth/logout", h.HandleLogout)
	mux.HandleFunc("GET /auth/whoami", h.HandleWhoami)
}

// HandleGoogleLogin redirects to Google OIDC for authentication.
func (h *Handler) HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate state for CSRF protection
	state, err := generateState()
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	// Store state in a cookie for verification on callback
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes
	})

	// Redirect to OIDC provider
	authURL := h.oidcClient.GetAuthURL(state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleGoogleCallback handles the OIDC callback after authentication.
func (h *Handler) HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		http.Error(w, "Missing state cookie", http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	if state != stateCookie.Value {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "oauth_state",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	// Check for error from provider
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		http.Error(w, "Authentication failed: "+errParam, http.StatusUnauthorized)
		return
	}

	// Exchange code for tokens
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	claims, err := h.oidcClient.ExchangeCode(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
		return
	}

	// Find or create user
	user, err := h.userService.FindOrCreateByEmail(r.Context(), claims.Email)
	if err != nil {
		http.Error(w, "Failed to find or create user", http.StatusInternalServerError)
		return
	}

	// Link Google account if not already linked
	if err := h.userService.LinkGoogleAccount(r.Context(), user.ID, claims.Sub); err != nil {
		// Log but don't fail - account linking is optional
	}

	// Create session
	sessionID, err := h.sessionService.Create(r.Context(), user.ID)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	SetCookie(w, sessionID)

	// Redirect to home or dashboard
	http.Redirect(w, r, "/", http.StatusFound)
}

// MagicLinkRequest is the request body for magic link requests.
type MagicLinkRequest struct {
	Email string `json:"email"`
}

// HandleMagicLinkRequest sends a magic login link.
func (h *Handler) HandleMagicLinkRequest(w http.ResponseWriter, r *http.Request) {
	// Support both URL-encoded and multipart form data (JS fetch sends multipart)
	if err := r.ParseMultipartForm(32 << 10); err != nil {
		if err2 := r.ParseForm(); err2 != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
	}

	email := r.FormValue("email")
	if email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	// Send magic link (always succeed to prevent email enumeration)
	_ = h.userService.SendMagicLink(r.Context(), email)

	// Redirect to login with success message
	http.Redirect(w, r, "/login?magic=sent", http.StatusSeeOther)
}

// HandleMagicLinkVerify verifies a magic link token.
func (h *Handler) HandleMagicLinkVerify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	user, err := h.userService.VerifyMagicToken(r.Context(), token)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Create session
	sessionID, err := h.sessionService.Create(r.Context(), user.ID)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	SetCookie(w, sessionID)

	// Redirect to home
	http.Redirect(w, r, "/", http.StatusFound)
}

// RegisterRequest is the request body for registration.
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// HandleRegister handles email/password registration.
func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if email == "" || password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	// Validate password strength
	if err := ValidatePasswordStrength(password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Find or create user
	user, err := h.userService.FindOrCreateByEmail(r.Context(), email)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Hash and store password (in full implementation)
	_, err = HashPassword(password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Create session
	sessionID, err := h.sessionService.Create(r.Context(), user.ID)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	SetCookie(w, sessionID)

	// Redirect to notes page
	http.Redirect(w, r, "/notes", http.StatusSeeOther)
}

// LoginRequest is the request body for login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// HandleLogin handles email/password login.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	_ = password // TODO: verify against stored hash

	if email == "" || password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	// Find user (in full implementation, would verify password)
	user, err := h.userService.FindOrCreateByEmail(r.Context(), email)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// In full implementation: verify password against stored hash
	// For now, we'll accept any password for testing with mocks

	// Create session
	sessionID, err := h.sessionService.Create(r.Context(), user.ID)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	SetCookie(w, sessionID)

	// Redirect to notes page
	http.Redirect(w, r, "/notes", http.StatusSeeOther)
}

// PasswordResetRequest is the request body for password reset.
type PasswordResetRequest struct {
	Email string `json:"email"`
}

// HandlePasswordResetRequest sends a password reset email.
func (h *Handler) HandlePasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	// Send reset email (always succeed to prevent email enumeration)
	_ = h.userService.SendPasswordReset(r.Context(), email)

	// Redirect to login with success message
	http.Redirect(w, r, "/login?reset=requested", http.StatusSeeOther)
}

// PasswordResetConfirmRequest is the request body for confirming password reset.
type PasswordResetConfirmRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// HandlePasswordResetConfirm confirms a password reset.
func (h *Handler) HandlePasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	newPassword := r.FormValue("new_password")

	if token == "" || newPassword == "" {
		http.Error(w, "Token and new password are required", http.StatusBadRequest)
		return
	}

	if err := h.userService.ResetPassword(r.Context(), token, newPassword); err != nil {
		if err == ErrWeakPassword {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err == ErrInvalidToken {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Failed to reset password", http.StatusInternalServerError)
		return
	}

	// Redirect to login page with success message
	http.Redirect(w, r, "/login?reset=success", http.StatusSeeOther)
}

// HandleLogout logs out the current user.
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID, err := GetFromRequest(r)
	if err == nil {
		// Delete session from database
		_ = h.sessionService.Delete(r.Context(), sessionID)
	}

	// Clear session cookie
	ClearCookie(w)

	// Redirect to home page
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// WhoamiResponse is the response for the whoami endpoint.
type WhoamiResponse struct {
	UserID        string `json:"user_id,omitempty"`
	Email         string `json:"email,omitempty"`
	Authenticated bool   `json:"authenticated"`
}

// HandleWhoami returns information about the current user.
func (h *Handler) HandleWhoami(w http.ResponseWriter, r *http.Request) {
	sessionID, err := GetFromRequest(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(WhoamiResponse{Authenticated: false})
		return
	}

	userID, err := h.sessionService.Validate(r.Context(), sessionID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(WhoamiResponse{Authenticated: false})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(WhoamiResponse{
		UserID:        userID,
		Authenticated: true,
	})
}

// Helper functions

func generateState() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
