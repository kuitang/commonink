package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/kuitang/agent-notes/internal/urlutil"
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
		Secure:   secureCookiesFlag.Load(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes
	})

	// Preserve return_to through the OIDC redirect flow
	if returnTo := r.FormValue("return_to"); isValidReturnTo(returnTo) {
		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_return_to",
			Value:    returnTo,
			Path:     "/",
			HttpOnly: true,
			Secure:   secureCookiesFlag.Load(),
			SameSite: http.SameSiteLaxMode,
			MaxAge:   600, // 10 minutes
		})
	}

	// Persist request origin for mock OIDC local callback generation.
	// This keeps host handling dynamic without hardcoded callback URLs.
	h.setMockOIDCCallbackOriginCookie(w, r)

	origin := urlutil.OriginFromRequest(r, h.userService.resolveBaseURL())
	redirectURL := urlutil.BuildAbsolute(origin, "/auth/google/callback")

	if mockOIDC, ok := h.oidcClient.(*LocalMockOIDCProvider); ok {
		mockOIDC.SetCallbackOrigin(state, origin)
	}

	// Redirect to OIDC provider
	authURL := h.oidcClient.GetAuthURL(state, redirectURL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handler) setMockOIDCCallbackOriginCookie(w http.ResponseWriter, r *http.Request) {
	origin := urlutil.OriginFromRequest(r, h.userService.resolveBaseURL())

	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_mock_callback_origin",
		Value:    origin,
		Path:     "/",
		HttpOnly: true,
		Secure:   secureCookiesFlag.Load(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes
	})
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

	origin := urlutil.OriginFromRequest(r, h.userService.resolveBaseURL())
	redirectURL := urlutil.BuildAbsolute(origin, "/auth/google/callback")
	claims, err := h.oidcClient.ExchangeCode(r.Context(), code, redirectURL)
	if err != nil {
		http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
		return
	}

	// Find or create user (OIDC auto-creates)
	user, err := h.userService.FindOrCreateByProvider(r.Context(), claims.Email)
	if err != nil {
		log.Printf("[AUTH] FindOrCreateByProvider failed for email=%q: %v", claims.Email, err)
		http.Error(w, "Failed to find or create user", http.StatusInternalServerError)
		return
	}

	// Verify/link Google sub
	// Check if intent is "link" (from account settings flow)
	intentCookie, _ := r.Cookie("oauth_intent")
	isLinkIntent := intentCookie != nil && intentCookie.Value == "link"

	if isLinkIntent {
		// Account linking flow: verify email matches logged-in user, then link
		sessionID, sessionErr := GetFromRequest(r)
		if sessionErr != nil {
			http.Error(w, "Must be logged in to link account", http.StatusUnauthorized)
			return
		}
		loggedInUserID, sessionErr := h.sessionService.Validate(r.Context(), sessionID)
		if sessionErr != nil {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}
		if loggedInUserID != user.ID {
			http.Error(w, "Email mismatch: Google email must match your account email", http.StatusForbidden)
			return
		}
		if err := h.userService.LinkGoogleAccount(r.Context(), user.ID, claims.Sub); err != nil {
			log.Printf("[AUTH] LinkGoogleAccount failed: %v", err)
			http.Error(w, "Failed to link Google account", http.StatusInternalServerError)
			return
		}
		// Clear intent cookie
		http.SetCookie(w, &http.Cookie{Name: "oauth_intent", Value: "", Path: "/", MaxAge: -1})
		// Don't create new session — user is already logged in
		// Redirect to account settings with success
		http.Redirect(w, r, "/settings/account?success=google_linked", http.StatusFound)
		return
	}

	// Normal login flow: verify google_sub consistency
	if err := h.userService.LinkGoogleAccount(r.Context(), user.ID, claims.Sub); err != nil {
		log.Printf("[AUTH] LinkGoogleAccount failed for user=%s: %v", user.ID, err)
		http.Error(w, "Google account mismatch", http.StatusForbidden)
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

	// Check for return_to cookie set during HandleGoogleLogin
	redirectTo := "/"
	if returnToCookie, err := r.Cookie("oauth_return_to"); err == nil && isValidReturnTo(returnToCookie.Value) {
		redirectTo = returnToCookie.Value
		// Clear the cookie
		http.SetCookie(w, &http.Cookie{
			Name:   "oauth_return_to",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
	}

	http.Redirect(w, r, redirectTo, http.StatusFound)
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
	_ = h.userService.SendMagicLink(r.Context(), email, urlutil.OriginFromRequest(r, h.userService.baseURL))

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

	tokenUser, err := h.userService.VerifyMagicToken(r.Context(), token)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Ensure account exists (auto-creates with NULL password for magic link users)
	user, err := h.userService.FindOrCreateByProvider(r.Context(), tokenUser.Email)
	if err != nil {
		http.Error(w, "Failed to create account", http.StatusInternalServerError)
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
	returnTo := r.FormValue("return_to")

	if email == "" || password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	// Validate password strength
	if err := ValidatePasswordStrength(password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Register new user with password
	user, err := h.userService.RegisterWithPassword(r.Context(), email, password)
	if err != nil {
		if errors.Is(err, ErrAccountExists) {
			http.Redirect(w, r, "/login?error=Account+already+exists.+Please+sign+in.", http.StatusSeeOther)
			return
		}
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
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

	// Redirect to return_to or notes page
	if isValidReturnTo(returnTo) {
		http.Redirect(w, r, returnTo, http.StatusSeeOther)
		return
	}
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
	returnTo := r.FormValue("return_to")

	if email == "" || password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	// Verify credentials against stored hash
	user, err := h.userService.VerifyLogin(r.Context(), email, password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			http.Redirect(w, r, "/login?error=Invalid+email+or+password", http.StatusSeeOther)
			return
		}
		http.Error(w, "Login failed", http.StatusInternalServerError)
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

	// Redirect to return_to or notes page
	if isValidReturnTo(returnTo) {
		http.Redirect(w, r, returnTo, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/notes", http.StatusSeeOther)
}

// PasswordResetRequest is the request body for password reset.
type PasswordResetRequest struct {
	Email string `json:"email"`
}

// HandlePasswordResetRequest sends a password reset email.
func (h *Handler) HandlePasswordResetRequest(w http.ResponseWriter, r *http.Request) {
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

	// Send reset email (always succeed to prevent email enumeration)
	_ = h.userService.SendPasswordReset(r.Context(), email, urlutil.OriginFromRequest(r, h.userService.baseURL))

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
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	if token == "" || password == "" {
		http.Error(w, "Token and new password are required", http.StatusBadRequest)
		return
	}

	if password != confirmPassword {
		q := url.Values{"token": {token}, "error": {"Passwords do not match"}}
		http.Redirect(w, r, "/auth/password-reset-confirm?"+q.Encode(), http.StatusSeeOther)
		return
	}

	if err := h.userService.ResetPassword(r.Context(), token, password); err != nil {
		if err == ErrWeakPassword {
			q := url.Values{"token": {token}, "error": {err.Error()}}
			http.Redirect(w, r, "/auth/password-reset-confirm?"+q.Encode(), http.StatusSeeOther)
			return
		}
		if err == ErrInvalidToken {
			http.Redirect(w, r, "/login?error=Reset+link+is+invalid+or+expired.+Please+request+a+new+one.", http.StatusSeeOther)
			return
		}
		http.Error(w, "Failed to reset password", http.StatusInternalServerError)
		return
	}

	// Redirect to login page with success message
	http.Redirect(w, r, "/login?success=Password+reset+successfully.+Please+sign+in.", http.StatusSeeOther)
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

// isValidReturnTo checks if a return_to URL is a safe local path.
// Prevents open redirect attacks by only allowing paths that start with /
// and are not protocol-relative URLs.
func isValidReturnTo(returnTo string) bool {
	if returnTo == "" {
		return false
	}
	if !strings.HasPrefix(returnTo, "/") {
		return false
	}
	if strings.HasPrefix(returnTo, "//") {
		return false
	}
	return true
}
