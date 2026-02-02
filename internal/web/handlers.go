// Package web provides HTTP handlers for the web UI.
package web

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/kuitang/agent-notes/internal/s3client"
)

// WebHandler provides HTTP handlers for web UI pages.
type WebHandler struct {
	renderer       *Renderer
	notesService   *notes.Service
	publicNotes    *notes.PublicNoteService
	authService    *auth.UserService
	sessionService *auth.SessionService
	consentService *auth.ConsentService
	s3Client       *s3client.Client
	baseURL        string
}

// NewWebHandler creates a new web handler.
func NewWebHandler(
	renderer *Renderer,
	notesService *notes.Service,
	publicNotes *notes.PublicNoteService,
	authService *auth.UserService,
	sessionService *auth.SessionService,
	consentService *auth.ConsentService,
	s3Client *s3client.Client,
	baseURL string,
) *WebHandler {
	return &WebHandler{
		renderer:       renderer,
		notesService:   notesService,
		publicNotes:    publicNotes,
		authService:    authService,
		sessionService: sessionService,
		consentService: consentService,
		s3Client:       s3Client,
		baseURL:        baseURL,
	}
}

// RegisterRoutes registers all web UI routes on the given mux.
func (h *WebHandler) RegisterRoutes(mux *http.ServeMux, authMiddleware *auth.Middleware) {
	// Landing page
	mux.Handle("GET /", authMiddleware.OptionalAuth(http.HandlerFunc(h.HandleLanding)))

	// Auth pages (no auth required)
	// Note: /auth/google and /auth/google/callback are registered by internal/auth/handlers.go
	mux.HandleFunc("GET /login", h.HandleLoginPage)
	mux.HandleFunc("POST /auth/login", h.HandleLogin)
	mux.HandleFunc("POST /auth/magic", h.HandleMagicLinkRequest)
	mux.HandleFunc("GET /auth/magic/verify", h.HandleMagicLinkVerify)
	mux.HandleFunc("POST /auth/register", h.HandleRegister)
	mux.HandleFunc("POST /auth/logout", h.HandleLogout)
	mux.HandleFunc("GET /password-reset", h.HandlePasswordResetPage)
	mux.HandleFunc("POST /auth/password-reset", h.HandlePasswordReset)
	mux.HandleFunc("GET /auth/password-reset-confirm", h.HandlePasswordResetConfirmPage)
	mux.HandleFunc("POST /auth/password-reset-confirm", h.HandlePasswordResetConfirm)
	mux.HandleFunc("GET /register", h.HandleRegisterPage)

	// Notes CRUD (auth required)
	mux.Handle("GET /notes", authMiddleware.RequireAuth(http.HandlerFunc(h.HandleNotesList)))
	mux.Handle("GET /notes/new", authMiddleware.RequireAuth(http.HandlerFunc(h.HandleNewNotePage)))
	mux.Handle("POST /notes", authMiddleware.RequireAuth(http.HandlerFunc(h.HandleCreateNote)))
	mux.Handle("GET /notes/{id}", authMiddleware.RequireAuth(http.HandlerFunc(h.HandleViewNote)))
	mux.Handle("GET /notes/{id}/edit", authMiddleware.RequireAuth(http.HandlerFunc(h.HandleEditNotePage)))
	mux.Handle("POST /notes/{id}", authMiddleware.RequireAuth(http.HandlerFunc(h.HandleUpdateNote)))
	mux.Handle("POST /notes/{id}/delete", authMiddleware.RequireAuth(http.HandlerFunc(h.HandleDeleteNote)))
	mux.Handle("POST /notes/{id}/publish", authMiddleware.RequireAuth(http.HandlerFunc(h.HandleTogglePublish)))

	// Public notes (no auth required)
	mux.HandleFunc("GET /public/{user_id}/{note_id}", h.HandlePublicNote)

	// OAuth consent (auth required)
	mux.Handle("GET /oauth/consent", authMiddleware.RequireAuth(http.HandlerFunc(h.HandleConsentPage)))
	mux.Handle("POST /oauth/consent", authMiddleware.RequireAuth(http.HandlerFunc(h.HandleConsentDecision)))
}

// PageData contains common data passed to all templates.
type PageData struct {
	Title        string
	User         *auth.User
	FlashMessage string
	FlashType    string // "success", "error", "info"
	Error        string
}

// NotesListData contains data for the notes list page.
type NotesListData struct {
	PageData
	Notes      []notes.Note
	Page       int
	TotalPages int
	HasPrev    bool
	HasNext    bool
}

// NoteViewData contains data for the note view page.
type NoteViewData struct {
	PageData
	Note     *notes.Note
	IsOwner  bool
	ShareURL string
}

// NoteEditData contains data for the note edit page.
type NoteEditData struct {
	PageData
	Note *notes.Note
}

// PublicNoteViewData contains data for the public note view page.
type PublicNoteViewData struct {
	PageData
	Note     *PublicNote
	ShareURL string
}

// PublicNote extends Note with author info for public display.
type PublicNote struct {
	notes.Note
	Author   string
	AuthorID string
}

// ConsentData contains data for the OAuth consent page.
type ConsentData struct {
	PageData
	ClientName  string
	ClientIcon  string
	Scopes      []ScopeInfo
	State       string
	RedirectURI string
	CSRFToken   string
}

// ScopeInfo describes an OAuth scope for display.
type ScopeInfo struct {
	Name        string
	Description string
}

// ConsentResultData contains data for consent result pages.
type ConsentResultData struct {
	PageData
	ClientName  string
	RedirectURI string
	State       string
}

// LoginPageData contains data for the login page.
type LoginPageData struct {
	PageData
}

// RegisterPageData contains data for the register page.
type RegisterPageData struct {
	PageData
	Email string
}

// MagicSentData contains data for the magic link sent page.
type MagicSentData struct {
	PageData
	Email string
}

// PasswordResetData contains data for password reset pages.
type PasswordResetData struct {
	PageData
	Email   string
	Success string
	Token   string
}

// AuthErrorData contains data for auth error pages.
type AuthErrorData struct {
	PageData
	ErrorCode        string
	ErrorDescription string
}

// Handler implementations

// HandleLanding handles GET / - redirects to notes if logged in, else shows login.
func (h *WebHandler) HandleLanding(w http.ResponseWriter, r *http.Request) {
	if auth.IsAuthenticated(r.Context()) {
		http.Redirect(w, r, "/notes", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// HandleLoginPage handles GET /login - shows the login page.
func (h *WebHandler) HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	data := LoginPageData{
		PageData: PageData{
			Title: "Sign In",
		},
	}

	// Check for error in query params
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		data.Error = errMsg
	}

	if err := h.renderer.Render(w, "login.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleLogin handles POST /auth/login - processes password login form.
func (h *WebHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/login?error=Invalid+form+data", http.StatusFound)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if email == "" || password == "" {
		http.Redirect(w, r, "/login?error=Email+and+password+are+required", http.StatusFound)
		return
	}

	// Find or create user (in production, would verify password)
	user, err := h.authService.FindOrCreateByEmail(r.Context(), email)
	if err != nil {
		http.Redirect(w, r, "/login?error=Invalid+credentials", http.StatusFound)
		return
	}

	// Create session
	sessionID, err := h.sessionService.Create(r.Context(), user.ID)
	if err != nil {
		http.Redirect(w, r, "/login?error=Failed+to+create+session", http.StatusFound)
		return
	}

	auth.SetCookie(w, sessionID)
	http.Redirect(w, r, "/notes", http.StatusFound)
}

// HandleMagicLinkRequest handles POST /auth/magic - sends magic link.
func (h *WebHandler) HandleMagicLinkRequest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/login?error=Invalid+form+data", http.StatusFound)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		http.Redirect(w, r, "/login?error=Email+is+required", http.StatusFound)
		return
	}

	// Send magic link (always succeed to prevent email enumeration)
	_ = h.authService.SendMagicLink(r.Context(), email)

	// Render magic link sent page
	data := MagicSentData{
		PageData: PageData{
			Title: "Check Your Email",
		},
		Email: email,
	}

	if err := h.renderer.Render(w, "magic_sent.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleMagicLinkVerify handles GET /auth/magic/verify - verifies magic link token.
func (h *WebHandler) HandleMagicLinkVerify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		h.renderAuthError(w, "invalid_token", "Missing token", "The magic link is invalid or has expired.")
		return
	}

	user, err := h.authService.VerifyMagicToken(r.Context(), token)
	if err != nil {
		h.renderAuthError(w, "invalid_token", "Invalid or expired token", "The magic link is invalid or has expired. Please request a new one.")
		return
	}

	// Create session
	sessionID, err := h.sessionService.Create(r.Context(), user.ID)
	if err != nil {
		h.renderAuthError(w, "session_error", "Failed to create session", "Please try logging in again.")
		return
	}

	auth.SetCookie(w, sessionID)
	http.Redirect(w, r, "/notes", http.StatusFound)
}

// HandleRegisterPage handles GET /register - shows registration page.
func (h *WebHandler) HandleRegisterPage(w http.ResponseWriter, r *http.Request) {
	data := RegisterPageData{
		PageData: PageData{
			Title: "Create Account",
		},
	}

	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		data.Error = errMsg
	}

	if err := h.renderer.Render(w, "register.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleRegister handles POST /auth/register - processes registration form.
func (h *WebHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/register?error=Invalid+form+data", http.StatusFound)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	if email == "" || password == "" {
		http.Redirect(w, r, "/register?error=Email+and+password+are+required", http.StatusFound)
		return
	}

	if password != confirmPassword {
		http.Redirect(w, r, "/register?error=Passwords+do+not+match", http.StatusFound)
		return
	}

	if err := auth.ValidatePasswordStrength(password); err != nil {
		http.Redirect(w, r, "/register?error="+err.Error(), http.StatusFound)
		return
	}

	// Find or create user
	user, err := h.authService.FindOrCreateByEmail(r.Context(), email)
	if err != nil {
		http.Redirect(w, r, "/register?error=Failed+to+create+account", http.StatusFound)
		return
	}

	// Hash password (in production, would store this)
	_, err = auth.HashPassword(password)
	if err != nil {
		http.Redirect(w, r, "/register?error=Failed+to+create+account", http.StatusFound)
		return
	}

	// Create session
	sessionID, err := h.sessionService.Create(r.Context(), user.ID)
	if err != nil {
		http.Redirect(w, r, "/register?error=Failed+to+create+session", http.StatusFound)
		return
	}

	auth.SetCookie(w, sessionID)
	http.Redirect(w, r, "/notes", http.StatusFound)
}

// HandleGoogleLogin handles GET /auth/google - initiates Google OAuth.
func (h *WebHandler) HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	// Stub: In production, redirect to Google OAuth
	http.Redirect(w, r, "/login?error=Google+OAuth+not+configured", http.StatusFound)
}

// HandleGoogleCallback handles GET /auth/google/callback - Google OAuth callback.
func (h *WebHandler) HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	// Stub: In production, handle OAuth callback
	h.renderAuthError(w, "oauth_error", "Google OAuth not configured", "Google sign-in is not yet configured.")
}

// HandleLogout handles POST /auth/logout - logs out the user.
func (h *WebHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID, err := auth.GetFromRequest(r)
	if err == nil {
		_ = h.sessionService.Delete(r.Context(), sessionID)
	}

	auth.ClearCookie(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// HandlePasswordResetPage handles GET /password-reset - shows password reset form.
func (h *WebHandler) HandlePasswordResetPage(w http.ResponseWriter, r *http.Request) {
	data := PasswordResetData{
		PageData: PageData{
			Title: "Reset Password",
		},
	}

	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		data.Error = errMsg
	}

	if err := h.renderer.Render(w, "password_reset.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandlePasswordReset handles POST /auth/password-reset - sends reset email.
func (h *WebHandler) HandlePasswordReset(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/password-reset?error=Invalid+form+data", http.StatusFound)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		http.Redirect(w, r, "/password-reset?error=Email+is+required", http.StatusFound)
		return
	}

	// Send reset email (always succeed to prevent enumeration)
	_ = h.authService.SendPasswordReset(r.Context(), email)

	// Render success page
	data := PasswordResetData{
		PageData: PageData{
			Title: "Reset Password",
		},
		Email:   email,
		Success: "If that email exists, a reset link has been sent.",
	}

	if err := h.renderer.Render(w, "password_reset.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandlePasswordResetConfirmPage handles GET /auth/password-reset-confirm - shows new password form.
func (h *WebHandler) HandlePasswordResetConfirmPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		h.renderAuthError(w, "invalid_token", "Missing token", "The reset link is invalid or has expired.")
		return
	}

	data := PasswordResetData{
		PageData: PageData{
			Title: "Create New Password",
		},
		Token: token,
	}

	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		data.Error = errMsg
	}

	if err := h.renderer.Render(w, "password_reset_confirm.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandlePasswordResetConfirm handles POST /auth/password-reset-confirm - processes new password.
func (h *WebHandler) HandlePasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderAuthError(w, "invalid_form", "Invalid form data", "Please try again.")
		return
	}

	token := r.FormValue("token")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	if token == "" {
		h.renderAuthError(w, "invalid_token", "Missing token", "The reset link is invalid.")
		return
	}

	if password != confirmPassword {
		http.Redirect(w, r, "/auth/password-reset-confirm?token="+token+"&error=Passwords+do+not+match", http.StatusFound)
		return
	}

	if err := h.authService.ResetPassword(r.Context(), token, password); err != nil {
		if err == auth.ErrWeakPassword {
			http.Redirect(w, r, "/auth/password-reset-confirm?token="+token+"&error="+err.Error(), http.StatusFound)
			return
		}
		if err == auth.ErrInvalidToken {
			h.renderAuthError(w, "invalid_token", "Invalid or expired token", "Please request a new password reset.")
			return
		}
		h.renderAuthError(w, "reset_error", "Failed to reset password", "Please try again.")
		return
	}

	// Redirect to login with success message
	http.Redirect(w, r, "/login?success=Password+reset+successful", http.StatusFound)
}

// HandleNotesList handles GET /notes - shows list of notes.
func (h *WebHandler) HandleNotesList(w http.ResponseWriter, r *http.Request) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Create notes service for this user
	notesService := notes.NewService(userDB)

	// Get page from query params
	page := 1
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	limit := 12
	offset := (page - 1) * limit

	result, err := notesService.List(limit, offset)
	if err != nil {
		h.renderer.RenderError(w, http.StatusInternalServerError, "Failed to load notes")
		return
	}

	totalPages := (result.TotalCount + limit - 1) / limit
	if totalPages == 0 {
		totalPages = 1
	}

	data := NotesListData{
		PageData: PageData{
			Title: "My Notes",
			User:  &auth.User{ID: auth.GetUserID(r.Context())},
		},
		Notes:      result.Notes,
		Page:       page,
		TotalPages: totalPages,
		HasPrev:    page > 1,
		HasNext:    page < totalPages,
	}

	if err := h.renderer.Render(w, "list.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleNewNotePage handles GET /notes/new - shows new note form.
func (h *WebHandler) HandleNewNotePage(w http.ResponseWriter, r *http.Request) {
	data := NoteEditData{
		PageData: PageData{
			Title: "New Note",
			User:  &auth.User{ID: auth.GetUserID(r.Context())},
		},
	}

	if err := h.renderer.Render(w, "edit.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleCreateNote handles POST /notes - creates a new note.
func (h *WebHandler) HandleCreateNote(w http.ResponseWriter, r *http.Request) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.renderer.RenderError(w, http.StatusBadRequest, "Invalid form data")
		return
	}

	title := r.FormValue("title")
	content := r.FormValue("content")

	notesService := notes.NewService(userDB)

	note, err := notesService.Create(notes.CreateNoteParams{
		Title:   title,
		Content: content,
	})
	if err != nil {
		h.renderer.RenderError(w, http.StatusInternalServerError, "Failed to create note")
		return
	}

	http.Redirect(w, r, "/notes/"+note.ID, http.StatusFound)
}

// HandleViewNote handles GET /notes/{id} - shows a note.
func (h *WebHandler) HandleViewNote(w http.ResponseWriter, r *http.Request) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	noteID := r.PathValue("id")
	if noteID == "" {
		http.Redirect(w, r, "/notes", http.StatusFound)
		return
	}

	notesService := notes.NewService(userDB)

	note, err := notesService.Read(noteID)
	if err != nil {
		h.renderer.RenderError(w, http.StatusNotFound, "Note not found")
		return
	}

	userID := auth.GetUserID(r.Context())
	shareURL := ""
	if note.IsPublic && h.publicNotes != nil {
		shareURL = h.publicNotes.GetPublicURL(userID, note.ID)
	}

	data := NoteViewData{
		PageData: PageData{
			Title: note.Title,
			User:  &auth.User{ID: userID},
		},
		Note:     note,
		IsOwner:  true,
		ShareURL: shareURL,
	}

	if err := h.renderer.Render(w, "view.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleEditNotePage handles GET /notes/{id}/edit - shows edit note form.
func (h *WebHandler) HandleEditNotePage(w http.ResponseWriter, r *http.Request) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	noteID := r.PathValue("id")
	if noteID == "" {
		http.Redirect(w, r, "/notes", http.StatusFound)
		return
	}

	notesService := notes.NewService(userDB)

	note, err := notesService.Read(noteID)
	if err != nil {
		h.renderer.RenderError(w, http.StatusNotFound, "Note not found")
		return
	}

	data := NoteEditData{
		PageData: PageData{
			Title: "Edit: " + note.Title,
			User:  &auth.User{ID: auth.GetUserID(r.Context())},
		},
		Note: note,
	}

	if err := h.renderer.Render(w, "edit.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleUpdateNote handles POST /notes/{id} - updates a note.
func (h *WebHandler) HandleUpdateNote(w http.ResponseWriter, r *http.Request) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	noteID := r.PathValue("id")
	if noteID == "" {
		http.Redirect(w, r, "/notes", http.StatusFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.renderer.RenderError(w, http.StatusBadRequest, "Invalid form data")
		return
	}

	title := r.FormValue("title")
	content := r.FormValue("content")

	notesService := notes.NewService(userDB)

	_, err := notesService.Update(noteID, notes.UpdateNoteParams{
		Title:   &title,
		Content: &content,
	})
	if err != nil {
		h.renderer.RenderError(w, http.StatusInternalServerError, "Failed to update note")
		return
	}

	http.Redirect(w, r, "/notes/"+noteID, http.StatusFound)
}

// HandleDeleteNote handles POST /notes/{id}/delete - deletes a note.
func (h *WebHandler) HandleDeleteNote(w http.ResponseWriter, r *http.Request) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	noteID := r.PathValue("id")
	if noteID == "" {
		http.Redirect(w, r, "/notes", http.StatusFound)
		return
	}

	notesService := notes.NewService(userDB)

	if err := notesService.Delete(noteID); err != nil {
		h.renderer.RenderError(w, http.StatusInternalServerError, "Failed to delete note")
		return
	}

	http.Redirect(w, r, "/notes", http.StatusFound)
}

// HandleTogglePublish handles POST /notes/{id}/publish - toggles public visibility.
func (h *WebHandler) HandleTogglePublish(w http.ResponseWriter, r *http.Request) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	noteID := r.PathValue("id")
	if noteID == "" {
		http.Redirect(w, r, "/notes", http.StatusFound)
		return
	}

	notesService := notes.NewService(userDB)

	// Get current note to check public status
	note, err := notesService.Read(noteID)
	if err != nil {
		h.renderer.RenderError(w, http.StatusNotFound, "Note not found")
		return
	}

	// Toggle public status
	if h.publicNotes != nil {
		if err := h.publicNotes.SetPublic(r.Context(), userDB, noteID, !note.IsPublic); err != nil {
			h.renderer.RenderError(w, http.StatusInternalServerError, "Failed to update note visibility")
			return
		}
	}

	http.Redirect(w, r, "/notes/"+noteID, http.StatusFound)
}

// HandlePublicNote handles GET /public/{user_id}/{note_id} - shows a public note.
func (h *WebHandler) HandlePublicNote(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("user_id")
	noteID := r.PathValue("note_id")

	if userID == "" || noteID == "" {
		h.renderer.RenderError(w, http.StatusNotFound, "Note not found")
		return
	}

	// For stub implementation, render a placeholder public note
	// In production, this would fetch the note from the public storage
	data := PublicNoteViewData{
		PageData: PageData{
			Title: "Public Note",
		},
		Note: &PublicNote{
			Note: notes.Note{
				ID:        noteID,
				Title:     "Public Note",
				Content:   "This is a public note.",
				IsPublic:  true,
				UpdatedAt: time.Now(),
			},
			Author:   "Anonymous",
			AuthorID: userID,
		},
		ShareURL: h.baseURL + "/public/" + userID + "/" + noteID,
	}

	if err := h.renderer.Render(w, "public_view.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleConsentPage handles GET /oauth/consent - shows OAuth consent screen.
func (h *WebHandler) HandleConsentPage(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	state := r.URL.Query().Get("state")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")

	// Parse scopes
	scopes := []ScopeInfo{}
	for _, s := range strings.Split(scope, " ") {
		switch s {
		case "notes:read":
			scopes = append(scopes, ScopeInfo{
				Name:        "notes:read",
				Description: "View your notes",
			})
		case "notes:write":
			scopes = append(scopes, ScopeInfo{
				Name:        "notes:write",
				Description: "Create and edit notes",
			})
		}
	}

	data := ConsentData{
		PageData: PageData{
			Title: "Authorize Application",
			User:  &auth.User{ID: auth.GetUserID(r.Context())},
		},
		ClientName:  clientID, // In production, look up client name from registry
		ClientIcon:  "",       // In production, look up client icon
		Scopes:      scopes,
		State:       state,
		RedirectURI: redirectURI,
		CSRFToken:   "", // In production, generate CSRF token
	}

	if err := h.renderer.Render(w, "consent.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleConsentDecision handles POST /oauth/consent - processes consent decision.
func (h *WebHandler) HandleConsentDecision(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderer.RenderError(w, http.StatusBadRequest, "Invalid form data")
		return
	}

	decision := r.FormValue("decision")
	state := r.FormValue("state")
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.URL.Query().Get("client_id")

	if decision == "deny" {
		// Show denied page
		data := ConsentResultData{
			PageData: PageData{
				Title: "Access Denied",
				User:  &auth.User{ID: auth.GetUserID(r.Context())},
			},
			ClientName:  clientID,
			RedirectURI: redirectURI,
			State:       state,
		}

		if err := h.renderer.Render(w, "consent_denied.html", data); err != nil {
			http.Error(w, "Failed to render page", http.StatusInternalServerError)
		}
		return
	}

	// Grant consent
	userID := auth.GetUserID(r.Context())
	scope := r.URL.Query().Get("scope")
	scopes := strings.Split(scope, " ")

	if h.consentService != nil {
		if err := h.consentService.RecordConsent(r.Context(), userID, clientID, scopes); err != nil {
			h.renderer.RenderError(w, http.StatusInternalServerError, "Failed to record consent")
			return
		}
	}

	// Show granted page
	data := ConsentResultData{
		PageData: PageData{
			Title: "Access Granted",
			User:  &auth.User{ID: userID},
		},
		ClientName:  clientID,
		RedirectURI: redirectURI,
		State:       state,
	}

	if err := h.renderer.Render(w, "consent_granted.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// renderAuthError renders the auth error page.
func (h *WebHandler) renderAuthError(w http.ResponseWriter, errorCode, errorMsg, errorDesc string) {
	data := AuthErrorData{
		PageData: PageData{
			Title: "Authentication Error",
			Error: errorMsg,
		},
		ErrorCode:        errorCode,
		ErrorDescription: errorDesc,
	}

	if err := h.renderer.Render(w, "error.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}
