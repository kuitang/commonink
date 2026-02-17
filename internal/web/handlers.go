// Package web provides HTTP handlers for the web UI.
package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/kuitang/agent-notes/internal/s3client"
	"github.com/kuitang/agent-notes/internal/shorturl"
	"github.com/kuitang/agent-notes/internal/urlutil"
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
	shortURLSvc    *shorturl.Service
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
	shortURLSvc *shorturl.Service,
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
		shortURLSvc:    shortURLSvc,
		baseURL:        baseURL,
	}
}

// RegisterRoutes registers all web UI routes on the given mux.
func (h *WebHandler) RegisterRoutes(mux *http.ServeMux, authMiddleware *auth.Middleware) {
	// Landing page
	mux.Handle("GET /", authMiddleware.OptionalAuth(http.HandlerFunc(h.HandleLanding)))

	// Auth pages (HTML pages only - POST routes are registered by internal/auth/handlers.go)
	mux.HandleFunc("GET /login", h.HandleLoginPage)
	mux.HandleFunc("GET /register", h.HandleRegisterPage)
	mux.HandleFunc("GET /password-reset", h.HandlePasswordResetPage)
	mux.HandleFunc("GET /auth/password-reset-confirm", h.HandlePasswordResetConfirmPage)

	// Notes CRUD (auth required - redirect to login for web pages)
	mux.Handle("GET /notes", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(h.HandleNotesList)))
	mux.Handle("GET /notes/new", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(h.HandleNewNotePage)))
	mux.Handle("POST /notes", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(h.HandleCreateNote)))
	mux.Handle("GET /notes/{id}", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(h.HandleViewNote)))
	mux.Handle("GET /notes/{id}/edit", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(h.HandleEditNotePage)))
	mux.Handle("POST /notes/{id}", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(h.HandleUpdateNote)))
	mux.Handle("POST /notes/{id}/delete", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(h.HandleDeleteNote)))
	mux.Handle("POST /notes/{id}/publish", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(h.HandleTogglePublish)))

	// Public notes (no auth required)
	mux.HandleFunc("GET /public/{user_id}/{note_id}", h.HandlePublicNote)

	// Short URL redirect (no auth required)
	mux.HandleFunc("GET /pub/{short_id}", h.HandleShortURLRedirect)

	// OAuth consent page (auth required - redirect to login for web pages)
	// NOTE: POST /oauth/consent is handled by oauth.Handler.RegisterRoutes() - not here
	mux.Handle("GET /oauth/consent", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(h.HandleConsentPage)))

	// Settings - API Key management (auth required - redirect to login for web pages)
	mux.Handle("GET /settings/api-keys", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(h.HandleAPIKeySettings)))
	mux.Handle("POST /settings/api-keys", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(h.HandleCreateAPIKey)))
	mux.Handle("POST /settings/api-keys/{id}/revoke", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(h.HandleRevokeAPIKey)))

	// API Key management - short URLs (aliases for /settings/api-keys)
	mux.Handle("GET /api-keys", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(h.HandleAPIKeySettings)))
	mux.Handle("GET /api-keys/new", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(h.HandleNewAPIKeyPage)))
	mux.Handle("POST /api-keys", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(h.HandleCreateAPIKey)))
	mux.Handle("POST /api-keys/{id}/revoke", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(h.HandleRevokeAPIKey)))

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
	Notes        []notes.Note
	Page         int
	TotalPages   int
	HasPrev      bool
	HasNext      bool
	StorageUsage *notes.StorageUsageInfo
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
	ReturnTo string
	Mode     string // "" for default email mode, "password" for password mode
	Email    string // pre-filled email (for password mode)
}

// RegisterPageData contains data for the register page.
type RegisterPageData struct {
	PageData
	Email    string
	ReturnTo string
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

// getUserWithEmail returns a User with ID and Email populated from the user's database.
func getUserWithEmail(r *http.Request) *auth.User {
	userID := auth.GetUserID(r.Context())
	user := &auth.User{ID: userID}
	userDB := auth.GetUserDB(r.Context())
	if userDB != nil {
		account, err := userDB.Queries().GetAccount(r.Context(), userID)
		if err == nil {
			user.Email = account.Email
		}
	}
	return user
}

// Handler implementations

// HandleLanding handles GET / - shows landing page, or redirects to notes if logged in.
func (h *WebHandler) HandleLanding(w http.ResponseWriter, r *http.Request) {
	if auth.IsAuthenticated(r.Context()) {
		http.Redirect(w, r, "/notes", http.StatusFound)
		return
	}

	data := PageData{
		Title: "Notes for AI Agents and Humans",
	}

	if err := h.renderer.Render(w, "landing.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleLoginPage handles GET /login - shows the login page.
func (h *WebHandler) HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	data := LoginPageData{
		PageData: PageData{
			Title: "Sign In",
		},
		ReturnTo: r.URL.Query().Get("return_to"),
		Mode:     r.URL.Query().Get("mode"),
		Email:    r.URL.Query().Get("email"),
	}

	// Check for error in query params
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		data.Error = errMsg
	}

	// Check for success messages
	if success := r.URL.Query().Get("success"); success != "" {
		data.FlashMessage = success
		data.FlashType = "success"
	}

	// Check for password reset requested
	if r.URL.Query().Get("reset") == "requested" {
		data.FlashMessage = "If an account exists with that email, we've sent a password reset link. Check your inbox."
		data.FlashType = "success"
	}

	if err := h.renderer.Render(w, "auth/login.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleRegisterPage handles GET /register - shows registration page.
func (h *WebHandler) HandleRegisterPage(w http.ResponseWriter, r *http.Request) {
	data := RegisterPageData{
		PageData: PageData{
			Title: "Create Account",
		},
		ReturnTo: r.URL.Query().Get("return_to"),
	}

	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		data.Error = errMsg
	}

	if err := h.renderer.Render(w, "auth/register.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
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

	if err := h.renderer.Render(w, "auth/password_reset.html", data); err != nil {
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

	if err := h.renderer.Render(w, "auth/password_reset_confirm.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
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

	// Get storage usage info
	var storageUsage *notes.StorageUsageInfo
	usage, err := notesService.GetStorageUsage()
	if err == nil {
		storageUsage = &usage
	}

	pageData := PageData{
		Title: "My Notes",
		User:  getUserWithEmail(r),
	}
	// Check for flash error message from query params
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		pageData.FlashMessage = errMsg
		pageData.FlashType = "error"
	}

	data := NotesListData{
		PageData:     pageData,
		Notes:        result.Notes,
		Page:         page,
		TotalPages:   totalPages,
		HasPrev:      page > 1,
		HasNext:      page < totalPages,
		StorageUsage: storageUsage,
	}

	if err := h.renderer.Render(w, "notes/list.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleNewNotePage handles GET /notes/new - shows new note form.
func (h *WebHandler) HandleNewNotePage(w http.ResponseWriter, r *http.Request) {
	data := NoteEditData{
		PageData: PageData{
			Title: "New Note",
			User:  getUserWithEmail(r),
		},
	}

	if err := h.renderer.Render(w, "notes/edit.html", data); err != nil {
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
		if errors.Is(err, notes.ErrStorageLimitExceeded) {
			http.Redirect(w, r, "/notes?error="+fmt.Sprintf("Storage limit exceeded. Free tier is limited to %.0f MB.", float64(notes.StorageLimitBytes)/(1024*1024)), http.StatusFound)
			return
		}
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
		shareURL = h.publicNotes.GetShortURL(r.Context(), userID, note.ID, h.requestOrigin(r))
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

	if err := h.renderer.Render(w, "notes/view.html", data); err != nil {
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
			User:  getUserWithEmail(r),
		},
		Note: note,
	}

	if err := h.renderer.Render(w, "notes/edit.html", data); err != nil {
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
		if errors.Is(err, notes.ErrStorageLimitExceeded) {
			http.Redirect(w, r, "/notes/"+noteID+"/edit?error="+fmt.Sprintf("Storage limit exceeded. Free tier is limited to %.0f MB.", float64(notes.StorageLimitBytes)/(1024*1024)), http.StatusFound)
			return
		}
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

// HandleShortURLRedirect handles GET /pub/{short_id} - renders public note inline (no redirect).
func (h *WebHandler) HandleShortURLRedirect(w http.ResponseWriter, r *http.Request) {
	shortID := r.PathValue("short_id")
	if shortID == "" {
		http.NotFound(w, r)
		return
	}

	if h.shortURLSvc == nil {
		http.Error(w, "Short URL service not configured", http.StatusInternalServerError)
		return
	}

	fullPath, err := h.shortURLSvc.Resolve(r.Context(), shortID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Parse user_id and note_id from fullPath ("/public/{user_id}/{note_id}")
	parts := strings.Split(strings.TrimPrefix(fullPath, "/"), "/")
	if len(parts) != 3 || parts[0] != "public" {
		http.NotFound(w, r)
		return
	}
	userID := parts[1]
	noteID := parts[2]

	// Render the public note inline at /pub/{short_id}
	h.renderPublicNote(w, r, userID, noteID, urlutil.BuildAbsolute(h.requestOrigin(r), "/pub/"+shortID))
}

// HandlePublicNote handles GET /public/{user_id}/{note_id} - redirects to short URL if available.
func (h *WebHandler) HandlePublicNote(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("user_id")
	noteID := r.PathValue("note_id")

	if userID == "" || noteID == "" {
		h.renderer.RenderError(w, http.StatusNotFound, "Note not found")
		return
	}

	// If a short URL exists, 301 redirect to /pub/{short_id} so the user sees the short URL
	fullPath := "/public/" + userID + "/" + noteID
	if h.shortURLSvc != nil {
		shortURLObj, err := h.shortURLSvc.GetByFullPath(r.Context(), fullPath)
		if err == nil && shortURLObj != nil {
			http.Redirect(w, r, "/pub/"+shortURLObj.ShortID, http.StatusMovedPermanently)
			return
		}
	}

	// Fallback: render inline if no short URL exists
	h.renderPublicNote(w, r, userID, noteID, urlutil.BuildAbsolute(h.requestOrigin(r), fullPath))
}

func (h *WebHandler) requestOrigin(r *http.Request) string {
	return urlutil.OriginFromRequest(r, h.baseURL)
}

// renderPublicNote renders a public note page with the minimal-chrome template.
func (h *WebHandler) renderPublicNote(w http.ResponseWriter, r *http.Request, userID, noteID, shareURL string) {
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
		ShareURL: shareURL,
	}

	if err := h.renderer.RenderPublic(w, "notes/public_view.html", data); err != nil {
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
			User:  getUserWithEmail(r),
		},
		ClientName:  clientID, // In production, look up client name from registry
		ClientIcon:  "",       // In production, look up client icon
		Scopes:      scopes,
		State:       state,
		RedirectURI: redirectURI,
		CSRFToken:   "", // In production, generate CSRF token
	}

	if err := h.renderer.Render(w, "oauth/consent.html", data); err != nil {
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
				User:  getUserWithEmail(r),
			},
			ClientName:  clientID,
			RedirectURI: redirectURI,
			State:       state,
		}

		if err := h.renderer.Render(w, "oauth/consent_denied.html", data); err != nil {
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

	if err := h.renderer.Render(w, "oauth/consent_granted.html", data); err != nil {
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

	if err := h.renderer.Render(w, "auth/error.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}
