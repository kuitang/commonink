// Package web provides HTTP handlers for the web UI.
package web

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/billing"
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
	billingService billing.BillingService
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
	billingService billing.BillingService,
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
		billingService: billingService,
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

	// Account settings (auth required)
	mux.Handle("GET /settings/account", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(h.HandleAccountSettings)))
	mux.Handle("POST /settings/set-password", authMiddleware.RequireAuth(http.HandlerFunc(h.HandleSetPassword)))
	mux.Handle("POST /settings/link-google", authMiddleware.RequireAuth(http.HandlerFunc(h.HandleLinkGoogle)))
	mux.Handle("POST /settings/unlink-google", authMiddleware.RequireAuth(http.HandlerFunc(h.HandleUnlinkGoogle)))

	// Billing routes
	mux.Handle("GET /pricing", authMiddleware.OptionalAuth(http.HandlerFunc(h.HandlePricing)))
	mux.Handle("POST /billing/checkout", authMiddleware.OptionalAuth(http.HandlerFunc(h.HandleCreateCheckout)))
	mux.Handle("GET /billing/success", authMiddleware.OptionalAuth(http.HandlerFunc(h.HandleBillingSuccess)))
	mux.HandleFunc("POST /billing/webhook", h.HandleBillingWebhook)
	mux.Handle("POST /billing/portal", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(h.HandleBillingPortal)))
	mux.Handle("GET /settings/billing", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(h.HandleBillingSettings)))

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

// PricingPageData contains data for the pricing page.
type PricingPageData struct {
	PageData
	StripePublishableKey string
	IsMockBilling        bool
}

// BillingSuccessData contains data for the billing success page.
type BillingSuccessData struct {
	PageData
	SessionStatus string
	CustomerEmail string
}

// BillingSettingsData contains data for the billing settings page.
type BillingSettingsData struct {
	PageData
	SubscriptionStatus string
	StorageUsage       *notes.StorageUsageInfo
}

// AccountSettingsData contains data for the account settings page.
type AccountSettingsData struct {
	PageData
	HasPassword bool
	HasGoogle   bool
}

// storageLimitForRequest returns the storage limit for the current user based on subscription status.
func storageLimitForRequest(r *http.Request) int64 {
	userID := auth.GetUserID(r.Context())
	userDB := auth.GetUserDB(r.Context())
	if userDB != nil {
		account, err := userDB.Queries().GetAccount(r.Context(), userID)
		if err == nil && account.SubscriptionStatus.Valid {
			return notes.StorageLimitForStatus(account.SubscriptionStatus.String)
		}
	}
	return notes.FreeStorageLimitBytes
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
			if account.SubscriptionStatus.Valid {
				user.SubscriptionStatus = account.SubscriptionStatus.String
			}
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
		Email:    r.URL.Query().Get("email"),
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
	notesService := notes.NewService(userDB, storageLimitForRequest(r))

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

	notesService := notes.NewService(userDB, storageLimitForRequest(r))

	note, err := notesService.Create(notes.CreateNoteParams{
		Title:   title,
		Content: content,
	})
	if err != nil {
		if errors.Is(err, notes.ErrStorageLimitExceeded) {
			http.Redirect(w, r, "/notes?error="+fmt.Sprintf("Storage limit exceeded. Free tier is limited to %.0f MB. Upgrade to Pro for unlimited storage.", float64(notes.FreeStorageLimitBytes)/(1024*1024)), http.StatusFound)
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

	notesService := notes.NewService(userDB, storageLimitForRequest(r))

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

	notesService := notes.NewService(userDB, storageLimitForRequest(r))

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

	notesService := notes.NewService(userDB, storageLimitForRequest(r))

	_, err := notesService.Update(noteID, notes.UpdateNoteParams{
		Title:   &title,
		Content: &content,
	})
	if err != nil {
		if errors.Is(err, notes.ErrStorageLimitExceeded) {
			http.Redirect(w, r, "/notes/"+noteID+"/edit?error="+fmt.Sprintf("Storage limit exceeded. Free tier is limited to %.0f MB. Upgrade to Pro for unlimited storage.", float64(notes.FreeStorageLimitBytes)/(1024*1024)), http.StatusFound)
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

	notesService := notes.NewService(userDB, storageLimitForRequest(r))

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

	notesService := notes.NewService(userDB, storageLimitForRequest(r))

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

// =============================================================================
// Billing Handlers
// =============================================================================

// HandlePricing handles GET /pricing - shows the pricing page.
func (h *WebHandler) HandlePricing(w http.ResponseWriter, r *http.Request) {
	data := PricingPageData{
		PageData: PageData{
			Title: "Pricing",
		},
	}

	if h.billingService != nil {
		data.StripePublishableKey = h.billingService.PublishableKey()
		data.IsMockBilling = h.billingService.IsMock()
	} else {
		data.IsMockBilling = true
	}

	if auth.IsAuthenticated(r.Context()) {
		data.User = getUserWithEmail(r)
	}

	if err := h.renderer.Render(w, "billing/pricing.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleCreateCheckout handles POST /billing/checkout - creates a Stripe checkout session.
func (h *WebHandler) HandleCreateCheckout(w http.ResponseWriter, r *http.Request) {
	if h.billingService == nil {
		http.Error(w, `{"error":"billing not configured"}`, http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Email string `json:"email"`
		Plan  string `json:"plan"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	var userID, email string
	if auth.IsAuthenticated(r.Context()) {
		userID = auth.GetUserID(r.Context())
		user := getUserWithEmail(r)
		if user != nil {
			email = user.Email
		}
	} else {
		if req.Email == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "email is required"})
			return
		}
		email = req.Email
	}

	clientSecret, err := h.billingService.CreateCheckoutSession(r.Context(), userID, email, req.Plan, h.requestOrigin(r))
	if err != nil {
		log.Printf("[BILLING] CreateCheckoutSession error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to create checkout session"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"clientSecret": clientSecret})
}

// HandleBillingSuccess handles GET /billing/success - shows the billing success page.
func (h *WebHandler) HandleBillingSuccess(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")

	data := BillingSuccessData{
		PageData: PageData{
			Title: "Payment Result",
		},
	}

	if auth.IsAuthenticated(r.Context()) {
		data.User = getUserWithEmail(r)
	}

	if sessionID != "" && h.billingService != nil {
		status, customerEmail, err := h.billingService.GetSessionStatus(r.Context(), sessionID)
		if err != nil {
			log.Printf("[BILLING] GetSessionStatus error: %v", err)
		} else {
			data.SessionStatus = status
			data.CustomerEmail = customerEmail
		}
	}

	if err := h.renderer.Render(w, "billing/success.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleBillingWebhook handles POST /billing/webhook - processes Stripe webhook events.
func (h *WebHandler) HandleBillingWebhook(w http.ResponseWriter, r *http.Request) {
	if h.billingService == nil {
		http.Error(w, "billing not configured", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	sigHeader := r.Header.Get("Stripe-Signature")

	if err := h.billingService.HandleWebhook(body, sigHeader); err != nil {
		log.Printf("[BILLING] Webhook error: %v", err)
		http.Error(w, "webhook processing failed", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HandleBillingPortal handles POST /billing/portal - redirects to Stripe customer portal.
func (h *WebHandler) HandleBillingPortal(w http.ResponseWriter, r *http.Request) {
	if h.billingService == nil {
		http.Error(w, "billing not configured", http.StatusServiceUnavailable)
		return
	}

	userID := auth.GetUserID(r.Context())

	// Look up stripe_customer_id from the user's account record
	var stripeCustomerID string
	userDB := auth.GetUserDB(r.Context())
	if userDB != nil {
		var id sql.NullString
		err := userDB.DB().QueryRowContext(r.Context(),
			`SELECT stripe_customer_id FROM account WHERE user_id = ?`, userID,
		).Scan(&id)
		if err == nil && id.Valid {
			stripeCustomerID = id.String
		}
	}

	if stripeCustomerID == "" {
		http.Redirect(w, r, "/pricing", http.StatusFound)
		return
	}

	returnURL := h.requestOrigin(r) + "/settings/billing"
	portalURL, err := h.billingService.CreatePortalSession(r.Context(), stripeCustomerID, returnURL)
	if err != nil {
		log.Printf("[BILLING] CreatePortalSession error: %v", err)
		h.renderer.RenderError(w, http.StatusInternalServerError, "Failed to create billing portal session")
		return
	}

	http.Redirect(w, r, portalURL, http.StatusFound)
}

// HandleBillingSettings handles GET /settings/billing - shows billing settings page.
func (h *WebHandler) HandleBillingSettings(w http.ResponseWriter, r *http.Request) {
	user := getUserWithEmail(r)

	data := BillingSettingsData{
		PageData: PageData{
			Title: "Billing Settings",
			User:  user,
		},
		SubscriptionStatus: user.SubscriptionStatus,
	}

	// Get storage usage
	userDB := auth.GetUserDB(r.Context())
	if userDB != nil {
		notesService := notes.NewService(userDB, storageLimitForRequest(r))
		usage, err := notesService.GetStorageUsage()
		if err == nil {
			data.StorageUsage = &usage
		}
	}

	if err := h.renderer.Render(w, "billing/settings.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// =============================================================================
// Account Settings Handlers
// =============================================================================

// HandleAccountSettings handles GET /settings/account - shows account settings page.
func (h *WebHandler) HandleAccountSettings(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r.Context())
	account, err := h.authService.GetAccountInfo(r.Context(), userID)
	if err != nil {
		log.Printf("[SETTINGS] GetAccountInfo failed for user=%s: %v", userID, err)
		h.renderer.RenderError(w, http.StatusInternalServerError, "Failed to load account settings")
		return
	}

	data := AccountSettingsData{
		PageData: PageData{
			Title: "Account Settings",
			User:  getUserWithEmail(r),
		},
		HasPassword: account.PasswordHash.Valid && account.PasswordHash.String != "",
		HasGoogle:   account.GoogleSub.Valid && account.GoogleSub.String != "",
	}

	if success := r.URL.Query().Get("success"); success != "" {
		switch success {
		case "google_linked":
			data.FlashMessage = "Google account linked successfully."
		case "google_unlinked":
			data.FlashMessage = "Google account unlinked."
		case "password_set":
			data.FlashMessage = "Password updated successfully."
		default:
			data.FlashMessage = success
		}
		data.FlashType = "success"
	}
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		data.Error = errMsg
	}

	if err := h.renderer.Render(w, "settings/account.html", data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

// HandleSetPassword handles POST /settings/set-password - sets or changes the user's password.
func (h *WebHandler) HandleSetPassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/settings/account?error=Invalid+form+data", http.StatusSeeOther)
		return
	}

	userID := auth.GetUserID(r.Context())
	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	if newPassword == "" {
		http.Redirect(w, r, "/settings/account?error=New+password+is+required", http.StatusSeeOther)
		return
	}
	if newPassword != confirmPassword {
		http.Redirect(w, r, "/settings/account?error=Passwords+do+not+match", http.StatusSeeOther)
		return
	}

	// Check if user already has a password — if so, verify current password
	account, err := h.authService.GetAccountInfo(r.Context(), userID)
	if err != nil {
		log.Printf("[SETTINGS] GetAccountInfo failed for user=%s: %v", userID, err)
		http.Redirect(w, r, "/settings/account?error=Failed+to+load+account", http.StatusSeeOther)
		return
	}

	if account.PasswordHash.Valid && account.PasswordHash.String != "" {
		if currentPassword == "" {
			http.Redirect(w, r, "/settings/account?error=Current+password+is+required", http.StatusSeeOther)
			return
		}
		if !h.authService.VerifyPasswordHash(currentPassword, account.PasswordHash.String) {
			http.Redirect(w, r, "/settings/account?error=Current+password+is+incorrect", http.StatusSeeOther)
			return
		}
	}

	if err := h.authService.SetPassword(r.Context(), userID, newPassword); err != nil {
		if errors.Is(err, auth.ErrWeakPassword) {
			http.Redirect(w, r, "/settings/account?error=Password+must+be+at+least+8+characters", http.StatusSeeOther)
			return
		}
		log.Printf("[SETTINGS] SetPassword failed for user=%s: %v", userID, err)
		http.Redirect(w, r, "/settings/account?error=Failed+to+set+password", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/settings/account?success=password_set", http.StatusSeeOther)
}

// HandleLinkGoogle handles POST /settings/link-google - initiates Google account linking.
func (h *WebHandler) HandleLinkGoogle(w http.ResponseWriter, r *http.Request) {
	// Set intent cookie so HandleGoogleCallback knows this is a link flow
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_intent",
		Value:    "link",
		Path:     "/",
		HttpOnly: true,
		Secure:   auth.GetSecureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes
	})

	// Redirect to the Google login handler which will start OIDC flow
	http.Redirect(w, r, "/auth/google?return_to=/settings/account", http.StatusSeeOther)
}

// HandleUnlinkGoogle handles POST /settings/unlink-google - unlinks Google account.
func (h *WebHandler) HandleUnlinkGoogle(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r.Context())

	// Verify account has a password before unlinking (prevent lockout)
	account, err := h.authService.GetAccountInfo(r.Context(), userID)
	if err != nil {
		log.Printf("[SETTINGS] GetAccountInfo failed for user=%s: %v", userID, err)
		http.Redirect(w, r, "/settings/account?error=Failed+to+load+account", http.StatusSeeOther)
		return
	}

	if !account.PasswordHash.Valid || account.PasswordHash.String == "" {
		http.Redirect(w, r, "/settings/account?error=Set+a+password+before+unlinking+Google", http.StatusSeeOther)
		return
	}

	if err := h.authService.UnlinkGoogleAccount(r.Context(), userID); err != nil {
		log.Printf("[SETTINGS] UnlinkGoogleAccount failed for user=%s: %v", userID, err)
		http.Redirect(w, r, "/settings/account?error=Failed+to+unlink+Google+account", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/settings/account?success=google_unlinked", http.StatusSeeOther)
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
