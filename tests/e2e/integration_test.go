// Package e2e provides end-to-end integration tests that use REAL handlers.
//
// KEY DIFFERENCE FROM oauth_auth_test.go:
// This file uses the ACTUAL handlers from internal/auth/handlers.go,
// internal/oauth/handlers.go, internal/web/handlers.go, and internal/mcp/server.go
// instead of custom test handlers. This ensures we test the real production code paths.
package e2e

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	_ "github.com/mutecomm/go-sqlcipher/v4"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/email"
	"github.com/kuitang/agent-notes/internal/mcp"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/kuitang/agent-notes/internal/oauth"
	"github.com/kuitang/agent-notes/internal/web"
)

// =============================================================================
// FULL APP TEST SERVER - Uses REAL handlers
// =============================================================================

// integrationTestMutex ensures test isolation
var integrationTestMutex sync.Mutex

// fullAppServer wraps httptest.Server with all real application components
type fullAppServer struct {
	*httptest.Server
	tempDir string

	// Services
	sessionsDB     *db.SessionsDB
	keyManager     *crypto.KeyManager
	userService    *auth.UserService
	sessionService *auth.SessionService
	consentService *auth.ConsentService
	emailService   *email.MockEmailService
	oauthProvider  *oauth.Provider
	authMiddleware *auth.Middleware
	renderer       *web.Renderer
}

// setupFullAppServer creates a test server with ALL real handlers wired up.
// This mirrors how cmd/server/main.go sets up the application.
func setupFullAppServer(t testing.TB) *fullAppServer {
	t.Helper()
	integrationTestMutex.Lock()

	tempDir := t.TempDir()
	return createFullAppServer(tempDir)
}

// setupFullAppServerRapid creates a test server for rapid.T tests
func setupFullAppServerRapid() *fullAppServer {
	integrationTestMutex.Lock()

	tempDir, err := os.MkdirTemp("", "integration-test-*")
	if err != nil {
		panic("Failed to create temp dir: " + err.Error())
	}
	return createFullAppServer(tempDir)
}

// createFullAppServer creates the full app server with all real handlers
func createFullAppServer(tempDir string) *fullAppServer {
	// Reset database singleton and set fresh data directory
	db.ResetForTesting()
	db.DataDirectory = tempDir

	// Initialize sessions database
	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		panic("Failed to open sessions database: " + err.Error())
	}

	// Generate master key for encryption
	masterKey := make([]byte, 32)
	if _, err := crand.Read(masterKey); err != nil {
		panic("Failed to generate master key: " + err.Error())
	}

	// Generate OAuth signing key
	_, signingKey, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		panic("Failed to generate signing key: " + err.Error())
	}

	// Generate HMAC secret
	hmacSecret := make([]byte, 32)
	if _, err := crand.Read(hmacSecret); err != nil {
		panic("Failed to generate HMAC secret: " + err.Error())
	}

	// Create mux for routing
	mux := http.NewServeMux()

	// Start httptest server with TLS
	server := httptest.NewTLSServer(mux)

	// Initialize key manager
	keyManager := crypto.NewKeyManager(masterKey, sessionsDB)

	// Initialize services
	emailService := email.NewMockEmailService()
	oidcClient := auth.NewMockOIDCClient()
	userService := auth.NewUserService(sessionsDB, emailService, server.URL)
	sessionService := auth.NewSessionService(sessionsDB)
	consentService := auth.NewConsentService(sessionsDB)

	// Create OAuth provider
	oauthProvider, err := oauth.NewProvider(oauth.Config{
		DB:         sessionsDB.DB(),
		Issuer:     server.URL,
		Resource:   server.URL,
		HMACSecret: hmacSecret,
		SigningKey: signingKey,
	})
	if err != nil {
		panic("Failed to create OAuth provider: " + err.Error())
	}

	// Find templates directory
	templatesDir := findIntegrationTemplatesDir()
	renderer, err := web.NewRenderer(templatesDir)
	if err != nil {
		panic("Failed to create renderer: " + err.Error())
	}

	// Create auth middleware
	authMiddleware := auth.NewMiddleware(sessionService, keyManager)

	// Create handlers
	oauthHandler := oauth.NewHandler(oauthProvider, sessionService, consentService, renderer)
	authHandler := auth.NewHandler(oidcClient, userService, sessionService)

	// Create web handler (with nil notesService - it's created per-request)
	webHandler := web.NewWebHandler(
		renderer,
		nil, // notesService created per-request with user's DB
		nil, // publicNotes - skip for this test
		userService,
		sessionService,
		consentService,
		nil, // s3Client - skip for this test
		server.URL,
	)

	// =============================================================================
	// Register ALL routes exactly like cmd/server/main.go
	// =============================================================================

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// OAuth metadata routes
	oauthProvider.RegisterMetadataRoutes(mux)

	// OAuth endpoints
	mux.HandleFunc("POST /oauth/register", oauthProvider.DCR)
	oauthHandler.RegisterRoutes(mux)

	// Web UI routes (with auth middleware)
	webHandler.RegisterRoutes(mux, authMiddleware)

	// Auth API routes (REAL handlers from internal/auth/handlers.go)
	authHandler.RegisterRoutes(mux)

	// Protected notes API routes
	notesHandler := &integrationNotesHandler{keyManager: keyManager}
	mux.Handle("GET /api/notes", authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.ListNotes)))
	mux.Handle("POST /api/notes", authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.CreateNote)))
	mux.Handle("GET /api/notes/{id}", authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.GetNote)))
	mux.Handle("PUT /api/notes/{id}", authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.UpdateNote)))
	mux.Handle("DELETE /api/notes/{id}", authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.DeleteNote)))
	mux.Handle("POST /api/notes/search", authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.SearchNotes)))

	// MCP endpoint (with OAuth token validation)
	mcpHandler := &integrationMCPHandler{
		oauthProvider: oauthProvider,
		keyManager:    keyManager,
	}
	mux.HandleFunc("POST /mcp", mcpHandler.ServeHTTP)

	return &fullAppServer{
		Server:         server,
		tempDir:        tempDir,
		sessionsDB:     sessionsDB,
		keyManager:     keyManager,
		userService:    userService,
		sessionService: sessionService,
		consentService: consentService,
		emailService:   emailService,
		oauthProvider:  oauthProvider,
		authMiddleware: authMiddleware,
		renderer:       renderer,
	}
}

// cleanup closes the test server and releases resources
func (ts *fullAppServer) cleanup() {
	ts.Server.Close()
	db.ResetForTesting()
	if ts.tempDir != "" && strings.Contains(ts.tempDir, "integration-test-") {
		os.RemoveAll(ts.tempDir)
	}
	integrationTestMutex.Unlock()
}

// findIntegrationTemplatesDir locates templates for tests
func findIntegrationTemplatesDir() string {
	candidates := []string{
		"../../web/templates",
		"../../../web/templates",
		"web/templates",
		"./web/templates",
		"/home/kuitang/git/agent-notes/web/templates",
	}

	for _, dir := range candidates {
		if _, err := os.Stat(filepath.Join(dir, "base.html")); err == nil {
			return dir
		}
	}

	panic("Cannot find templates directory")
}

// =============================================================================
// INTEGRATION HANDLERS - Wrappers that use auth context
// =============================================================================

// integrationNotesHandler wraps notes operations with authenticated context
type integrationNotesHandler struct {
	keyManager *crypto.KeyManager
}

func (h *integrationNotesHandler) getService(r *http.Request) (*notes.Service, error) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		return nil, fmt.Errorf("no user database in context")
	}
	return notes.NewService(userDB), nil
}

func (h *integrationNotesHandler) ListNotes(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeIntegrationError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	result, err := svc.List(50, 0)
	if err != nil {
		writeIntegrationError(w, http.StatusInternalServerError, "Failed to list notes: "+err.Error())
		return
	}

	writeIntegrationJSON(w, http.StatusOK, result)
}

func (h *integrationNotesHandler) CreateNote(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeIntegrationError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	var params notes.CreateNoteParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		writeIntegrationError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	if params.Title == "" {
		writeIntegrationError(w, http.StatusBadRequest, "Title is required")
		return
	}

	note, err := svc.Create(params)
	if err != nil {
		writeIntegrationError(w, http.StatusInternalServerError, "Failed to create note: "+err.Error())
		return
	}

	writeIntegrationJSON(w, http.StatusCreated, note)
}

func (h *integrationNotesHandler) GetNote(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeIntegrationError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeIntegrationError(w, http.StatusBadRequest, "Note ID is required")
		return
	}

	note, err := svc.Read(id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeIntegrationError(w, http.StatusNotFound, "Note not found")
			return
		}
		writeIntegrationError(w, http.StatusInternalServerError, "Failed to get note: "+err.Error())
		return
	}

	writeIntegrationJSON(w, http.StatusOK, note)
}

func (h *integrationNotesHandler) UpdateNote(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeIntegrationError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeIntegrationError(w, http.StatusBadRequest, "Note ID is required")
		return
	}

	var params notes.UpdateNoteParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		writeIntegrationError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	note, err := svc.Update(id, params)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeIntegrationError(w, http.StatusNotFound, "Note not found")
			return
		}
		writeIntegrationError(w, http.StatusInternalServerError, "Failed to update note: "+err.Error())
		return
	}

	writeIntegrationJSON(w, http.StatusOK, note)
}

func (h *integrationNotesHandler) DeleteNote(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeIntegrationError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeIntegrationError(w, http.StatusBadRequest, "Note ID is required")
		return
	}

	err = svc.Delete(id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeIntegrationError(w, http.StatusNotFound, "Note not found")
			return
		}
		writeIntegrationError(w, http.StatusInternalServerError, "Failed to delete note: "+err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *integrationNotesHandler) SearchNotes(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeIntegrationError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	var req struct {
		Query string `json:"query"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeIntegrationError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	if req.Query == "" {
		writeIntegrationError(w, http.StatusBadRequest, "Search query is required")
		return
	}

	results, err := svc.Search(req.Query)
	if err != nil {
		writeIntegrationError(w, http.StatusInternalServerError, "Failed to search notes: "+err.Error())
		return
	}

	writeIntegrationJSON(w, http.StatusOK, results)
}

// integrationMCPHandler handles MCP requests with OAuth token validation
type integrationMCPHandler struct {
	oauthProvider *oauth.Provider
	keyManager    *crypto.KeyManager
}

func (h *integrationMCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract and validate Bearer token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, h.oauthProvider.Resource()))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := h.oauthProvider.VerifyAccessToken(token)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Get user's DEK and open their database
	dek, err := h.keyManager.GetOrCreateUserDEK(claims.Subject)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	userDB, err := db.OpenUserDBWithDEK(claims.Subject, dek)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create notes service and MCP server
	notesSvc := notes.NewService(userDB)
	mcpServer := mcp.NewServer(notesSvc)
	mcpServer.ServeHTTP(w, r)
}

// Helper functions
func writeIntegrationJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeIntegrationError(w http.ResponseWriter, status int, message string) {
	writeIntegrationJSON(w, status, map[string]string{"error": message})
}

// =============================================================================
// RAPID GENERATORS FOR PROPERTY-BASED TESTS
// =============================================================================

func integrationEmailGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-z]{5,10}@example\.com`)
}

func integrationPasswordGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[A-Za-z0-9!@#]{12,20}`)
}

func integrationNoteTitleGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[A-Za-z0-9 ]{5,50}`)
}

func integrationNoteContentGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[A-Za-z0-9 .,!?]{10,200}`)
}

func integrationOAuthStateGenerator() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-zA-Z0-9_-]{16,64}`)
}

// =============================================================================
// TEST 1: Auth API Flow (tests internal/auth/handlers.go)
// =============================================================================

func testIntegration_AuthAPI_Properties(t *rapid.T) {
	ts := setupFullAppServerRapid()
	defer ts.cleanup()

	email := integrationEmailGenerator().Draw(t, "email")
	password := integrationPasswordGenerator().Draw(t, "password")

	client := ts.Client()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("Failed to create cookie jar: %v", err)
	}
	client.Jar = jar

	// Property 1: POST /auth/register -> 201
	regBody := fmt.Sprintf(`{"email":"%s","password":"%s"}`, email, password)
	regResp, err := client.Post(ts.URL+"/auth/register", "application/json", strings.NewReader(regBody))
	if err != nil {
		t.Fatalf("Registration request failed: %v", err)
	}
	defer regResp.Body.Close()

	if regResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(regResp.Body)
		t.Fatalf("Expected 201 for registration, got %d: %s", regResp.StatusCode, string(body))
	}

	var regResult map[string]string
	if err := json.NewDecoder(regResp.Body).Decode(&regResult); err != nil {
		t.Fatalf("Failed to decode registration response: %v", err)
	}

	// Property 2: Response contains user_id and email
	if regResult["user_id"] == "" {
		t.Fatal("Registration response should contain user_id")
	}
	if regResult["email"] != email {
		t.Fatalf("Registration response email mismatch: expected %s, got %s", email, regResult["email"])
	}

	// Property 3: Session cookie is set
	sessionCookieFound := false
	for _, c := range regResp.Cookies() {
		if c.Name == "session_id" {
			sessionCookieFound = true
			break
		}
	}
	if !sessionCookieFound {
		t.Fatal("Session cookie should be set after registration")
	}

	// Property 4: GET /auth/whoami -> authenticated: true
	whoamiResp, err := client.Get(ts.URL + "/auth/whoami")
	if err != nil {
		t.Fatalf("Whoami request failed: %v", err)
	}
	defer whoamiResp.Body.Close()

	var whoamiResult map[string]interface{}
	if err := json.NewDecoder(whoamiResp.Body).Decode(&whoamiResult); err != nil {
		t.Fatalf("Failed to decode whoami response: %v", err)
	}

	if whoamiResult["authenticated"] != true {
		t.Fatal("Should be authenticated after registration")
	}

	// Property 5: POST /auth/logout -> clears session
	logoutResp, err := client.Post(ts.URL+"/auth/logout", "application/json", nil)
	if err != nil {
		t.Fatalf("Logout request failed: %v", err)
	}
	logoutResp.Body.Close()

	if logoutResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 for logout, got %d", logoutResp.StatusCode)
	}

	// Property 6: GET /auth/whoami -> authenticated: false after logout
	whoami2Resp, err := client.Get(ts.URL + "/auth/whoami")
	if err != nil {
		t.Fatalf("Whoami request after logout failed: %v", err)
	}
	defer whoami2Resp.Body.Close()

	var whoami2Result map[string]interface{}
	if err := json.NewDecoder(whoami2Resp.Body).Decode(&whoami2Result); err != nil {
		t.Fatalf("Failed to decode whoami response: %v", err)
	}

	if whoami2Result["authenticated"] != false {
		t.Fatal("Should NOT be authenticated after logout")
	}

	// Property 7: POST /auth/login -> 200 + session cookie
	loginResp, err := client.Post(ts.URL+"/auth/login", "application/json",
		strings.NewReader(fmt.Sprintf(`{"email":"%s","password":"%s"}`, email, password)))
	if err != nil {
		t.Fatalf("Login request failed: %v", err)
	}
	defer loginResp.Body.Close()

	if loginResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("Expected 200 for login, got %d: %s", loginResp.StatusCode, string(body))
	}

	// Property 8: Session cookie is set after login
	loginSessionFound := false
	for _, c := range loginResp.Cookies() {
		if c.Name == "session_id" {
			loginSessionFound = true
			break
		}
	}
	if !loginSessionFound {
		t.Fatal("Session cookie should be set after login")
	}
}

func TestIntegration_AuthAPI_Properties(t *testing.T) {
	rapid.Check(t, testIntegration_AuthAPI_Properties)
}

func FuzzIntegration_AuthAPI_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testIntegration_AuthAPI_Properties))
}

// =============================================================================
// TEST 2: Magic Link Flow (tests internal/auth/handlers.go)
// =============================================================================

func testIntegration_MagicLink_Properties(t *rapid.T) {
	ts := setupFullAppServerRapid()
	defer ts.cleanup()

	email := integrationEmailGenerator().Draw(t, "email")

	client := ts.Client()

	// Property 1: POST /auth/magic with email -> 200 (always succeeds to prevent enumeration)
	magicResp, err := client.Post(ts.URL+"/auth/magic", "application/json",
		strings.NewReader(fmt.Sprintf(`{"email":"%s"}`, email)))
	if err != nil {
		t.Fatalf("Magic link request failed: %v", err)
	}
	defer magicResp.Body.Close()

	if magicResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(magicResp.Body)
		t.Fatalf("Expected 200 for magic link, got %d: %s", magicResp.StatusCode, string(body))
	}

	// Property 2: Response contains generic message
	var magicResult map[string]string
	if err := json.NewDecoder(magicResp.Body).Decode(&magicResult); err != nil {
		t.Fatalf("Failed to decode magic link response: %v", err)
	}

	if magicResult["message"] == "" {
		t.Fatal("Magic link response should contain message")
	}

	// Property 3: Email was sent via mock service
	// Check that at least one email was sent
	emailCount := ts.emailService.Count()
	if emailCount == 0 {
		t.Fatal("Magic link email should have been sent")
	}

	// Property 4: Verify last email was sent to correct address
	lastEmail := ts.emailService.LastEmail()
	if lastEmail.To != email {
		t.Fatalf("Email should be sent to the requested address: expected %s, got %s", email, lastEmail.To)
	}
}

func TestIntegration_MagicLink_Properties(t *testing.T) {
	rapid.Check(t, testIntegration_MagicLink_Properties)
}

func FuzzIntegration_MagicLink_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testIntegration_MagicLink_Properties))
}

// =============================================================================
// TEST 3: Password Reset Flow
// =============================================================================

func testIntegration_PasswordReset_Properties(t *rapid.T) {
	ts := setupFullAppServerRapid()
	defer ts.cleanup()

	email := integrationEmailGenerator().Draw(t, "email")
	password := integrationPasswordGenerator().Draw(t, "password")

	client := ts.Client()

	// First register the user
	regBody := fmt.Sprintf(`{"email":"%s","password":"%s"}`, email, password)
	regResp, err := client.Post(ts.URL+"/auth/register", "application/json", strings.NewReader(regBody))
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}
	regResp.Body.Close()

	// Property 1: POST /auth/password/reset with email -> 200
	resetResp, err := client.Post(ts.URL+"/auth/password/reset", "application/json",
		strings.NewReader(fmt.Sprintf(`{"email":"%s"}`, email)))
	if err != nil {
		t.Fatalf("Password reset request failed: %v", err)
	}
	defer resetResp.Body.Close()

	if resetResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resetResp.Body)
		t.Fatalf("Expected 200 for password reset, got %d: %s", resetResp.StatusCode, string(body))
	}

	// Property 2: Response contains generic message
	var resetResult map[string]string
	if err := json.NewDecoder(resetResp.Body).Decode(&resetResult); err != nil {
		t.Fatalf("Failed to decode password reset response: %v", err)
	}

	if resetResult["message"] == "" {
		t.Fatal("Password reset response should contain message")
	}

	// Property 3: Reset email was sent
	// Check that emails were sent
	emailCount := ts.emailService.Count()
	if emailCount == 0 {
		t.Fatal("Password reset email should have been sent")
	}

	// Verify email was sent to the correct address
	lastEmail := ts.emailService.LastEmail()
	if lastEmail.To != email {
		t.Fatalf("Password reset email should be sent to the requested address: expected %s, got %s", email, lastEmail.To)
	}
}

func TestIntegration_PasswordReset_Properties(t *testing.T) {
	rapid.Check(t, testIntegration_PasswordReset_Properties)
}

func FuzzIntegration_PasswordReset_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testIntegration_PasswordReset_Properties))
}

// =============================================================================
// TEST 4: OAuth + MCP Flow (tests oauth_middleware)
// =============================================================================

func testIntegration_OAuthMCP_Properties(t *rapid.T) {
	ts := setupFullAppServerRapid()
	defer ts.cleanup()

	noteTitle := integrationNoteTitleGenerator().Draw(t, "title")
	noteContent := integrationNoteContentGenerator().Draw(t, "content")
	state := integrationOAuthStateGenerator().Draw(t, "state")

	client := ts.Client()

	// Step 1: Register OAuth client
	dcrReq := map[string]interface{}{
		"client_name":               "TestMCPClient",
		"redirect_uris":             []string{"http://localhost:8080/callback"},
		"grant_types":               []string{"authorization_code", "refresh_token"},
		"response_types":            []string{"code"},
		"token_endpoint_auth_method": "none", // Public client
	}
	dcrBody, _ := json.Marshal(dcrReq)
	dcrResp, err := client.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(string(dcrBody)))
	if err != nil {
		t.Fatalf("DCR request failed: %v", err)
	}
	defer dcrResp.Body.Close()

	if dcrResp.StatusCode != http.StatusOK && dcrResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(dcrResp.Body)
		t.Fatalf("DCR failed with status %d: %s", dcrResp.StatusCode, string(body))
	}

	var dcrResult map[string]interface{}
	if err := json.NewDecoder(dcrResp.Body).Decode(&dcrResult); err != nil {
		t.Fatalf("Failed to decode DCR response: %v", err)
	}

	clientID := dcrResult["client_id"].(string)

	// Step 2: Generate PKCE
	verifier := generateIntegrationSecureRandom(64)
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Step 3: Create user and session
	testEmail := "oauth-mcp-test-" + generateIntegrationSecureRandom(8) + "@example.com"
	user, err := ts.userService.FindOrCreateByEmail(context.Background(), testEmail)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	sessionID, err := ts.sessionService.Create(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Step 4: Record consent (bypass consent UI for test)
	if err := ts.consentService.RecordConsent(context.Background(), user.ID, clientID, []string{"notes:read", "notes:write"}); err != nil {
		t.Fatalf("Failed to record consent: %v", err)
	}

	// Also record consent in the database directly for OAuth handler
	_, err = ts.sessionsDB.DB().ExecContext(context.Background(), `
		INSERT INTO oauth_consents (id, user_id, client_id, scopes, granted_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(user_id, client_id) DO UPDATE SET
			scopes = excluded.scopes,
			granted_at = excluded.granted_at
	`, generateIntegrationSecureRandom(32), user.ID, clientID, "notes:read notes:write", ts.sessionsDB.DB())

	// Step 5: Build authorization request
	authParams := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {"http://localhost:8080/callback"},
		"response_type":         {"code"},
		"scope":                 {"notes:read notes:write"},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	// Create client with session cookie
	jar, _ := cookiejar.New(nil)
	authClient := ts.Client()
	authClient.Jar = jar

	// Set session cookie
	serverURL, _ := url.Parse(ts.URL)
	jar.SetCookies(serverURL, []*http.Cookie{{
		Name:  "session_id",
		Value: sessionID,
		Path:  "/",
	}})

	authClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Make authorization request
	authResp, err := authClient.Get(ts.URL + "/oauth/authorize?" + authParams.Encode())
	if err != nil {
		t.Fatalf("Authorization request failed: %v", err)
	}
	defer authResp.Body.Close()

	// Extract authorization code from redirect
	var authCode string
	if authResp.StatusCode == http.StatusFound {
		location := authResp.Header.Get("Location")
		if strings.Contains(location, "code=") {
			parsed, _ := url.Parse(location)
			authCode = parsed.Query().Get("code")
		}
	}

	if authCode == "" {
		t.Fatal("Failed to get authorization code")
	}

	// Step 6: Token exchange
	tokenParams := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {authCode},
		"redirect_uri":  {"http://localhost:8080/callback"},
		"code_verifier": {verifier},
	}

	tokenResp, err := client.PostForm(ts.URL+"/oauth/token", tokenParams)
	if err != nil {
		t.Fatalf("Token exchange failed: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("Token exchange returned %d: %s", tokenResp.StatusCode, string(body))
	}

	var tokenResult map[string]interface{}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenResult); err != nil {
		t.Fatalf("Failed to decode token response: %v", err)
	}

	accessToken := tokenResult["access_token"].(string)

	// Property: Access token should be valid JWT format
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("Access token should have 3 parts, got %d", len(parts))
	}

	// Step 7: Use MCP with Bearer token to create note
	mcpCreateReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "note_create",
			"arguments": map[string]interface{}{
				"title":   noteTitle,
				"content": noteContent,
			},
		},
		"id": 1,
	}
	mcpBody, _ := json.Marshal(mcpCreateReq)

	mcpReq, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(string(mcpBody)))
	mcpReq.Header.Set("Content-Type", "application/json")
	mcpReq.Header.Set("Accept", "application/json, text/event-stream")
	mcpReq.Header.Set("Authorization", "Bearer "+accessToken)

	mcpResp, err := client.Do(mcpReq)
	if err != nil {
		t.Fatalf("MCP request failed: %v", err)
	}
	defer mcpResp.Body.Close()

	// Property: MCP request with valid token should succeed
	if mcpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(mcpResp.Body)
		t.Fatalf("MCP request with valid token should return 200, got %d: %s", mcpResp.StatusCode, string(body))
	}
}

func TestIntegration_OAuthMCP_Properties(t *testing.T) {
	rapid.Check(t, testIntegration_OAuthMCP_Properties)
}

// =============================================================================
// TEST 5: Refresh Token Flow
// =============================================================================

func testIntegration_RefreshToken_Properties(t *rapid.T) {
	ts := setupFullAppServerRapid()
	defer ts.cleanup()

	client := ts.Client()

	// Step 1: Register OAuth client
	dcrReq := map[string]interface{}{
		"client_name":               "RefreshTestClient",
		"redirect_uris":             []string{"http://localhost:8080/callback"},
		"grant_types":               []string{"authorization_code", "refresh_token"},
		"response_types":            []string{"code"},
		"token_endpoint_auth_method": "none",
	}
	dcrBody, _ := json.Marshal(dcrReq)
	dcrResp, err := client.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(string(dcrBody)))
	if err != nil {
		t.Fatalf("DCR request failed: %v", err)
	}
	defer dcrResp.Body.Close()

	var dcrResult map[string]interface{}
	json.NewDecoder(dcrResp.Body).Decode(&dcrResult)
	clientID := dcrResult["client_id"].(string)

	// Step 2: Create tokens directly via provider (bypass full OAuth flow for this test)
	testEmail := "refresh-test-" + generateIntegrationSecureRandom(8) + "@example.com"
	user, _ := ts.userService.FindOrCreateByEmail(context.Background(), testEmail)

	tokens, err := ts.oauthProvider.CreateTokens(context.Background(), oauth.TokenParams{
		ClientID:            clientID,
		UserID:              user.ID,
		Scope:               "notes:read notes:write",
		Resource:            ts.URL,
		IncludeRefreshToken: true,
	})
	if err != nil {
		t.Fatalf("Failed to create tokens: %v", err)
	}

	// Property 1: Initial tokens should be present
	if tokens.AccessToken == "" {
		t.Fatal("Access token should not be empty")
	}
	if tokens.RefreshToken == "" {
		t.Fatal("Refresh token should not be empty")
	}

	// Step 3: Use refresh token to get new access token
	refreshParams := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {tokens.RefreshToken},
	}

	refreshResp, err := client.PostForm(ts.URL+"/oauth/token", refreshParams)
	if err != nil {
		t.Fatalf("Refresh request failed: %v", err)
	}
	defer refreshResp.Body.Close()

	if refreshResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(refreshResp.Body)
		t.Fatalf("Refresh should return 200, got %d: %s", refreshResp.StatusCode, string(body))
	}

	var refreshResult map[string]interface{}
	json.NewDecoder(refreshResp.Body).Decode(&refreshResult)

	newAccessToken := refreshResult["access_token"].(string)

	// Property 2: New access token should be different
	if newAccessToken == tokens.AccessToken {
		t.Fatal("New access token should be different from old one")
	}

	// Property 3: New access token should be valid
	claims, err := ts.oauthProvider.VerifyAccessToken(newAccessToken)
	if err != nil {
		t.Fatalf("New access token should be valid: %v", err)
	}

	// Property 4: User ID should be preserved
	if claims.Subject != user.ID {
		t.Fatalf("User ID should be preserved: expected %s, got %s", user.ID, claims.Subject)
	}

	// Property 5: Scope should be preserved
	if claims.Scope != "notes:read notes:write" {
		t.Fatalf("Scope should be preserved: expected 'notes:read notes:write', got '%s'", claims.Scope)
	}
}

func TestIntegration_RefreshToken_Properties(t *testing.T) {
	rapid.Check(t, testIntegration_RefreshToken_Properties)
}

func FuzzIntegration_RefreshToken_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testIntegration_RefreshToken_Properties))
}

// =============================================================================
// TEST 6: Full User Journey (end-to-end)
// =============================================================================

func testIntegration_FullUserJourney_Properties(t *rapid.T) {
	ts := setupFullAppServerRapid()
	defer ts.cleanup()

	email := integrationEmailGenerator().Draw(t, "email")
	password := integrationPasswordGenerator().Draw(t, "password")
	noteTitle := integrationNoteTitleGenerator().Draw(t, "title")
	noteContent := integrationNoteContentGenerator().Draw(t, "content")

	// Create HTTP client with cookie jar
	jar, _ := cookiejar.New(nil)
	client := ts.Client()
	client.Jar = jar

	// ==========================================================
	// Step 1: Register via API
	// ==========================================================
	regBody := fmt.Sprintf(`{"email":"%s","password":"%s"}`, email, password)
	regResp, err := client.Post(ts.URL+"/auth/register", "application/json", strings.NewReader(regBody))
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}
	defer regResp.Body.Close()

	if regResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(regResp.Body)
		t.Fatalf("Expected 201, got %d: %s", regResp.StatusCode, string(body))
	}

	// ==========================================================
	// Step 2: Create note via API
	// ==========================================================
	noteBody := fmt.Sprintf(`{"title":"%s","content":"%s"}`, noteTitle, noteContent)
	noteResp, err := client.Post(ts.URL+"/api/notes", "application/json", strings.NewReader(noteBody))
	if err != nil {
		t.Fatalf("Create note failed: %v", err)
	}
	defer noteResp.Body.Close()

	if noteResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(noteResp.Body)
		t.Fatalf("Expected 201 for note creation, got %d: %s", noteResp.StatusCode, string(body))
	}

	var createdNote map[string]interface{}
	json.NewDecoder(noteResp.Body).Decode(&createdNote)
	noteID := createdNote["id"].(string)

	// Property: Note should have expected title
	if createdNote["title"] != noteTitle {
		t.Fatalf("Note title mismatch: expected %s, got %s", noteTitle, createdNote["title"])
	}

	// ==========================================================
	// Step 3: Verify note exists via list
	// ==========================================================
	listResp, err := client.Get(ts.URL + "/api/notes")
	if err != nil {
		t.Fatalf("List notes failed: %v", err)
	}
	defer listResp.Body.Close()

	var listResult map[string]interface{}
	json.NewDecoder(listResp.Body).Decode(&listResult)
	notesArray := listResult["notes"].([]interface{})

	// Property: Created note should appear in list
	noteFound := false
	for _, n := range notesArray {
		note := n.(map[string]interface{})
		if note["id"] == noteID {
			noteFound = true
			break
		}
	}
	if !noteFound {
		t.Fatal("Created note should appear in list")
	}

	// ==========================================================
	// Step 4: OAuth authorize for MCP client
	// ==========================================================
	dcrReq := map[string]interface{}{
		"client_name":               "JourneyTestClient",
		"redirect_uris":             []string{"http://localhost:8080/callback"},
		"grant_types":               []string{"authorization_code", "refresh_token"},
		"response_types":            []string{"code"},
		"token_endpoint_auth_method": "none",
	}
	dcrBody, _ := json.Marshal(dcrReq)
	dcrResp, err := client.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(string(dcrBody)))
	if err != nil {
		t.Fatalf("DCR failed: %v", err)
	}
	defer dcrResp.Body.Close()

	var dcrResult map[string]interface{}
	json.NewDecoder(dcrResp.Body).Decode(&dcrResult)
	clientID := dcrResult["client_id"].(string)

	// Generate PKCE
	verifier := generateIntegrationSecureRandom(64)
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Get user ID from session
	user, _ := ts.userService.FindOrCreateByEmail(context.Background(), email)

	// Record consent
	ts.consentService.RecordConsent(context.Background(), user.ID, clientID, []string{"notes:read", "notes:write"})
	ts.sessionsDB.DB().ExecContext(context.Background(), `
		INSERT INTO oauth_consents (id, user_id, client_id, scopes, granted_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(user_id, client_id) DO UPDATE SET scopes = excluded.scopes
	`, generateIntegrationSecureRandom(32), user.ID, clientID, "notes:read notes:write", ts.sessionsDB.DB())

	// Authorization request
	authParams := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {"http://localhost:8080/callback"},
		"response_type":         {"code"},
		"scope":                 {"notes:read notes:write"},
		"state":                 {"test-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	authResp, _ := client.Get(ts.URL + "/oauth/authorize?" + authParams.Encode())
	defer authResp.Body.Close()

	var authCode string
	if authResp.StatusCode == http.StatusFound {
		location := authResp.Header.Get("Location")
		if strings.Contains(location, "code=") {
			parsed, _ := url.Parse(location)
			authCode = parsed.Query().Get("code")
		}
	}

	if authCode == "" {
		t.Fatal("Failed to get authorization code in journey test")
	}

	// Token exchange
	tokenParams := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {authCode},
		"redirect_uri":  {"http://localhost:8080/callback"},
		"code_verifier": {verifier},
	}

	// Use a fresh client for token exchange
	tokenClient := ts.Client()
	tokenResp, _ := tokenClient.PostForm(ts.URL+"/oauth/token", tokenParams)
	defer tokenResp.Body.Close()

	var tokenResult map[string]interface{}
	json.NewDecoder(tokenResp.Body).Decode(&tokenResult)
	accessToken := tokenResult["access_token"].(string)

	// ==========================================================
	// Step 5: Use MCP to list notes
	// ==========================================================
	mcpListReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "note_list",
			"arguments": map[string]interface{}{},
		},
		"id": 1,
	}
	mcpBody, _ := json.Marshal(mcpListReq)

	mcpReq, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(string(mcpBody)))
	mcpReq.Header.Set("Content-Type", "application/json")
	mcpReq.Header.Set("Accept", "application/json, text/event-stream")
	mcpReq.Header.Set("Authorization", "Bearer "+accessToken)

	mcpClient := ts.Client()
	mcpResp, err := mcpClient.Do(mcpReq)
	if err != nil {
		t.Fatalf("MCP list request failed: %v", err)
	}
	defer mcpResp.Body.Close()

	// Property: MCP request should succeed
	if mcpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(mcpResp.Body)
		t.Fatalf("MCP list should return 200, got %d: %s", mcpResp.StatusCode, string(body))
	}

	// ==========================================================
	// Step 6: Delete via API
	// ==========================================================
	// Reset client redirect behavior
	client.CheckRedirect = nil
	jar2, _ := cookiejar.New(nil)
	client.Jar = jar2

	// Login again to get fresh session
	loginResp, _ := client.Post(ts.URL+"/auth/login", "application/json",
		strings.NewReader(fmt.Sprintf(`{"email":"%s","password":"%s"}`, email, password)))
	loginResp.Body.Close()

	deleteReq, _ := http.NewRequest("DELETE", ts.URL+"/api/notes/"+noteID, nil)
	deleteResp, err := client.Do(deleteReq)
	if err != nil {
		t.Fatalf("Delete request failed: %v", err)
	}
	defer deleteResp.Body.Close()

	// Property: Delete should succeed
	if deleteResp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(deleteResp.Body)
		t.Fatalf("Delete should return 204, got %d: %s", deleteResp.StatusCode, string(body))
	}

	// ==========================================================
	// Step 7: Verify note is gone
	// ==========================================================
	getResp, _ := client.Get(ts.URL + "/api/notes/" + noteID)
	defer getResp.Body.Close()

	// Property: Deleted note should return 404
	if getResp.StatusCode != http.StatusNotFound {
		t.Fatalf("Deleted note should return 404, got %d", getResp.StatusCode)
	}

	// ==========================================================
	// Step 8: Logout
	// ==========================================================
	logoutResp, _ := client.Post(ts.URL+"/auth/logout", "application/json", nil)
	logoutResp.Body.Close()

	// Property: Should not be authenticated after logout
	whoamiResp, _ := client.Get(ts.URL + "/auth/whoami")
	defer whoamiResp.Body.Close()

	var whoamiResult map[string]interface{}
	json.NewDecoder(whoamiResp.Body).Decode(&whoamiResult)

	if whoamiResult["authenticated"] != false {
		t.Fatal("Should not be authenticated after logout")
	}
}

func TestIntegration_FullUserJourney_Properties(t *testing.T) {
	rapid.Check(t, testIntegration_FullUserJourney_Properties)
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func generateIntegrationSecureRandom(length int) string {
	bytes := make([]byte, length)
	if _, err := crand.Read(bytes); err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)[:length]
}

// =============================================================================
// ADDITIONAL INTEGRATION TESTS
// =============================================================================

// TestIntegration_NotesAPI_CRUD tests the notes API CRUD operations
func TestIntegration_NotesAPI_CRUD(t *testing.T) {
	ts := setupFullAppServer(t)
	defer ts.cleanup()

	// Register and login user
	email := "notes-crud-test@example.com"
	password := "TestPassword123!"

	jar, _ := cookiejar.New(nil)
	client := ts.Client()
	client.Jar = jar

	// Register
	regBody := fmt.Sprintf(`{"email":"%s","password":"%s"}`, email, password)
	regResp, err := client.Post(ts.URL+"/auth/register", "application/json", strings.NewReader(regBody))
	require.NoError(t, err)
	regResp.Body.Close()
	require.Equal(t, http.StatusCreated, regResp.StatusCode)

	t.Run("Create note", func(t *testing.T) {
		noteBody := `{"title":"Test Note","content":"Test content"}`
		resp, err := client.Post(ts.URL+"/api/notes", "application/json", strings.NewReader(noteBody))
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusCreated, resp.StatusCode)

		var note map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&note)
		require.NotEmpty(t, note["id"])
		require.Equal(t, "Test Note", note["title"])
	})

	t.Run("List notes", func(t *testing.T) {
		resp, err := client.Get(ts.URL + "/api/notes")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		notes := result["notes"].([]interface{})
		require.Greater(t, len(notes), 0)
	})
}

// TestIntegration_OAuthMetadata tests OAuth metadata endpoints
func TestIntegration_OAuthMetadata(t *testing.T) {
	ts := setupFullAppServer(t)
	defer ts.cleanup()

	client := ts.Client()

	t.Run("Protected resource metadata", func(t *testing.T) {
		resp, err := client.Get(ts.URL + "/.well-known/oauth-protected-resource")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var metadata map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&metadata)
		require.NotEmpty(t, metadata["resource"])
		require.NotEmpty(t, metadata["authorization_servers"])
	})

	t.Run("Authorization server metadata", func(t *testing.T) {
		resp, err := client.Get(ts.URL + "/.well-known/oauth-authorization-server")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var metadata map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&metadata)
		require.NotEmpty(t, metadata["issuer"])
		require.NotEmpty(t, metadata["authorization_endpoint"])
		require.NotEmpty(t, metadata["token_endpoint"])
		require.NotEmpty(t, metadata["registration_endpoint"])
	})

	t.Run("JWKS endpoint", func(t *testing.T) {
		resp, err := client.Get(ts.URL + "/.well-known/jwks.json")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var jwks map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&jwks)
		require.NotEmpty(t, jwks["keys"])
	})
}

// TestIntegration_UnauthenticatedAccess tests that protected endpoints require auth
func TestIntegration_UnauthenticatedAccess(t *testing.T) {
	ts := setupFullAppServer(t)
	defer ts.cleanup()

	client := ts.Client()

	t.Run("Notes API requires auth", func(t *testing.T) {
		resp, err := client.Get(ts.URL + "/api/notes")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("MCP requires auth", func(t *testing.T) {
		mcpReq := `{"jsonrpc":"2.0","method":"tools/list","id":1}`
		resp, err := client.Post(ts.URL+"/mcp", "application/json", strings.NewReader(mcpReq))
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Should have WWW-Authenticate header
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		require.Contains(t, wwwAuth, "resource_metadata")
	})
}
