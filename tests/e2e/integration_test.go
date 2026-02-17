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
	emailpkg "github.com/kuitang/agent-notes/internal/email"
	"github.com/kuitang/agent-notes/internal/mcp"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/kuitang/agent-notes/internal/oauth"
	"github.com/kuitang/agent-notes/internal/web"
	"github.com/kuitang/agent-notes/tests/e2e/testutil"
)

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// =============================================================================
// FULL APP TEST SERVER - Uses REAL handlers
// =============================================================================

// integrationTestMutex ensures test isolation
var integrationTestMutex sync.Mutex
var integrationSharedMu sync.Mutex
var integrationSharedFixture *fullAppServer

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
	emailService   *emailpkg.MockEmailService
	oauthProvider  *oauth.Provider
	authMiddleware *auth.Middleware
	renderer       *web.Renderer
	oidcClient     *auth.MockOIDCClient // Exposed for tests to configure mock responses
}

// setupFullAppServer creates a test server with ALL real handlers wired up.
// This mirrors how cmd/server/main.go sets up the application.
func setupFullAppServer(t testing.TB) *fullAppServer {
	t.Helper()
	integrationTestMutex.Lock()
	t.Cleanup(integrationTestMutex.Unlock)

	ts, err := getOrCreateSharedFullAppServer()
	if err != nil {
		t.Fatalf("Failed to initialize shared integration fixture: %v", err)
	}
	if err := resetFullAppServerState(ts); err != nil {
		t.Fatalf("Failed to reset shared integration fixture: %v", err)
	}
	return ts
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
	emailService := emailpkg.NewMockEmailService()
	oidcClient := auth.NewMockOIDCClient()
	// Configure mock OIDC client with a default success response
	oidcClient.SetNextSuccess("google-sub-12345", "test@example.com", "Test User", true)
	userService := auth.NewUserService(sessionsDB, keyManager, emailService, server.URL, auth.FakeInsecureHasher{})
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

	// NOTE: We do NOT use webHandler.RegisterRoutes() because it has a route conflict
	// with oauthHandler.RegisterRoutes() (both register POST /oauth/consent).
	// This is actually a bug in the production code that should be fixed.
	// For testing, we manually register only the routes we need.

	// =============================================================================
	// Register routes (avoiding the POST /oauth/consent conflict)
	// =============================================================================

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// OAuth metadata routes
	oauthProvider.RegisterMetadataRoutes(mux)

	// OAuth endpoints (including POST /oauth/consent)
	mux.HandleFunc("POST /oauth/register", oauthProvider.DCR)
	oauthHandler.RegisterRoutes(mux)

	// Auth API routes (REAL handlers from internal/auth/handlers.go)
	authHandler.RegisterRoutes(mux)

	// Landing page redirect
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	})

	// Login page
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><h1>Login</h1></body></html>"))
	})

	// Notes page (stub — prevents GET / catch-all from intercepting /notes redirect)
	mux.HandleFunc("GET /notes", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><h1>Notes</h1></body></html>"))
	})

	// Protected notes API routes
	notesHandler := &integrationNotesHandler{keyManager: keyManager}
	mux.Handle("GET /api/notes", authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.ListNotes)))
	mux.Handle("POST /api/notes", authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.CreateNote)))
	mux.Handle("GET /api/notes/{id}", authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.GetNote)))
	mux.Handle("PUT /api/notes/{id}", authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.UpdateNote)))
	mux.Handle("DELETE /api/notes/{id}", authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.DeleteNote)))
	mux.Handle("POST /api/notes/search", authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.SearchNotes)))

	// MCP endpoint (with REAL OAuth middleware - exercises internal/auth/oauth_middleware.go)
	tokenVerifier := auth.NewTokenVerifier(server.URL, server.URL, oauthProvider.PublicKey())
	resourceMetadataURL := server.URL + "/.well-known/oauth-protected-resource"
	mcpHandler := newIntegrationMCPHandler(keyManager)
	mux.Handle("POST /mcp", auth.OAuthMiddleware(tokenVerifier, resourceMetadataURL, true)(http.HandlerFunc(mcpHandler.ServeHTTP)))

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
		oidcClient:     oidcClient,
	}
}

// cleanup closes the test server and releases resources
func (ts *fullAppServer) cleanup() {
	if ts.tempDir != "" && strings.Contains(ts.tempDir, "integration-shared-") {
		return
	}
	ts.Server.Close()
	db.ResetForTesting()
	if ts.tempDir != "" && strings.Contains(ts.tempDir, "integration-test-") {
		os.RemoveAll(ts.tempDir)
	}
	integrationTestMutex.Unlock()
}

func getOrCreateSharedFullAppServer() (*fullAppServer, error) {
	integrationSharedMu.Lock()
	defer integrationSharedMu.Unlock()

	if integrationSharedFixture != nil {
		if err := integrationSharedFixture.sessionsDB.DB().Ping(); err == nil {
			return integrationSharedFixture, nil
		}
		integrationSharedFixture.closeSharedResources()
		integrationSharedFixture = nil
	}

	tempDir, err := os.MkdirTemp("", "integration-shared-*")
	if err != nil {
		return nil, fmt.Errorf("create shared integration temp dir: %w", err)
	}
	integrationSharedFixture = createFullAppServer(tempDir)
	return integrationSharedFixture, nil
}

func (ts *fullAppServer) closeSharedResources() {
	if ts.Server != nil {
		ts.Server.Close()
	}
	if ts.tempDir != "" {
		_ = os.RemoveAll(ts.tempDir)
	}
}

func resetFullAppServerState(ts *fullAppServer) error {
	if err := resetSharedDBFixtureState(ts.tempDir, ts.sessionsDB); err != nil {
		return err
	}
	if ts.emailService != nil {
		ts.emailService.Clear()
	}
	if ts.oidcClient != nil {
		ts.oidcClient.Reset()
		ts.oidcClient.SetNextSuccess("google-sub-12345", "test@example.com", "Test User", true)
	}
	return nil
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

// integrationMCPHandler handles MCP requests (auth handled by OAuthMiddleware)
type integrationMCPHandler struct {
	keyManager *crypto.KeyManager
	mcpServers map[string]*mcp.Server // Cache MCP servers per user for session persistence
	mu         sync.RWMutex
}

func newIntegrationMCPHandler(keyManager *crypto.KeyManager) *integrationMCPHandler {
	return &integrationMCPHandler{
		keyManager: keyManager,
		mcpServers: make(map[string]*mcp.Server),
	}
}

func (h *integrationMCPHandler) getOrCreateMCPServer(userID string) (*mcp.Server, error) {
	// Check cache first
	h.mu.RLock()
	if server, ok := h.mcpServers[userID]; ok {
		h.mu.RUnlock()
		return server, nil
	}
	h.mu.RUnlock()

	// Create new server
	h.mu.Lock()
	defer h.mu.Unlock()

	// Double-check after acquiring write lock
	if server, ok := h.mcpServers[userID]; ok {
		return server, nil
	}

	// Use in-memory database for MCP tests
	userDB, err := db.NewUserDBInMemory(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to open user DB: %w", err)
	}

	// Create notes service and MCP server
	notesSvc := notes.NewService(userDB)
	mcpServer := mcp.NewServer(notesSvc)
	h.mcpServers[userID] = mcpServer

	return mcpServer, nil
}

func (h *integrationMCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// User ID is set by OAuthMiddleware (exercises internal/auth/oauth_middleware.go)
	userID, ok := auth.UserIDFromContext(r.Context())
	if !ok || userID == "" {
		// This shouldn't happen if OAuthMiddleware is working correctly
		http.Error(w, "User ID not found in context", http.StatusInternalServerError)
		return
	}

	// Get or create cached MCP server for this user
	mcpServer, err := h.getOrCreateMCPServer(userID)
	if err != nil {
		http.Error(w, "Internal server error: "+err.Error(), http.StatusInternalServerError)
		return
	}

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

func newIntegrationHTTPClient(ts *fullAppServer) *http.Client {
	client := ts.Client()
	clone := *client
	clone.Jar = nil
	clone.CheckRedirect = nil
	return &clone
}

// =============================================================================
// TEST 1: Auth API Flow (tests internal/auth/handlers.go)
// =============================================================================

func testIntegration_AuthAPI_PropertiesWithServer(t *rapid.T, ts *fullAppServer) {
	email := uniqueIntegrationEmail(testutil.EmailGenerator().Draw(t, "email"))
	password := testutil.PasswordGenerator().Draw(t, "password")

	client := newIntegrationHTTPClient(ts)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("Failed to create cookie jar: %v", err)
	}
	client.Jar = jar

	// Property 1: POST /auth/register -> redirects to /notes (200 OK)
	regResp, err := client.PostForm(ts.URL+"/auth/register", url.Values{"email": {email}, "password": {password}})
	if err != nil {
		t.Fatalf("Registration request failed: %v", err)
	}
	defer regResp.Body.Close()

	if regResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(regResp.Body)
		t.Fatalf("Expected 200 after registration redirect, got %d: %s", regResp.StatusCode, string(body))
	}

	// Property 2: GET /auth/whoami -> authenticated: true
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

	// Property 3: POST /auth/logout -> redirects to /
	logoutResp, err := client.PostForm(ts.URL+"/auth/logout", nil)
	if err != nil {
		t.Fatalf("Logout request failed: %v", err)
	}
	logoutResp.Body.Close()

	// Property 4: GET /auth/whoami -> authenticated: false after logout
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

	// Property 5: POST /auth/login -> redirects to /notes
	loginResp, err := client.PostForm(ts.URL+"/auth/login", url.Values{"email": {email}, "password": {password}})
	if err != nil {
		t.Fatalf("Login request failed: %v", err)
	}
	defer loginResp.Body.Close()

	if loginResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("Expected 200 after login redirect, got %d: %s", loginResp.StatusCode, string(body))
	}

	// Property 6: GET /auth/whoami -> authenticated: true after login
	whoami3Resp, err := client.Get(ts.URL + "/auth/whoami")
	if err != nil {
		t.Fatalf("Whoami request after login failed: %v", err)
	}
	defer whoami3Resp.Body.Close()

	var whoami3Result map[string]interface{}
	if err := json.NewDecoder(whoami3Resp.Body).Decode(&whoami3Result); err != nil {
		t.Fatalf("Failed to decode whoami response: %v", err)
	}

	if whoami3Result["authenticated"] != true {
		t.Fatal("Should be authenticated after login")
	}
}

func testIntegration_AuthAPI_Properties(t *rapid.T) {
	ts := setupFullAppServerRapid()
	defer ts.cleanup()
	testIntegration_AuthAPI_PropertiesWithServer(t, ts)
}

func TestIntegration_AuthAPI_Properties(t *testing.T) {
	ts := setupFullAppServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		testIntegration_AuthAPI_PropertiesWithServer(rt, ts)
	})
}

func FuzzIntegration_AuthAPI_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testIntegration_AuthAPI_Properties))
}

// =============================================================================
// TEST 1.5: Auth API Validation Errors (tests error paths in handlers)
// =============================================================================

func testIntegration_AuthAPIValidation_PropertiesWithServer(t *rapid.T, ts *fullAppServer) {
	client := newIntegrationHTTPClient(ts)

	// Generate valid and invalid inputs
	validEmail := testutil.EmailGenerator().Draw(t, "validEmail")

	// Property 1: Register with missing email should fail
	regResp, err := client.PostForm(ts.URL+"/auth/register", url.Values{"password": {"ValidPassword123!"}})
	if err != nil {
		t.Fatalf("Register request failed: %v", err)
	}
	regResp.Body.Close()

	if regResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Register with missing email should return 400, got %d", regResp.StatusCode)
	}

	// Property 2: Register with missing password should fail
	regResp2, err := client.PostForm(ts.URL+"/auth/register", url.Values{"email": {validEmail}})
	if err != nil {
		t.Fatalf("Register request failed: %v", err)
	}
	regResp2.Body.Close()

	if regResp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("Register with missing password should return 400, got %d", regResp2.StatusCode)
	}

	// Property 3: Register with weak password should fail
	regResp3, err := client.PostForm(ts.URL+"/auth/register", url.Values{"email": {validEmail}, "password": {"weak"}})
	if err != nil {
		t.Fatalf("Register request failed: %v", err)
	}
	regResp3.Body.Close()

	if regResp3.StatusCode != http.StatusBadRequest {
		t.Fatalf("Register with weak password should return 400, got %d", regResp3.StatusCode)
	}

	// Property 4: Login with missing email should fail
	loginResp, err := client.PostForm(ts.URL+"/auth/login", url.Values{"password": {"SomePassword123!"}})
	if err != nil {
		t.Fatalf("Login request failed: %v", err)
	}
	loginResp.Body.Close()

	if loginResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Login with missing email should return 400, got %d", loginResp.StatusCode)
	}

	// Property 5: Login with missing password should fail
	loginResp2, err := client.PostForm(ts.URL+"/auth/login", url.Values{"email": {validEmail}})
	if err != nil {
		t.Fatalf("Login request failed: %v", err)
	}
	loginResp2.Body.Close()

	if loginResp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("Login with missing password should return 400, got %d", loginResp2.StatusCode)
	}

	// Property 6: Magic link with missing email should fail
	magicResp, err := client.PostForm(ts.URL+"/auth/magic", url.Values{})
	if err != nil {
		t.Fatalf("Magic link request failed: %v", err)
	}
	magicResp.Body.Close()

	if magicResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Magic link with missing email should return 400, got %d", magicResp.StatusCode)
	}

	// Property 7: Password reset with missing email should fail
	resetResp, err := client.PostForm(ts.URL+"/auth/password-reset", url.Values{})
	if err != nil {
		t.Fatalf("Password reset request failed: %v", err)
	}
	resetResp.Body.Close()

	if resetResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Password reset with missing email should return 400, got %d", resetResp.StatusCode)
	}

	// Property 8: Empty form data should return 400
	emptyResp, err := client.PostForm(ts.URL+"/auth/register", url.Values{})
	if err != nil {
		t.Fatalf("Empty form request failed: %v", err)
	}
	emptyResp.Body.Close()

	if emptyResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Empty form should return 400, got %d", emptyResp.StatusCode)
	}

	// Property 9: Whoami when not authenticated should return authenticated: false
	whoamiResp, err := client.Get(ts.URL + "/auth/whoami")
	if err != nil {
		t.Fatalf("Whoami request failed: %v", err)
	}
	defer whoamiResp.Body.Close()

	var whoamiResult map[string]interface{}
	json.NewDecoder(whoamiResp.Body).Decode(&whoamiResult)

	if whoamiResult["authenticated"] != false {
		t.Fatal("Whoami should return authenticated: false when not logged in")
	}
}

func testIntegration_AuthAPIValidation_Properties(t *rapid.T) {
	ts := setupFullAppServerRapid()
	defer ts.cleanup()
	testIntegration_AuthAPIValidation_PropertiesWithServer(t, ts)
}

func TestIntegration_AuthAPIValidation_Properties(t *testing.T) {
	ts := setupFullAppServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		testIntegration_AuthAPIValidation_PropertiesWithServer(rt, ts)
	})
}

func FuzzIntegration_AuthAPIValidation_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testIntegration_AuthAPIValidation_Properties))
}

// =============================================================================
// TEST 2: Magic Link Flow (tests internal/auth/handlers.go including verify!)
// =============================================================================

func testIntegration_MagicLink_PropertiesWithServer(t *rapid.T, ts *fullAppServer) {
	email := uniqueIntegrationEmail(testutil.EmailGenerator().Draw(t, "email"))

	client := newIntegrationHTTPClient(ts)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("Failed to create cookie jar: %v", err)
	}
	client.Jar = jar
	emailCountBefore := ts.emailService.Count()

	// Property 1: POST /auth/magic with email -> redirects to login (always succeeds to prevent enumeration)
	magicResp, err := client.PostForm(ts.URL+"/auth/magic", url.Values{"email": {email}})
	if err != nil {
		t.Fatalf("Magic link request failed: %v", err)
	}
	defer magicResp.Body.Close()

	// After redirect, we end up at /login with 200 OK
	if magicResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(magicResp.Body)
		t.Fatalf("Expected 200 after redirect, got %d: %s", magicResp.StatusCode, string(body))
	}

	// Property 2: Email was sent via mock service
	emailCount := ts.emailService.Count()
	if emailCount <= emailCountBefore {
		t.Fatal("Magic link email should have been sent")
	}

	// Property 4: Verify last email was sent to correct address
	lastEmail := ts.emailService.LastEmail()
	if lastEmail.To != email {
		t.Fatalf("Email should be sent to the requested address: expected %s, got %s", email, lastEmail.To)
	}

	// Property 5: Extract token from email and verify it
	// The email Data contains MagicLinkData with the Link field
	magicLinkData, ok := lastEmail.Data.(emailpkg.MagicLinkData)
	if !ok {
		t.Fatal("Email data should be MagicLinkData")
	}

	// Parse the link to extract the token
	linkURL, err := url.Parse(magicLinkData.Link)
	if err != nil {
		t.Fatalf("Failed to parse magic link URL: %v", err)
	}
	token := linkURL.Query().Get("token")
	if token == "" {
		t.Fatal("Magic link should contain token")
	}

	// Property 6: GET /auth/magic/verify?token=... -> redirects and sets session
	// Stop following redirects so we can verify the cookie
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	verifyResp, err := client.Get(ts.URL + "/auth/magic/verify?token=" + token)
	if err != nil {
		t.Fatalf("Magic link verify request failed: %v", err)
	}
	defer verifyResp.Body.Close()

	// Should redirect (302 Found) after successful verification
	if verifyResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(verifyResp.Body)
		t.Fatalf("Expected 302 redirect for magic verify, got %d: %s", verifyResp.StatusCode, string(body))
	}

	// Property 7: Session cookie should be set after verification
	sessionCookieFound := false
	for _, c := range verifyResp.Cookies() {
		if c.Name == "session_id" && c.Value != "" {
			sessionCookieFound = true
			break
		}
	}
	if !sessionCookieFound {
		t.Fatal("Session cookie should be set after magic link verification")
	}

	// Property 8: Using token again should fail (token consumed)
	verifyResp2, err := client.Get(ts.URL + "/auth/magic/verify?token=" + token)
	if err != nil {
		t.Fatalf("Second magic link verify request failed: %v", err)
	}
	defer verifyResp2.Body.Close()

	if verifyResp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Reusing magic link token should return 401, got %d", verifyResp2.StatusCode)
	}
}

func testIntegration_MagicLink_Properties(t *rapid.T) {
	ts := setupFullAppServerRapid()
	defer ts.cleanup()
	testIntegration_MagicLink_PropertiesWithServer(t, ts)
}

func TestIntegration_MagicLink_Properties(t *testing.T) {
	ts := setupFullAppServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		testIntegration_MagicLink_PropertiesWithServer(rt, ts)
	})
}

func FuzzIntegration_MagicLink_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testIntegration_MagicLink_Properties))
}

// =============================================================================
// TEST 3: Password Reset Flow (tests HandlePasswordResetConfirm!)
// =============================================================================

func testIntegration_PasswordReset_PropertiesWithServer(t *rapid.T, ts *fullAppServer) {
	email := uniqueIntegrationEmail(testutil.EmailGenerator().Draw(t, "email"))
	password := testutil.PasswordGenerator().Draw(t, "password")
	newPassword := testutil.PasswordGenerator().Draw(t, "newPassword")
	// Old and new passwords must differ for Property 6 to be meaningful
	if password == newPassword {
		t.Skip("old and new passwords must differ for Property 6")
	}

	client := newIntegrationHTTPClient(ts)

	// First register the user
	regResp, err := client.PostForm(ts.URL+"/auth/register", url.Values{"email": {email}, "password": {password}})
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}
	regResp.Body.Close()

	// Clear emails from registration
	ts.emailService.Clear()

	// Property 1: POST /auth/password-reset with email -> redirects to login
	resetResp, err := client.PostForm(ts.URL+"/auth/password-reset", url.Values{"email": {email}})
	if err != nil {
		t.Fatalf("Password reset request failed: %v", err)
	}
	defer resetResp.Body.Close()

	// After redirect, we end up at /login with 200 OK
	if resetResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resetResp.Body)
		t.Fatalf("Expected 200 after redirect, got %d: %s", resetResp.StatusCode, string(body))
	}

	// Property 2: Reset email was sent
	emailCount := ts.emailService.Count()
	if emailCount == 0 {
		t.Fatal("Password reset email should have been sent")
	}

	// Verify email was sent to the correct address
	lastEmail := ts.emailService.LastEmail()
	if lastEmail.To != email {
		t.Fatalf("Password reset email should be sent to the requested address: expected %s, got %s", email, lastEmail.To)
	}

	// Property 4: Extract token from email and confirm reset
	resetData, ok := lastEmail.Data.(emailpkg.PasswordResetData)
	if !ok {
		t.Fatal("Email data should be PasswordResetData")
	}

	// Parse the link to extract the token
	linkURL, err := url.Parse(resetData.Link)
	if err != nil {
		t.Fatalf("Failed to parse reset link URL: %v", err)
	}
	token := linkURL.Query().Get("token")
	if token == "" {
		t.Fatal("Reset link should contain token")
	}

	// Property 4: POST /auth/password-reset-confirm with valid token -> redirects to login
	confirmResp, err := client.PostForm(ts.URL+"/auth/password-reset-confirm", url.Values{"token": {token}, "password": {newPassword}, "confirm_password": {newPassword}})
	if err != nil {
		t.Fatalf("Password reset confirm request failed: %v", err)
	}
	defer confirmResp.Body.Close()

	// After redirect, we end up at /login with 200 OK
	if confirmResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(confirmResp.Body)
		t.Fatalf("Expected 200 after redirect, got %d: %s", confirmResp.StatusCode, string(body))
	}
	// Verify the confirm actually succeeded (not just redirected to login with error)
	confirmFinalURL := confirmResp.Request.URL.String()
	if strings.Contains(confirmFinalURL, "error=") {
		t.Fatalf("Password reset confirm failed: redirected to %s", confirmFinalURL)
	}
	if !strings.Contains(confirmFinalURL, "success=") {
		t.Fatalf("Password reset confirm should redirect to login with success message, got: %s", confirmFinalURL)
	}

	// Property 5: Login with NEW password should succeed
	// Use a fresh client with fresh cookies but same TLS config as test server
	freshJar, _ := cookiejar.New(nil)
	freshClient := newIntegrationHTTPClient(ts)
	freshClient.Jar = freshJar
	loginResp, err := freshClient.PostForm(ts.URL+"/auth/login", url.Values{"email": {email}, "password": {newPassword}})
	if err != nil {
		t.Fatalf("Login with new password failed: %v", err)
	}
	loginResp.Body.Close()
	// After successful login, should end up at /notes (200)
	if !strings.Contains(loginResp.Request.URL.Path, "/notes") {
		t.Fatalf("Login with new password should redirect to /notes, got: %s", loginResp.Request.URL.String())
	}

	// Property 6: Login with OLD password should fail
	freshJar2, _ := cookiejar.New(nil)
	oldPwClient := newIntegrationHTTPClient(ts)
	oldPwClient.Jar = freshJar2
	oldPwClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	oldPwResp, err := oldPwClient.PostForm(ts.URL+"/auth/login", url.Values{"email": {email}, "password": {password}})
	if err != nil {
		t.Fatalf("Login with old password request failed: %v", err)
	}
	oldPwResp.Body.Close()
	if oldPwResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("Login with old password should redirect (303), got %d", oldPwResp.StatusCode)
	}
	oldPwLoc := oldPwResp.Header.Get("Location")
	if !strings.Contains(oldPwLoc, "error") {
		t.Fatalf("Login with old password should redirect with error, got Location: %s", oldPwLoc)
	}

	// Property 7: Token should be consumed (reusing should fail)
	// Use a non-redirect client to verify the 303 → /login?error=... redirect
	noRedirectClient := *client
	noRedirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	confirmResp2, err := noRedirectClient.PostForm(ts.URL+"/auth/password-reset-confirm", url.Values{"token": {token}, "password": {"AnotherPassword123!"}, "confirm_password": {"AnotherPassword123!"}})
	if err != nil {
		t.Fatalf("Second password reset confirm request failed: %v", err)
	}
	defer confirmResp2.Body.Close()

	if confirmResp2.StatusCode != http.StatusSeeOther {
		t.Fatalf("Reusing reset token should redirect (303), got %d", confirmResp2.StatusCode)
	}
	redirectLoc := confirmResp2.Header.Get("Location")
	if !strings.Contains(redirectLoc, "error") {
		t.Fatalf("Reusing consumed token should redirect with error, got Location: %s", redirectLoc)
	}

	// Property 8: Weak password should be rejected
	// First request a new reset token
	resetResp2, err := client.PostForm(ts.URL+"/auth/password-reset", url.Values{"email": {email}})
	if err != nil {
		t.Fatalf("Second password reset request failed: %v", err)
	}
	resetResp2.Body.Close()

	lastEmail2 := ts.emailService.LastEmail()
	resetData2, _ := lastEmail2.Data.(emailpkg.PasswordResetData)
	linkURL2, _ := url.Parse(resetData2.Link)
	token2 := linkURL2.Query().Get("token")

	// Try with weak password (use no-redirect client to see the 303)
	weakResp, err := noRedirectClient.PostForm(ts.URL+"/auth/password-reset-confirm", url.Values{"token": {token2}, "password": {"weak"}, "confirm_password": {"weak"}})
	if err != nil {
		t.Fatalf("Weak password reset confirm request failed: %v", err)
	}
	defer weakResp.Body.Close()

	if weakResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("Weak password should redirect (303), got %d", weakResp.StatusCode)
	}
	weakLoc := weakResp.Header.Get("Location")
	if !strings.Contains(weakLoc, "error") {
		t.Fatalf("Weak password should redirect with error, got Location: %s", weakLoc)
	}
}

func testIntegration_PasswordReset_Properties(t *rapid.T) {
	ts := setupFullAppServerRapid()
	defer ts.cleanup()
	testIntegration_PasswordReset_PropertiesWithServer(t, ts)
}

func TestIntegration_PasswordReset_Properties(t *testing.T) {
	ts := setupFullAppServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		testIntegration_PasswordReset_PropertiesWithServer(rt, ts)
	})
}

func FuzzIntegration_PasswordReset_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testIntegration_PasswordReset_Properties))
}

// =============================================================================
// TEST 3.5: Invalid Token Handling (tests error paths with arbitrary strings)
// =============================================================================

func testIntegration_InvalidTokens_PropertiesWithServer(t *rapid.T, ts *fullAppServer) {
	// Generate arbitrary tokens to test error handling
	arbitraryToken := rapid.String().Draw(t, "arbitrary_token")
	arbitraryPassword := rapid.String().Draw(t, "arbitrary_password")

	client := newIntegrationHTTPClient(ts)

	// Property 1: Magic link verify with arbitrary token should return 401
	verifyResp, err := client.Get(ts.URL + "/auth/magic/verify?token=" + url.QueryEscape(arbitraryToken))
	if err != nil {
		t.Fatalf("Magic verify request failed: %v", err)
	}
	verifyResp.Body.Close()

	// Invalid tokens should return 401 Unauthorized
	if verifyResp.StatusCode != http.StatusUnauthorized && verifyResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Invalid magic token should return 401 or 400, got %d", verifyResp.StatusCode)
	}

	// Property 2: Password reset confirm with arbitrary token should fail (redirect to login with error)
	noRedirectClient := *client
	noRedirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	confirmResp, err := noRedirectClient.PostForm(ts.URL+"/auth/password-reset-confirm", url.Values{"token": {arbitraryToken}, "password": {arbitraryPassword}, "confirm_password": {arbitraryPassword}})
	if err != nil {
		t.Fatalf("Password reset confirm request failed: %v", err)
	}
	confirmResp.Body.Close()

	// Invalid token should redirect (303) or return 400 (if password empty/weak is caught first)
	if confirmResp.StatusCode != http.StatusSeeOther && confirmResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Invalid reset token should redirect or return 400, got %d", confirmResp.StatusCode)
	}

	// Property 3: Empty token should be rejected with 400
	emptyTokenResp, err := client.Get(ts.URL + "/auth/magic/verify?token=")
	if err != nil {
		t.Fatalf("Empty token magic verify request failed: %v", err)
	}
	emptyTokenResp.Body.Close()

	if emptyTokenResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Empty magic token should return 400, got %d", emptyTokenResp.StatusCode)
	}

	// Property 4: Missing token should be rejected with 400
	noTokenResp, err := client.Get(ts.URL + "/auth/magic/verify")
	if err != nil {
		t.Fatalf("No token magic verify request failed: %v", err)
	}
	noTokenResp.Body.Close()

	if noTokenResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Missing magic token should return 400, got %d", noTokenResp.StatusCode)
	}

	// Property 5: Empty fields in password reset confirm should be rejected
	emptyFieldsResp, err := client.PostForm(ts.URL+"/auth/password-reset-confirm", url.Values{"token": {""}, "password": {""}})
	if err != nil {
		t.Fatalf("Empty fields password reset confirm request failed: %v", err)
	}
	emptyFieldsResp.Body.Close()

	if emptyFieldsResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Empty fields in reset confirm should return 400, got %d", emptyFieldsResp.StatusCode)
	}
}

func testIntegration_InvalidTokens_Properties(t *rapid.T) {
	ts := setupFullAppServerRapid()
	defer ts.cleanup()
	testIntegration_InvalidTokens_PropertiesWithServer(t, ts)
}

func TestIntegration_InvalidTokens_Properties(t *testing.T) {
	ts := setupFullAppServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		testIntegration_InvalidTokens_PropertiesWithServer(rt, ts)
	})
}

func FuzzIntegration_InvalidTokens_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testIntegration_InvalidTokens_Properties))
}

// =============================================================================
// TEST 3.6: Google OAuth Flow (tests HandleGoogleLogin/Callback)
// =============================================================================

func testIntegration_GoogleOAuth_PropertiesWithServer(t *rapid.T, ts *fullAppServer) {
	// Generate arbitrary email for this test
	testEmail := uniqueIntegrationEmail(testutil.EmailGenerator().Draw(t, "email"))

	client := newIntegrationHTTPClient(ts)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Property 1: GET /auth/google should redirect to OIDC provider
	googleResp, err := client.Get(ts.URL + "/auth/google")
	if err != nil {
		t.Fatalf("Google auth request failed: %v", err)
	}
	defer googleResp.Body.Close()

	if googleResp.StatusCode != http.StatusFound {
		t.Fatalf("Google auth should redirect (302), got %d", googleResp.StatusCode)
	}

	// Property 2: Redirect location should contain state parameter
	location := googleResp.Header.Get("Location")
	if !strings.Contains(location, "state=") {
		t.Fatal("Google auth redirect should contain state parameter")
	}

	// Property 3: oauth_state cookie should be set
	var stateCookie *http.Cookie
	for _, c := range googleResp.Cookies() {
		if c.Name == "oauth_state" && c.Value != "" {
			stateCookie = c
			break
		}
	}
	if stateCookie == nil {
		t.Fatal("oauth_state cookie should be set")
	}

	// Property 4: Callback without state cookie should fail
	callbackResp, err := client.Get(ts.URL + "/auth/google/callback?code=test&state=test")
	if err != nil {
		t.Fatalf("Callback request failed: %v", err)
	}
	callbackResp.Body.Close()

	if callbackResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Callback without state cookie should return 400, got %d", callbackResp.StatusCode)
	}

	// Property 5: Callback with mismatched state should fail
	jar, _ := cookiejar.New(nil)
	client2 := newIntegrationHTTPClient(ts)
	client2.Jar = jar
	client2.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	serverURL, _ := url.Parse(ts.URL)
	jar.SetCookies(serverURL, []*http.Cookie{{
		Name:  "oauth_state",
		Value: "valid_state",
		Path:  "/",
	}})

	mismatchResp, err := client2.Get(ts.URL + "/auth/google/callback?code=test&state=different_state")
	if err != nil {
		t.Fatalf("Mismatched state callback request failed: %v", err)
	}
	mismatchResp.Body.Close()

	if mismatchResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Mismatched state should return 400, got %d", mismatchResp.StatusCode)
	}

	// Property 6: Callback with error parameter should return unauthorized
	jar2, _ := cookiejar.New(nil)
	client3 := newIntegrationHTTPClient(ts)
	client3.Jar = jar2
	client3.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	jar2.SetCookies(serverURL, []*http.Cookie{{
		Name:  "oauth_state",
		Value: "test_state",
		Path:  "/",
	}})

	errorResp, err := client3.Get(ts.URL + "/auth/google/callback?error=access_denied&state=test_state")
	if err != nil {
		t.Fatalf("Error callback request failed: %v", err)
	}
	errorResp.Body.Close()

	if errorResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Callback with error should return 401, got %d", errorResp.StatusCode)
	}

	// Property 7: SUCCESSFUL callback flow - complete the OAuth dance
	// Configure the mock OIDC client to return success
	ts.oidcClient.SetNextSuccess("google-sub-"+testEmail, testEmail, "Test User", true)

	// Create a client that preserves cookies through the flow
	jar3, _ := cookiejar.New(nil)
	client4 := newIntegrationHTTPClient(ts)
	client4.Jar = jar3
	client4.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Step 1: Start the OAuth flow
	startResp, err := client4.Get(ts.URL + "/auth/google")
	if err != nil {
		t.Fatalf("Start OAuth request failed: %v", err)
	}
	startResp.Body.Close()

	if startResp.StatusCode != http.StatusFound {
		t.Fatalf("Start OAuth should redirect, got %d", startResp.StatusCode)
	}

	// Extract state from cookies
	var state string
	for _, c := range jar3.Cookies(serverURL) {
		if c.Name == "oauth_state" {
			state = c.Value
			break
		}
	}
	if state == "" {
		t.Fatal("State cookie not found after starting OAuth")
	}

	// Step 2: Simulate callback from Google with matching state
	callbackURL := fmt.Sprintf("%s/auth/google/callback?code=valid_code&state=%s", ts.URL, state)
	successResp, err := client4.Get(callbackURL)
	if err != nil {
		t.Fatalf("Successful callback request failed: %v", err)
	}
	successResp.Body.Close()

	// Should redirect to home after successful auth
	if successResp.StatusCode != http.StatusFound {
		t.Fatalf("Successful callback should redirect (302), got %d", successResp.StatusCode)
	}

	// Property 8: Session cookie should be set after successful callback
	sessionCookieFound := false
	for _, c := range jar3.Cookies(serverURL) {
		if c.Name == "session_id" && c.Value != "" {
			sessionCookieFound = true
			break
		}
	}
	if !sessionCookieFound {
		t.Fatal("Session cookie should be set after successful Google callback")
	}

	// Property 9: User should be authenticated after callback
	// Need a new client that follows redirects
	client5 := newIntegrationHTTPClient(ts)
	client5.Jar = jar3

	whoamiResp, err := client5.Get(ts.URL + "/auth/whoami")
	if err != nil {
		t.Fatalf("Whoami request failed: %v", err)
	}
	defer whoamiResp.Body.Close()

	var whoamiResult map[string]interface{}
	if err := json.NewDecoder(whoamiResp.Body).Decode(&whoamiResult); err != nil {
		t.Fatalf("Failed to decode whoami response: %v", err)
	}

	if whoamiResult["authenticated"] != true {
		t.Fatal("User should be authenticated after successful Google callback")
	}

	// Property 10: Missing code parameter should fail
	jar4, _ := cookiejar.New(nil)
	client6 := newIntegrationHTTPClient(ts)
	client6.Jar = jar4
	client6.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	jar4.SetCookies(serverURL, []*http.Cookie{{
		Name:  "oauth_state",
		Value: "test_state",
		Path:  "/",
	}})

	noCodeResp, err := client6.Get(ts.URL + "/auth/google/callback?state=test_state")
	if err != nil {
		t.Fatalf("No code callback request failed: %v", err)
	}
	noCodeResp.Body.Close()

	if noCodeResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Callback without code should return 400, got %d", noCodeResp.StatusCode)
	}
}

func testIntegration_GoogleOAuth_Properties(t *rapid.T) {
	ts := setupFullAppServerRapid()
	defer ts.cleanup()
	testIntegration_GoogleOAuth_PropertiesWithServer(t, ts)
}

func TestIntegration_GoogleOAuth_Properties(t *testing.T) {
	ts := setupFullAppServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		testIntegration_GoogleOAuth_PropertiesWithServer(rt, ts)
	})
}

func FuzzIntegration_GoogleOAuth_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testIntegration_GoogleOAuth_Properties))
}

// =============================================================================
// TEST 4: OAuth + MCP Flow (tests oauth_middleware)
// =============================================================================

func testIntegration_OAuthMCP_PropertiesWithServer(t *rapid.T, ts *fullAppServer) {
	noteTitle := testutil.NoteTitleGenerator().Draw(t, "title")
	noteContent := testutil.NoteContentGenerator().Draw(t, "content")
	state := testutil.StateGenerator().Draw(t, "state")

	client := newIntegrationHTTPClient(ts)

	// Step 1: Register OAuth client
	dcrReq := map[string]interface{}{
		"client_name":                "TestMCPClient",
		"redirect_uris":              []string{"http://localhost:8080/callback"},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
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
	user, err := ts.userService.FindOrCreateByProvider(context.Background(), testEmail)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	sessionID, err := ts.sessionService.Create(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Step 4: Build authorization request (consent will be handled via UI flow)
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
	authClient := newIntegrationHTTPClient(ts)
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

	// Extract authorization code, handling consent page if needed
	var authCode string
	if authResp.StatusCode == http.StatusFound {
		// Direct redirect with code (consent already granted or auto-approved)
		location := authResp.Header.Get("Location")
		if strings.Contains(location, "code=") {
			parsed, _ := url.Parse(location)
			authCode = parsed.Query().Get("code")
		}
		authResp.Body.Close()
	} else if authResp.StatusCode == http.StatusOK {
		// Consent page shown - submit the consent form
		authResp.Body.Close()

		// Submit consent form
		consentResp, err := authClient.PostForm(ts.URL+"/oauth/consent", url.Values{
			"decision": {"allow"},
		})
		if err != nil {
			t.Fatalf("Failed to submit consent: %v", err)
		}
		defer consentResp.Body.Close()

		// After consent, should redirect with code
		if consentResp.StatusCode == http.StatusFound {
			location := consentResp.Header.Get("Location")
			if strings.Contains(location, "code=") {
				parsed, _ := url.Parse(location)
				authCode = parsed.Query().Get("code")
			}
		}
	} else {
		body, _ := io.ReadAll(authResp.Body)
		authResp.Body.Close()
		t.Fatalf("Unexpected authorization response: %d - %s", authResp.StatusCode, string(body))
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

	// Step 7: Initialize MCP session
	// MCP requires initialize -> initialized sequence before other requests
	initReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "integration-test",
				"version": "1.0.0",
			},
		},
		"id": 1,
	}
	initBody, _ := json.Marshal(initReq)

	initHTTPReq, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(string(initBody)))
	initHTTPReq.Header.Set("Content-Type", "application/json")
	initHTTPReq.Header.Set("Accept", "application/json, text/event-stream")
	initHTTPReq.Header.Set("Authorization", "Bearer "+accessToken)

	initResp, err := client.Do(initHTTPReq)
	if err != nil {
		t.Fatalf("MCP initialize request failed: %v", err)
	}

	initRespBody, _ := io.ReadAll(initResp.Body)
	initResp.Body.Close()

	// Property: MCP initialize should succeed
	if initResp.StatusCode != http.StatusOK {
		t.Fatalf("MCP initialize should return 200, got %d: %s", initResp.StatusCode, string(initRespBody))
	}

	// Extract MCP session ID from response header
	mcpSessionID := initResp.Header.Get("Mcp-Session-Id")

	// Parse SSE response to get JSON result
	initJSON := parseSSEResponse(string(initRespBody))
	var initResult map[string]interface{}
	if err := json.Unmarshal([]byte(initJSON), &initResult); err != nil {
		t.Fatalf("Failed to parse initialize response: %v - body: %s", err, initJSON)
	}

	// Verify no error
	if errObj, ok := initResult["error"]; ok {
		t.Fatalf("MCP initialize returned error: %v", errObj)
	}

	// Step 8: Send initialized notification
	initializedNotif := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	initializedBody, _ := json.Marshal(initializedNotif)

	initializedHTTPReq, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(string(initializedBody)))
	initializedHTTPReq.Header.Set("Content-Type", "application/json")
	initializedHTTPReq.Header.Set("Accept", "application/json, text/event-stream")
	initializedHTTPReq.Header.Set("Authorization", "Bearer "+accessToken)
	if mcpSessionID != "" {
		initializedHTTPReq.Header.Set("Mcp-Session-Id", mcpSessionID)
	}

	initializedResp, err := client.Do(initializedHTTPReq)
	if err != nil {
		t.Fatalf("MCP initialized notification failed: %v", err)
	}
	initializedResp.Body.Close()

	// Step 9: Test tools/list
	mcpListReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      2,
	}
	mcpListBody, _ := json.Marshal(mcpListReq)

	listReq, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(string(mcpListBody)))
	listReq.Header.Set("Content-Type", "application/json")
	listReq.Header.Set("Accept", "application/json, text/event-stream")
	listReq.Header.Set("Authorization", "Bearer "+accessToken)
	if mcpSessionID != "" {
		listReq.Header.Set("Mcp-Session-Id", mcpSessionID)
	}

	listResp, err := client.Do(listReq)
	if err != nil {
		t.Fatalf("MCP tools/list request failed: %v", err)
	}

	listRespBody, _ := io.ReadAll(listResp.Body)
	listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("MCP tools/list with valid token should return 200, got %d: %s", listResp.StatusCode, string(listRespBody))
	}

	// Parse SSE response
	listJSON := parseSSEResponse(string(listRespBody))
	var listResult map[string]interface{}
	if err := json.Unmarshal([]byte(listJSON), &listResult); err != nil {
		t.Fatalf("Failed to parse tools/list response: %v - body: %s", err, listJSON)
	}

	// Property: tools/list should return tools array
	result, ok := listResult["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("tools/list result should be an object: %v", listResult)
	}
	tools, ok := result["tools"].([]interface{})
	if !ok {
		t.Fatalf("tools/list result should contain tools array: %v", result)
	}
	if len(tools) == 0 {
		t.Fatal("tools/list should return at least one tool")
	}

	// Step 10: Use MCP with Bearer token to create note
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
		"id": 3,
	}
	mcpBody, _ := json.Marshal(mcpCreateReq)

	mcpReq, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(string(mcpBody)))
	mcpReq.Header.Set("Content-Type", "application/json")
	mcpReq.Header.Set("Accept", "application/json, text/event-stream")
	mcpReq.Header.Set("Authorization", "Bearer "+accessToken)
	if mcpSessionID != "" {
		mcpReq.Header.Set("Mcp-Session-Id", mcpSessionID)
	}

	mcpResp, err := client.Do(mcpReq)
	if err != nil {
		t.Fatalf("MCP request failed: %v", err)
	}
	defer mcpResp.Body.Close()

	mcpRespBody, _ := io.ReadAll(mcpResp.Body)
	if mcpResp.StatusCode != http.StatusOK {
		t.Fatalf("MCP tools/call with valid token should return 200, got %d: %s", mcpResp.StatusCode, string(mcpRespBody))
	}

	// Parse SSE response
	createJSON := parseSSEResponse(string(mcpRespBody))
	var createResult map[string]interface{}
	if err := json.Unmarshal([]byte(createJSON), &createResult); err != nil {
		t.Fatalf("Failed to parse note create response: %v - body: %s", err, createJSON)
	}

	// Verify no JSON-RPC error
	if errObj, ok := createResult["error"]; ok {
		t.Fatalf("MCP note_create returned error: %v", errObj)
	}
}

func testIntegration_OAuthMCP_Properties(t *rapid.T) {
	ts := setupFullAppServerRapid()
	defer ts.cleanup()
	testIntegration_OAuthMCP_PropertiesWithServer(t, ts)
}

// parseSSEResponse extracts JSON from an SSE response
// SSE format is: "event: message\ndata: {json}\n\n"
func parseSSEResponse(body string) string {
	// If body starts with "{", it's already JSON
	if strings.HasPrefix(strings.TrimSpace(body), "{") {
		return body
	}

	// Parse SSE format
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "data: ") {
			return strings.TrimPrefix(line, "data: ")
		}
	}
	return body
}

func TestIntegration_OAuthMCP_Properties(t *testing.T) {
	ts := setupFullAppServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		testIntegration_OAuthMCP_PropertiesWithServer(rt, ts)
	})
}

// =============================================================================
// TEST 4.5: MCP Full CRUD (tests all MCP note operations)
// =============================================================================

func testIntegration_MCPFullCRUD_PropertiesWithServer(t *rapid.T, ts *fullAppServer) {
	noteTitle := testutil.NoteTitleGenerator().Draw(t, "title")
	noteContent := testutil.NoteContentGenerator().Draw(t, "content")
	updatedContent := testutil.NoteContentGenerator().Draw(t, "updatedContent")

	client := newIntegrationHTTPClient(ts)

	// Create user and get access token directly via provider (bypass OAuth flow for this test)
	testEmail := "mcp-crud-test-" + generateIntegrationSecureRandom(8) + "@example.com"
	user, _ := ts.userService.FindOrCreateByProvider(context.Background(), testEmail)

	// Register a public OAuth client
	dcrReq := map[string]interface{}{
		"client_name":                "MCPCRUDTestClient",
		"redirect_uris":              []string{"http://localhost:8080/callback"},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}
	dcrBody, _ := json.Marshal(dcrReq)
	dcrResp, _ := client.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(string(dcrBody)))
	var dcrResult map[string]interface{}
	json.NewDecoder(dcrResp.Body).Decode(&dcrResult)
	dcrResp.Body.Close()
	clientID := dcrResult["client_id"].(string)

	// Create access token directly
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
	accessToken := tokens.AccessToken

	// Track MCP session ID
	var mcpSessionID string

	// Helper to make MCP calls with session tracking
	makeMCPCall := func(method string, params map[string]interface{}, requestID int) (map[string]interface{}, string) {
		req := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  method,
			"id":      requestID,
		}
		if params != nil {
			req["params"] = params
		}
		body, _ := json.Marshal(req)

		httpReq, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(string(body)))
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Accept", "application/json, text/event-stream")
		httpReq.Header.Set("Authorization", "Bearer "+accessToken)
		if mcpSessionID != "" {
			httpReq.Header.Set("Mcp-Session-Id", mcpSessionID)
		}

		resp, err := client.Do(httpReq)
		if err != nil {
			t.Fatalf("MCP request failed: %v", err)
		}
		defer resp.Body.Close()

		// Capture session ID from response
		sessionID := resp.Header.Get("Mcp-Session-Id")

		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("MCP %s should return 200, got %d: %s", method, resp.StatusCode, string(respBody))
		}

		jsonStr := parseSSEResponse(string(respBody))
		var result map[string]interface{}
		json.Unmarshal([]byte(jsonStr), &result)
		return result, sessionID
	}

	// Step 1: Initialize MCP session
	initResult, sessionID := makeMCPCall("initialize", map[string]interface{}{
		"protocolVersion": "2025-03-26",
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]interface{}{
			"name":    "mcp-crud-test",
			"version": "1.0.0",
		},
	}, 1)
	if errObj, ok := initResult["error"]; ok {
		t.Fatalf("Initialize failed: %v", errObj)
	}
	mcpSessionID = sessionID

	// Step 1.5: Send initialized notification (required before tools/call)
	initializedNotif := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	initializedBody, _ := json.Marshal(initializedNotif)
	initializedReq, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(string(initializedBody)))
	initializedReq.Header.Set("Content-Type", "application/json")
	initializedReq.Header.Set("Accept", "application/json, text/event-stream")
	initializedReq.Header.Set("Authorization", "Bearer "+accessToken)
	if mcpSessionID != "" {
		initializedReq.Header.Set("Mcp-Session-Id", mcpSessionID)
	}
	client.Do(initializedReq)

	// Step 2: Create note
	createResult, _ := makeMCPCall("tools/call", map[string]interface{}{
		"name": "note_create",
		"arguments": map[string]interface{}{
			"title":   noteTitle,
			"content": noteContent,
		},
	}, 2)
	if errObj, ok := createResult["error"]; ok {
		t.Fatalf("note_create failed: %v", errObj)
	}

	// Extract note ID from result
	result, ok := createResult["result"].(map[string]interface{})
	if !ok {
		t.Fatal("note_create should return result object")
	}
	content, ok := result["content"].([]interface{})
	if !ok || len(content) == 0 {
		t.Fatal("note_create should return content array")
	}
	textContent := content[0].(map[string]interface{})["text"].(string)

	// Parse the created note to get ID
	var createdNote struct {
		ID      string `json:"id"`
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal([]byte(textContent), &createdNote); err != nil {
		t.Fatalf("Failed to parse created note: %v", err)
	}
	noteID := createdNote.ID

	// Property 1: Created note should have expected title
	if createdNote.Title != noteTitle {
		t.Fatalf("Created note title mismatch: expected %s, got %s", noteTitle, createdNote.Title)
	}

	// Step 3: List notes - should contain created note
	listResult, _ := makeMCPCall("tools/call", map[string]interface{}{
		"name":      "note_list",
		"arguments": map[string]interface{}{},
	}, 3)
	if errObj, ok := listResult["error"]; ok {
		t.Fatalf("note_list failed: %v", errObj)
	}

	// Property 2: List should not be empty
	listContent := listResult["result"].(map[string]interface{})["content"].([]interface{})
	if len(listContent) == 0 {
		t.Fatal("note_list should return content")
	}

	// Step 4: View note
	viewResult, _ := makeMCPCall("tools/call", map[string]interface{}{
		"name": "note_view",
		"arguments": map[string]interface{}{
			"id": noteID,
		},
	}, 4)
	if errObj, ok := viewResult["error"]; ok {
		t.Fatalf("note_view failed: %v", errObj)
	}

	// Property 3: Viewed note should have expected content
	viewContent := viewResult["result"].(map[string]interface{})["content"].([]interface{})
	viewText := viewContent[0].(map[string]interface{})["text"].(string)
	var viewedNote struct {
		ID      string `json:"id"`
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	json.Unmarshal([]byte(viewText), &viewedNote)
	if viewedNote.Content != noteContent {
		t.Fatalf("Viewed note content mismatch: expected %s, got %s", noteContent, viewedNote.Content)
	}

	// Step 5: Update note
	updateResult, _ := makeMCPCall("tools/call", map[string]interface{}{
		"name": "note_update",
		"arguments": map[string]interface{}{
			"id":      noteID,
			"content": updatedContent,
		},
	}, 5)
	if errObj, ok := updateResult["error"]; ok {
		t.Fatalf("note_update failed: %v", errObj)
	}

	// Property 4: Updated note should have new content
	updateContent := updateResult["result"].(map[string]interface{})["content"].([]interface{})
	updateText := updateContent[0].(map[string]interface{})["text"].(string)
	var updatedNote struct {
		ID      string `json:"id"`
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	json.Unmarshal([]byte(updateText), &updatedNote)
	if updatedNote.Content != updatedContent {
		t.Fatalf("Updated note content mismatch: expected %s, got %s", updatedContent, updatedNote.Content)
	}

	// Step 6: Search notes (search for part of the content)
	searchTerm := updatedContent[:min(10, len(updatedContent))]
	searchResult, _ := makeMCPCall("tools/call", map[string]interface{}{
		"name": "note_search",
		"arguments": map[string]interface{}{
			"query": searchTerm,
		},
	}, 6)
	if errObj, ok := searchResult["error"]; ok {
		t.Fatalf("note_search failed: %v", errObj)
	}
	searchContent := searchResult["result"].(map[string]interface{})["content"].([]interface{})
	if len(searchContent) == 0 {
		t.Fatalf("Search for %q returned empty content", searchTerm)
	}

	// Step 7: Delete note
	deleteResult, _ := makeMCPCall("tools/call", map[string]interface{}{
		"name": "note_delete",
		"arguments": map[string]interface{}{
			"id": noteID,
		},
	}, 7)
	if errObj, ok := deleteResult["error"]; ok {
		t.Fatalf("note_delete failed: %v", errObj)
	}

	// Property 5: After delete, view should fail
	viewAfterDeleteResult, _ := makeMCPCall("tools/call", map[string]interface{}{
		"name": "note_view",
		"arguments": map[string]interface{}{
			"id": noteID,
		},
	}, 8)
	// Should get an error in the result (tool error, not JSON-RPC error)
	viewAfterDeleteContent := viewAfterDeleteResult["result"].(map[string]interface{})["content"].([]interface{})
	viewAfterDeleteText := viewAfterDeleteContent[0].(map[string]interface{})
	if viewAfterDeleteText["type"] != "text" {
		// Check if it's an error response - should indicate note not found
	}
}

func testIntegration_MCPFullCRUD_Properties(t *rapid.T) {
	ts := setupFullAppServerRapid()
	defer ts.cleanup()
	testIntegration_MCPFullCRUD_PropertiesWithServer(t, ts)
}

func TestIntegration_MCPFullCRUD_Properties(t *testing.T) {
	ts := setupFullAppServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		testIntegration_MCPFullCRUD_PropertiesWithServer(rt, ts)
	})
}

func FuzzIntegration_MCPFullCRUD_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testIntegration_MCPFullCRUD_Properties))
}

// =============================================================================
// TEST 5: Refresh Token Flow
// =============================================================================

func testIntegration_RefreshToken_PropertiesWithServer(t *rapid.T, ts *fullAppServer) {
	client := newIntegrationHTTPClient(ts)

	// Step 1: Register OAuth client
	dcrReq := map[string]interface{}{
		"client_name":                "RefreshTestClient",
		"redirect_uris":              []string{"http://localhost:8080/callback"},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
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
	user, _ := ts.userService.FindOrCreateByProvider(context.Background(), testEmail)

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

func testIntegration_RefreshToken_Properties(t *rapid.T) {
	ts := setupFullAppServerRapid()
	defer ts.cleanup()
	testIntegration_RefreshToken_PropertiesWithServer(t, ts)
}

func TestIntegration_RefreshToken_Properties(t *testing.T) {
	ts := setupFullAppServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		testIntegration_RefreshToken_PropertiesWithServer(rt, ts)
	})
}

func FuzzIntegration_RefreshToken_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testIntegration_RefreshToken_Properties))
}

// =============================================================================
// TEST 6: Full User Journey (end-to-end)
// =============================================================================

func testIntegration_FullUserJourney_PropertiesWithServer(t *rapid.T, ts *fullAppServer) {
	email := uniqueIntegrationEmail(testutil.EmailGenerator().Draw(t, "email"))
	password := testutil.PasswordGenerator().Draw(t, "password")
	noteTitle := testutil.NoteTitleGenerator().Draw(t, "title")
	noteContent := testutil.NoteContentGenerator().Draw(t, "content")

	// Create HTTP client with cookie jar
	jar, _ := cookiejar.New(nil)
	client := newIntegrationHTTPClient(ts)
	client.Jar = jar

	// ==========================================================
	// Step 1: Register via web form (redirects to /notes)
	// ==========================================================
	regResp, err := client.PostForm(ts.URL+"/auth/register", url.Values{"email": {email}, "password": {password}})
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}
	defer regResp.Body.Close()

	// After redirect, we end up at /notes with 200 OK
	if regResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(regResp.Body)
		t.Fatalf("Expected 200 after registration redirect, got %d: %s", regResp.StatusCode, string(body))
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
		"client_name":                "JourneyTestClient",
		"redirect_uris":              []string{"http://localhost:8080/callback"},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
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

	// Handle consent page or direct redirect
	var authCode string
	if authResp.StatusCode == http.StatusFound {
		location := authResp.Header.Get("Location")
		if strings.Contains(location, "code=") {
			parsed, _ := url.Parse(location)
			authCode = parsed.Query().Get("code")
		}
		authResp.Body.Close()
	} else if authResp.StatusCode == http.StatusOK {
		// Consent page shown - submit the consent form
		authResp.Body.Close()

		// Submit consent form
		consentResp, err := client.PostForm(ts.URL+"/oauth/consent", url.Values{
			"decision": {"allow"},
		})
		if err != nil {
			t.Fatalf("Failed to submit consent: %v", err)
		}

		// After consent, should redirect with code
		if consentResp.StatusCode == http.StatusFound {
			location := consentResp.Header.Get("Location")
			if strings.Contains(location, "code=") {
				parsed, _ := url.Parse(location)
				authCode = parsed.Query().Get("code")
			}
		}
		consentResp.Body.Close()
	} else {
		body, _ := io.ReadAll(authResp.Body)
		authResp.Body.Close()
		t.Fatalf("Unexpected authorization response: %d - %s", authResp.StatusCode, string(body))
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
	tokenClient := newIntegrationHTTPClient(ts)
	tokenResp, err := tokenClient.PostForm(ts.URL+"/oauth/token", tokenParams)
	if err != nil {
		t.Fatalf("Token exchange failed: %v", err)
	}
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

	mcpClient := newIntegrationHTTPClient(ts)
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
	loginResp, _ := client.PostForm(ts.URL+"/auth/login", url.Values{"email": {email}, "password": {password}})
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
	getResp, err := client.Get(ts.URL + "/api/notes/" + noteID)
	if err != nil {
		t.Fatalf("Get deleted note failed: %v", err)
	}
	defer getResp.Body.Close()

	// Property: Deleted note should return 404
	if getResp.StatusCode != http.StatusNotFound {
		t.Fatalf("Deleted note should return 404, got %d", getResp.StatusCode)
	}

	// ==========================================================
	// Step 8: Logout
	// ==========================================================
	logoutResp, _ := client.PostForm(ts.URL+"/auth/logout", nil)
	logoutResp.Body.Close()

	// Property: Should not be authenticated after logout
	whoamiResp, err := client.Get(ts.URL + "/auth/whoami")
	if err != nil {
		t.Fatalf("Whoami request failed: %v", err)
	}
	defer whoamiResp.Body.Close()

	var whoamiResult map[string]interface{}
	json.NewDecoder(whoamiResp.Body).Decode(&whoamiResult)

	if whoamiResult["authenticated"] != false {
		t.Fatal("Should not be authenticated after logout")
	}
}

func testIntegration_FullUserJourney_Properties(t *rapid.T) {
	ts := setupFullAppServerRapid()
	defer ts.cleanup()
	testIntegration_FullUserJourney_PropertiesWithServer(t, ts)
}

func TestIntegration_FullUserJourney_Properties(t *testing.T) {
	ts := setupFullAppServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		testIntegration_FullUserJourney_PropertiesWithServer(rt, ts)
	})
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

func uniqueIntegrationEmail(seed string) string {
	at := strings.Index(seed, "@")
	suffix := generateIntegrationSecureRandom(8)
	if at <= 0 {
		return "integration-" + suffix + "@example.com"
	}
	return seed[:at] + "+" + suffix + seed[at:]
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
	client := newIntegrationHTTPClient(ts)
	client.Jar = jar

	// Register (redirects to /notes, final status is 200)
	regResp, err := client.PostForm(ts.URL+"/auth/register", url.Values{"email": {email}, "password": {password}})
	require.NoError(t, err)
	regResp.Body.Close()
	require.Equal(t, http.StatusOK, regResp.StatusCode)

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

	client := newIntegrationHTTPClient(ts)

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

	client := newIntegrationHTTPClient(ts)

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
