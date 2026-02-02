// Package openai provides conformance tests for OpenAI function calling integration.
// These tests verify that OpenAI's gpt-5-mini model can correctly use function calling
// via the Responses API to interact with our notes HTTP API WITH OAUTH AUTHENTICATION.
//
// KEY DIFFERENCE FROM PREVIOUS VERSION:
// This file now uses REAL OAuth authentication flow instead of bypassing auth
// with a hardcoded user ID. This tests the full production flow:
// OpenAI API → Function calling → OAuth-protected HTTP API → Notes CRUD
package openai

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/ed25519"
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
	"time"

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	emailpkg "github.com/kuitang/agent-notes/internal/email"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/kuitang/agent-notes/internal/oauth"
	"github.com/kuitang/agent-notes/internal/web"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/responses"
	"pgregory.net/rapid"
)

const (
	// Model to use - MUST be gpt-5-mini per CLAUDE.md requirements
	OpenAIModel = "gpt-5-mini"
)

// =============================================================================
// Tool Definitions for Responses API
// =============================================================================

// Define tool parameters using the Responses API format
var (
	toolCreateNote = responses.ToolUnionParam{
		OfFunction: &responses.FunctionToolParam{
			Name:        "create_note",
			Description: openai.String("Create a new note with a title and optional content"),
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"title": map[string]any{
						"type":        "string",
						"description": "The title of the note (required)",
					},
					"content": map[string]any{
						"type":        "string",
						"description": "The content/body of the note (optional)",
					},
				},
				"required":             []string{"title"},
				"additionalProperties": false,
			},
		},
	}

	toolReadNote = responses.ToolUnionParam{
		OfFunction: &responses.FunctionToolParam{
			Name:        "read_note",
			Description: openai.String("Read a note by its ID"),
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "The unique ID of the note to read",
					},
				},
				"required":             []string{"id"},
				"additionalProperties": false,
			},
		},
	}

	toolUpdateNote = responses.ToolUnionParam{
		OfFunction: &responses.FunctionToolParam{
			Name:        "update_note",
			Description: openai.String("Update an existing note's title and/or content"),
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "The unique ID of the note to update",
					},
					"title": map[string]any{
						"type":        "string",
						"description": "The new title (optional)",
					},
					"content": map[string]any{
						"type":        "string",
						"description": "The new content (optional)",
					},
				},
				"required":             []string{"id"},
				"additionalProperties": false,
			},
		},
	}

	toolDeleteNote = responses.ToolUnionParam{
		OfFunction: &responses.FunctionToolParam{
			Name:        "delete_note",
			Description: openai.String("Delete a note by its ID"),
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "The unique ID of the note to delete",
					},
				},
				"required":             []string{"id"},
				"additionalProperties": false,
			},
		},
	}

	toolListNotes = responses.ToolUnionParam{
		OfFunction: &responses.FunctionToolParam{
			Name:        "list_notes",
			Description: openai.String("List all notes with optional pagination"),
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit": map[string]any{
						"type":        "integer",
						"description": "Maximum number of notes to return (default 50)",
					},
					"offset": map[string]any{
						"type":        "integer",
						"description": "Number of notes to skip (default 0)",
					},
				},
				"required":             []string{},
				"additionalProperties": false,
			},
		},
	}

	toolSearchNotes = responses.ToolUnionParam{
		OfFunction: &responses.FunctionToolParam{
			Name:        "search_notes",
			Description: openai.String("Search notes by query using full-text search"),
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "The search query to find notes",
					},
				},
				"required":             []string{"query"},
				"additionalProperties": false,
			},
		},
	}

	// allTools contains all available tool definitions
	allTools = []responses.ToolUnionParam{
		toolCreateNote,
		toolReadNote,
		toolUpdateNote,
		toolDeleteNote,
		toolListNotes,
		toolSearchNotes,
	}
)

// =============================================================================
// OAuth-Enabled Test Server Infrastructure
// =============================================================================

var openaiTestMutex sync.Mutex

// oauthTestServer wraps httptest.Server with OAuth authentication support
type oauthTestServer struct {
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
}

// oauthTestEnv holds the test environment including server and OAuth credentials
type oauthTestEnv struct {
	server      *oauthTestServer
	client      *openai.Client
	httpClient  *http.Client
	baseURL     string
	accessToken string // OAuth access token
	userID      string
	cleanup     func()
}

// setupOAuthTestEnv creates a test environment with OAuth authentication
func setupOAuthTestEnv(t testing.TB) *oauthTestEnv {
	t.Helper()
	openaiTestMutex.Lock()

	// Get API key from env
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		openaiTestMutex.Unlock()
		t.Fatal("OPENAI_API_KEY not set - run: source ~/openai_key.sh")
	}

	tempDir := t.TempDir()
	ts := createOAuthTestServer(tempDir)

	// Perform OAuth flow to get access token
	accessToken, userID := performOAuthFlow(t, ts)

	openaiClient := openai.NewClient(option.WithAPIKey(apiKey))

	env := &oauthTestEnv{
		server:      ts,
		client:      &openaiClient,
		httpClient:  ts.Client(),
		baseURL:     ts.URL,
		accessToken: accessToken,
		userID:      userID,
		cleanup: func() {
			ts.Close()
			db.ResetForTesting()
			openaiTestMutex.Unlock()
		},
	}

	return env
}

// createOAuthTestServer creates a test server with full OAuth support
func createOAuthTestServer(tempDir string) *oauthTestServer {
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
	templatesDir := findOpenAITemplatesDir()
	renderer, err := web.NewRenderer(templatesDir)
	if err != nil {
		panic("Failed to create renderer: " + err.Error())
	}

	// Create handlers
	oauthHandler := oauth.NewHandler(oauthProvider, sessionService, consentService, renderer)
	authMiddleware := auth.NewMiddleware(sessionService, keyManager)

	// Register OAuth routes
	oauthProvider.RegisterMetadataRoutes(mux)
	mux.HandleFunc("POST /oauth/register", oauthProvider.DCR)
	oauthHandler.RegisterRoutes(mux)

	// Register OAuth-protected notes API routes
	notesHandler := &oauthNotesHandler{keyManager: keyManager}
	tokenVerifier := auth.NewTokenVerifier(server.URL, server.URL, oauthProvider.PublicKey())
	resourceMetadataURL := server.URL + "/.well-known/oauth-protected-resource"

	// Notes API routes with OAuth middleware
	mux.Handle("GET /notes", auth.OAuthMiddleware(tokenVerifier, resourceMetadataURL, true)(
		authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.ListNotes))))
	mux.Handle("POST /notes", auth.OAuthMiddleware(tokenVerifier, resourceMetadataURL, true)(
		authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.CreateNote))))
	mux.Handle("GET /notes/{id}", auth.OAuthMiddleware(tokenVerifier, resourceMetadataURL, true)(
		authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.GetNote))))
	mux.Handle("PUT /notes/{id}", auth.OAuthMiddleware(tokenVerifier, resourceMetadataURL, true)(
		authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.UpdateNote))))
	mux.Handle("DELETE /notes/{id}", auth.OAuthMiddleware(tokenVerifier, resourceMetadataURL, true)(
		authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.DeleteNote))))
	mux.Handle("POST /notes/search", auth.OAuthMiddleware(tokenVerifier, resourceMetadataURL, true)(
		authMiddleware.RequireAuth(http.HandlerFunc(notesHandler.SearchNotes))))

	return &oauthTestServer{
		Server:         server,
		tempDir:        tempDir,
		sessionsDB:     sessionsDB,
		keyManager:     keyManager,
		userService:    userService,
		sessionService: sessionService,
		consentService: consentService,
		emailService:   emailService,
		oauthProvider:  oauthProvider,
	}
}

// performOAuthFlow performs the full OAuth flow and returns an access token
func performOAuthFlow(t testing.TB, ts *oauthTestServer) (string, string) {
	t.Helper()

	client := ts.Client()

	// Step 1: Register OAuth client (simulating ChatGPT DCR)
	dcrReq := map[string]interface{}{
		"client_name":                "OpenAIConformanceTestClient",
		"redirect_uris":              []string{"http://localhost:8080/callback"},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none", // Public client like Claude
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
	verifier := generateSecureRandom(64)
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Step 3: Create user and session
	testEmail := "openai-conformance-" + generateSecureRandom(8) + "@example.com"
	user, err := ts.userService.FindOrCreateByEmail(context.Background(), testEmail)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	sessionID, err := ts.sessionService.Create(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Step 4: Build authorization request
	state := generateSecureRandom(32)
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

	// Extract authorization code
	var authCode string
	if authResp.StatusCode == http.StatusFound {
		location := authResp.Header.Get("Location")
		if strings.Contains(location, "code=") {
			parsed, _ := url.Parse(location)
			authCode = parsed.Query().Get("code")
		}
		authResp.Body.Close()
	} else if authResp.StatusCode == http.StatusOK {
		// Consent page shown - submit consent
		authResp.Body.Close()

		consentResp, err := authClient.PostForm(ts.URL+"/oauth/consent", url.Values{
			"decision": {"allow"},
		})
		if err != nil {
			t.Fatalf("Failed to submit consent: %v", err)
		}
		defer consentResp.Body.Close()

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

	// Step 5: Token exchange
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
	tokenPreview := accessToken
	if len(tokenPreview) > 20 {
		tokenPreview = tokenPreview[:20]
	}
	t.Logf("[OAuth] Successfully obtained access token (first 20 chars): %s...", tokenPreview)

	return accessToken, user.ID
}

func generateSecureRandom(length int) string {
	bytes := make([]byte, length)
	if _, err := crand.Read(bytes); err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)[:length]
}

func findOpenAITemplatesDir() string {
	candidates := []string{
		"../../../web/templates",
		"../../../../web/templates",
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
// OAuth-Protected Notes Handler
// =============================================================================

type oauthNotesHandler struct {
	keyManager *crypto.KeyManager
}

func (h *oauthNotesHandler) getService(r *http.Request) (*notes.Service, error) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		return nil, fmt.Errorf("no user database in context")
	}
	return notes.NewService(userDB), nil
}

func (h *oauthNotesHandler) ListNotes(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	result, err := svc.List(50, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list notes: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *oauthNotesHandler) CreateNote(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	var params notes.CreateNoteParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	note, err := svc.Create(params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create note: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, note)
}

func (h *oauthNotesHandler) GetNote(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	id := r.PathValue("id")
	note, err := svc.Read(id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "Note not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to read note: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, note)
}

func (h *oauthNotesHandler) UpdateNote(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	id := r.PathValue("id")
	var params notes.UpdateNoteParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	note, err := svc.Update(id, params)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "Note not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to update note: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, note)
}

func (h *oauthNotesHandler) DeleteNote(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	id := r.PathValue("id")
	if err := svc.Delete(id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "Note not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to delete note: "+err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *oauthNotesHandler) SearchNotes(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	var params struct {
		Query string `json:"query"`
	}
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	results, err := svc.Search(params.Query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to search notes: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, results)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// =============================================================================
// Tool Execution with OAuth
// =============================================================================

// executeTool executes a tool call against the OAuth-protected HTTP API
func (env *oauthTestEnv) executeTool(ctx context.Context, toolName string, args json.RawMessage) (string, error) {
	var result string
	var err error

	switch toolName {
	case "create_note":
		result, err = env.executeCreateNote(ctx, args)
	case "read_note":
		result, err = env.executeReadNote(ctx, args)
	case "update_note":
		result, err = env.executeUpdateNote(ctx, args)
	case "delete_note":
		result, err = env.executeDeleteNote(ctx, args)
	case "list_notes":
		result, err = env.executeListNotes(ctx, args)
	case "search_notes":
		result, err = env.executeSearchNotes(ctx, args)
	default:
		return "", fmt.Errorf("unknown tool: %s", toolName)
	}

	return result, err
}

func (env *oauthTestEnv) executeCreateNote(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid create_note args: %w", err)
	}

	body, _ := json.Marshal(map[string]string{
		"title":   params.Title,
		"content": params.Content,
	})

	req, _ := http.NewRequestWithContext(ctx, "POST", env.baseURL+"/notes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+env.accessToken) // OAuth token!

	resp, err := env.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("create_note request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("create_note failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return string(respBody), nil
}

func (env *oauthTestEnv) executeReadNote(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid read_note args: %w", err)
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", env.baseURL+"/notes/"+params.ID, nil)
	req.Header.Set("Authorization", "Bearer "+env.accessToken)

	resp, err := env.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("read_note request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("read_note failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return string(respBody), nil
}

func (env *oauthTestEnv) executeUpdateNote(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		ID      string  `json:"id"`
		Title   *string `json:"title,omitempty"`
		Content *string `json:"content,omitempty"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid update_note args: %w", err)
	}

	updateBody := make(map[string]string)
	if params.Title != nil {
		updateBody["title"] = *params.Title
	}
	if params.Content != nil {
		updateBody["content"] = *params.Content
	}

	body, _ := json.Marshal(updateBody)

	req, _ := http.NewRequestWithContext(ctx, "PUT", env.baseURL+"/notes/"+params.ID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+env.accessToken)

	resp, err := env.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("update_note request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("update_note failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return string(respBody), nil
}

func (env *oauthTestEnv) executeDeleteNote(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid delete_note args: %w", err)
	}

	req, _ := http.NewRequestWithContext(ctx, "DELETE", env.baseURL+"/notes/"+params.ID, nil)
	req.Header.Set("Authorization", "Bearer "+env.accessToken)

	resp, err := env.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("delete_note request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("delete_note failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return `{"success": true, "message": "Note deleted successfully"}`, nil
}

func (env *oauthTestEnv) executeListNotes(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Limit  int `json:"limit"`
		Offset int `json:"offset"`
	}
	params.Limit = 50
	params.Offset = 0
	_ = json.Unmarshal(args, &params)

	url := fmt.Sprintf("%s/notes?limit=%d&offset=%d", env.baseURL, params.Limit, params.Offset)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+env.accessToken)

	resp, err := env.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("list_notes request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("list_notes failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return string(respBody), nil
}

func (env *oauthTestEnv) executeSearchNotes(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid search_notes args: %w", err)
	}

	body, _ := json.Marshal(map[string]string{"query": params.Query})
	req, _ := http.NewRequestWithContext(ctx, "POST", env.baseURL+"/notes/search", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+env.accessToken)

	resp, err := env.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("search_notes request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("search_notes failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return string(respBody), nil
}

// =============================================================================
// Conversation Management
// =============================================================================

type ToolCall struct {
	Name      string
	Arguments string
}

type Conversation struct {
	LastResponseID string
}

func (env *oauthTestEnv) runConversation(ctx context.Context, prompt string, conv *Conversation) (string, []ToolCall, error) {
	var toolCalls []ToolCall

	params := responses.ResponseNewParams{
		Model:        OpenAIModel,
		Instructions: openai.String("You are a helpful assistant that manages notes. Use the provided tools to create, read, update, delete, list, and search notes. Always use the tools when the user asks you to manage notes."),
		Input: responses.ResponseNewParamsInputUnion{
			OfString: openai.String(prompt),
		},
		Tools: allTools,
	}

	if conv != nil && conv.LastResponseID != "" {
		params.PreviousResponseID = openai.String(conv.LastResponseID)
	}

	maxIterations := 10
	var previousResponseID string

	for i := 0; i < maxIterations; i++ {
		if previousResponseID != "" {
			params.PreviousResponseID = openai.String(previousResponseID)
		}

		response, err := env.client.Responses.New(ctx, params)
		if err != nil {
			return "", toolCalls, fmt.Errorf("OpenAI Responses API error: %w", err)
		}

		previousResponseID = response.ID

		hasFunctionCalls := false
		var functionCallOutputs []responses.ResponseInputItemUnionParam

		for _, output := range response.Output {
			if output.Type == "function_call" {
				hasFunctionCalls = true

				toolCalls = append(toolCalls, ToolCall{
					Name:      output.Name,
					Arguments: output.Arguments,
				})

				result, err := env.executeTool(ctx, output.Name, json.RawMessage(output.Arguments))
				if err != nil {
					result = fmt.Sprintf(`{"error": "%s"}`, err.Error())
				}

				functionCallOutputs = append(functionCallOutputs, responses.ResponseInputItemParamOfFunctionCallOutput(output.CallID, result))
			}
		}

		if !hasFunctionCalls {
			if conv != nil {
				conv.LastResponseID = previousResponseID
			}
			return response.OutputText(), toolCalls, nil
		}

		params = responses.ResponseNewParams{
			Model:              OpenAIModel,
			PreviousResponseID: openai.String(previousResponseID),
			Input: responses.ResponseNewParamsInputUnion{
				OfInputItemList: functionCallOutputs,
			},
			Tools: allTools,
		}
	}

	return "", toolCalls, fmt.Errorf("max iterations reached without completion")
}

// =============================================================================
// Property-Based Tests with OAuth
// =============================================================================

func testOpenAI_CreateNote_Properties(t *rapid.T, env *oauthTestEnv) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	title := rapid.StringMatching(`[A-Za-z][A-Za-z0-9 ]{0,49}`).Draw(t, "title")
	content := rapid.StringMatching(`[A-Za-z0-9 .,!?]{0,200}`).Draw(t, "content")

	prompt := fmt.Sprintf("Create a note with title '%s' and content '%s'", title, content)

	response, _, err := env.runConversation(ctx, prompt, nil)
	if err != nil {
		t.Fatalf("Conversation failed: %v", err)
	}

	if !strings.Contains(strings.ToLower(response), "created") &&
		!strings.Contains(strings.ToLower(response), "note") {
		t.Logf("Response: %s", response)
	}

	listResult, err := env.executeListNotes(ctx, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Failed to list notes: %v", err)
	}

	if !strings.Contains(listResult, title) {
		t.Fatalf("Created note not found in list. Title: %s, List: %s", title, listResult)
	}
}

func testOpenAI_CRUD_Roundtrip_Properties(t *rapid.T, env *oauthTestEnv) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	title := rapid.StringMatching(`[A-Za-z][A-Za-z0-9 ]{2,20}`).Draw(t, "title")
	content := rapid.StringMatching(`[A-Za-z0-9 .,]{5,50}`).Draw(t, "content")
	updatedTitle := rapid.StringMatching(`Updated [A-Za-z0-9]{2,10}`).Draw(t, "updatedTitle")

	// Step 1: Create note
	createPrompt := fmt.Sprintf("Create a note titled '%s' with content '%s'. Tell me the ID of the created note.", title, content)
	createResp, _, err := env.runConversation(ctx, createPrompt, nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	t.Logf("Create response: %s", createResp)

	listResult, err := env.executeListNotes(ctx, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	var listResp notes.NoteListResult
	if err := json.Unmarshal([]byte(listResult), &listResp); err != nil {
		t.Fatalf("Failed to parse list response: %v", err)
	}

	if len(listResp.Notes) == 0 {
		t.Fatalf("No notes found after create")
	}

	var noteID string
	for _, note := range listResp.Notes {
		if note.Title == title {
			noteID = note.ID
			break
		}
	}
	if noteID == "" {
		t.Fatalf("Created note not found in list")
	}

	// Step 2: Read note
	readPrompt := fmt.Sprintf("Read the note with ID '%s' and tell me its title and content.", noteID)
	readResp, _, err := env.runConversation(ctx, readPrompt, nil)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	t.Logf("Read response: %s", readResp)

	// Step 3: Update note
	updatePrompt := fmt.Sprintf("Update the note with ID '%s' and change its title to '%s'.", noteID, updatedTitle)
	updateResp, _, err := env.runConversation(ctx, updatePrompt, nil)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	t.Logf("Update response: %s", updateResp)

	readResult, err := env.executeReadNote(ctx, json.RawMessage(fmt.Sprintf(`{"id":"%s"}`, noteID)))
	if err != nil {
		t.Fatalf("Read after update failed: %v", err)
	}

	var updatedNote notes.Note
	if err := json.Unmarshal([]byte(readResult), &updatedNote); err != nil {
		t.Fatalf("Failed to parse updated note: %v", err)
	}

	if updatedNote.Title != updatedTitle {
		t.Fatalf("Update failed: expected title '%s', got '%s'", updatedTitle, updatedNote.Title)
	}

	// Step 4: Delete note
	deletePrompt := fmt.Sprintf("Delete the note with ID '%s'.", noteID)
	deleteResp, _, err := env.runConversation(ctx, deletePrompt, nil)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	t.Logf("Delete response: %s", deleteResp)

	_, err = env.executeReadNote(ctx, json.RawMessage(fmt.Sprintf(`{"id":"%s"}`, noteID)))
	if err == nil {
		t.Fatalf("Note still exists after delete")
	}
	if !strings.Contains(err.Error(), "404") && !strings.Contains(err.Error(), "not found") {
		t.Fatalf("Unexpected error after delete: %v", err)
	}
}

// =============================================================================
// Test Entry Points
// =============================================================================

func TestOpenAI_CreateNote_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping OpenAI test in short mode")
	}

	env := setupOAuthTestEnv(t)
	defer env.cleanup()

	rapid.Check(t, func(t *rapid.T) {
		testOpenAI_CreateNote_Properties(t, env)
	})
}

func TestOpenAI_CRUD_Roundtrip_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping OpenAI test in short mode")
	}

	env := setupOAuthTestEnv(t)
	defer env.cleanup()

	rapid.Check(t, func(t *rapid.T) {
		testOpenAI_CRUD_Roundtrip_Properties(t, env)
	})
}

// TestOpenAI_OAuth_Integration tests the full OAuth + OpenAI + Notes flow
func TestOpenAI_OAuth_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping OpenAI test in short mode")
	}

	env := setupOAuthTestEnv(t)
	defer env.cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	t.Logf("[OAuth Integration] Using access token for authenticated requests")
	t.Logf("[OAuth Integration] User ID: %s", env.userID)

	// Test 1: Verify OAuth token works for create
	t.Run("OAuthCreate", func(t *testing.T) {
		prompt := "Create a note titled 'OAuth Integration Test' with content 'Testing OAuth authentication flow'"
		resp, toolCalls, err := env.runConversation(ctx, prompt, nil)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))

		// Verify at least one tool call was made
		if len(toolCalls) == 0 {
			t.Fatal("Expected at least one tool call")
		}

		// Verify the create_note tool was called
		found := false
		for _, tc := range toolCalls {
			if tc.Name == "create_note" {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("Expected create_note tool call")
		}
	})

	// Test 2: Verify OAuth token works for list
	t.Run("OAuthList", func(t *testing.T) {
		prompt := "List all my notes"
		resp, _, err := env.runConversation(ctx, prompt, nil)
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}
		t.Logf("Response: %s", resp)
	})

	// Test 3: Verify unauthorized request fails
	t.Run("UnauthorizedFails", func(t *testing.T) {
		// Make request without OAuth token
		req, _ := http.NewRequest("GET", env.baseURL+"/notes", nil)
		// Deliberately NOT setting Authorization header

		resp, err := env.httpClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		// Should return 401 Unauthorized
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Expected 401 Unauthorized, got %d", resp.StatusCode)
		}

		// Should have WWW-Authenticate header
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth == "" {
			t.Fatal("Expected WWW-Authenticate header")
		}
		if !strings.Contains(wwwAuth, "Bearer") {
			t.Fatalf("Expected Bearer challenge, got: %s", wwwAuth)
		}
	})
}

// TestOpenAI_ToolDefinitions tests that all tool definitions are valid
func TestOpenAI_ToolDefinitions(t *testing.T) {
	expectedTools := []string{
		"create_note",
		"read_note",
		"update_note",
		"delete_note",
		"list_notes",
		"search_notes",
	}

	if len(allTools) != len(expectedTools) {
		t.Fatalf("Expected %d tools, got %d", len(expectedTools), len(allTools))
	}

	for i, tool := range allTools {
		if tool.OfFunction == nil {
			t.Errorf("Tool %d is not a function tool", i)
			continue
		}

		if tool.OfFunction.Name != expectedTools[i] {
			t.Errorf("Tool %d: expected name '%s', got '%s'",
				i, expectedTools[i], tool.OfFunction.Name)
		}

		if tool.OfFunction.Description.Value == "" {
			t.Errorf("Tool '%s' has no description", tool.OfFunction.Name)
		}

		if tool.OfFunction.Parameters == nil {
			t.Errorf("Tool '%s' has no parameters", tool.OfFunction.Name)
		}
	}
}
