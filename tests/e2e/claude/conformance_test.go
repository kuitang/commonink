// Package claude provides E2E tests using Claude CLI with streaming JSON.
// Uses bidirectional stdin/stdout streaming for multi-turn conversation.
// Uses SAME prompts as OpenAI tests for parity.
//
// KEY DIFFERENCE FROM OPENAI TESTS:
// - OpenAI tests: We call OpenAI API → OpenAI calls our HTTP API with Bearer tokens
// - Claude tests: Claude CLI connects directly to our MCP server, handles OAuth internally
//
// OAUTH TESTING APPROACH:
// 1. OAuth-enabled server tests verify 401 + WWW-Authenticate responses
// 2. Authenticated MCP tests use pre-provisioned OAuth tokens via Authorization header
// 3. Claude CLI tests with --dangerously-skip-permissions bypass OAuth for CRUD testing
package claude

import (
	"bufio"
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
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	emailpkg "github.com/kuitang/agent-notes/internal/email"
	"github.com/kuitang/agent-notes/internal/mcp"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/kuitang/agent-notes/internal/oauth"
	"github.com/kuitang/agent-notes/internal/web"
)

const TestUserID = "test-user-001"

// =============================================================================
// Original Simple Test Environment (MCP without OAuth)
// =============================================================================

// testEnv holds the test environment
type testEnv struct {
	server    *httptest.Server
	notesSvc  *notes.Service
	mcpConfig string
	cleanup   func()
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	if _, err := exec.LookPath("claude"); err != nil {
		t.Fatal("claude CLI not found")
	}

	tempDir := t.TempDir()
	os.Setenv("DB_DATA_DIR", tempDir)

	if err := db.InitSchemas(TestUserID); err != nil {
		t.Fatalf("DB init failed: %v", err)
	}

	userDB, err := db.OpenUserDB(TestUserID)
	if err != nil {
		t.Fatalf("Open DB failed: %v", err)
	}

	notesSvc := notes.NewService(userDB)
	mcpSrv := mcp.NewServer(notesSvc)

	mux := http.NewServeMux()
	mux.Handle("/mcp", mcpSrv)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	})

	server := httptest.NewServer(mux)

	// Create MCP config - use "http" transport for streamable HTTP
	// See: https://code.claude.com/docs/en/mcp
	mcpConfig := filepath.Join(tempDir, ".mcp.json")
	config := map[string]any{
		"mcpServers": map[string]any{
			"agent-notes": map[string]any{
				"type": "http",
				"url":  server.URL + "/mcp",
			},
		},
	}
	configBytes, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(mcpConfig, configBytes, 0644)

	return &testEnv{
		server:    server,
		notesSvc:  notesSvc,
		mcpConfig: mcpConfig,
		cleanup: func() {
			server.Close()
			db.CloseAll()
		},
	}
}

// =============================================================================
// OAuth-Enabled Test Environment (Parity with OpenAI tests)
// =============================================================================

// oauthTestEnv holds the OAuth-enabled test environment
type oauthTestEnv struct {
	server      *httptest.Server
	tempDir     string
	accessToken string
	userID      string
	httpClient  *http.Client
	mcpConfig   string

	// Services
	sessionsDB     *db.SessionsDB
	keyManager     *crypto.KeyManager
	userService    *auth.UserService
	sessionService *auth.SessionService
	consentService *auth.ConsentService
	oauthProvider  *oauth.Provider

	cleanup func()
}

// setupOAuthTestEnv creates an OAuth-enabled test environment
// This mirrors the OpenAI test setup for parity
func setupOAuthTestEnv(t *testing.T) *oauthTestEnv {
	t.Helper()

	if _, err := exec.LookPath("claude"); err != nil {
		t.Fatal("claude CLI not found")
	}

	tempDir := t.TempDir()
	env := createOAuthServer(t, tempDir)

	// Perform OAuth flow to get access token (same as OpenAI tests)
	accessToken, userID := performOAuthFlow(t, env)

	env.accessToken = accessToken
	env.userID = userID
	env.httpClient = env.server.Client()
	env.cleanup = func() {
		env.server.Close()
		db.ResetForTesting()
	}

	return env
}

// createOAuthServer creates the full OAuth-enabled server
func createOAuthServer(t *testing.T, tempDir string) *oauthTestEnv {
	// Reset database singleton
	db.ResetForTesting()
	db.DataDirectory = tempDir

	// Initialize sessions database
	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		t.Fatalf("Failed to open sessions database: %v", err)
	}

	// Generate keys
	masterKey := make([]byte, 32)
	crand.Read(masterKey)

	_, signingKey, _ := ed25519.GenerateKey(crand.Reader)

	hmacSecret := make([]byte, 32)
	crand.Read(hmacSecret)

	// Create mux
	mux := http.NewServeMux()

	// Start server
	server := httptest.NewTLSServer(mux)

	// Initialize services
	keyManager := crypto.NewKeyManager(masterKey, sessionsDB)
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
		t.Fatalf("Failed to create OAuth provider: %v", err)
	}

	// Find templates directory
	templatesDir := findTemplatesDir()
	renderer, _ := web.NewRenderer(templatesDir)

	// Create handlers
	oauthHandler := oauth.NewHandler(oauthProvider, sessionService, consentService, renderer)

	// Register OAuth routes
	oauthProvider.RegisterMetadataRoutes(mux)
	mux.HandleFunc("POST /oauth/register", oauthProvider.DCR)
	oauthHandler.RegisterRoutes(mux)

	// OAuth-protected MCP endpoint
	tokenVerifier := auth.NewTokenVerifier(server.URL, server.URL, oauthProvider.PublicKey())
	resourceMetadataURL := server.URL + "/.well-known/oauth-protected-resource"

	// MCP endpoint with OAuth middleware
	mux.Handle("POST /mcp", auth.OAuthMiddleware(tokenVerifier, resourceMetadataURL, true)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user ID from context (set by OAuth middleware)
			userID, ok := auth.UserIDFromContext(r.Context())
			if !ok || userID == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// Initialize user database if needed
			if err := db.InitSchemas(userID); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			// Open user database
			userDB, err := db.OpenUserDB(userID)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			notesSvc := notes.NewService(userDB)
			mcpSrv := mcp.NewServer(notesSvc)
			mcpSrv.ServeHTTP(w, r)
		})))

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	})

	// Create MCP config for Claude CLI
	mcpConfig := filepath.Join(tempDir, ".mcp.json")
	config := map[string]any{
		"mcpServers": map[string]any{
			"agent-notes": map[string]any{
				"type": "http",
				"url":  server.URL + "/mcp",
			},
		},
	}
	configBytes, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(mcpConfig, configBytes, 0644)

	return &oauthTestEnv{
		server:         server,
		tempDir:        tempDir,
		mcpConfig:      mcpConfig,
		sessionsDB:     sessionsDB,
		keyManager:     keyManager,
		userService:    userService,
		sessionService: sessionService,
		consentService: consentService,
		oauthProvider:  oauthProvider,
	}
}

// performOAuthFlow performs the full OAuth flow (same as OpenAI tests for parity)
func performOAuthFlow(t *testing.T, env *oauthTestEnv) (string, string) {
	t.Helper()

	client := env.server.Client()

	// Step 1: Register OAuth client as PUBLIC client (like Claude)
	dcrReq := map[string]interface{}{
		"client_name":                "ClaudeConformanceTestClient",
		"redirect_uris":              []string{"http://localhost:8080/callback"},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none", // Public client like Claude
	}
	dcrBody, _ := json.Marshal(dcrReq)
	dcrResp, err := client.Post(env.server.URL+"/oauth/register", "application/json", strings.NewReader(string(dcrBody)))
	if err != nil {
		t.Fatalf("DCR request failed: %v", err)
	}
	defer dcrResp.Body.Close()

	if dcrResp.StatusCode != http.StatusOK && dcrResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(dcrResp.Body)
		t.Fatalf("DCR failed with status %d: %s", dcrResp.StatusCode, string(body))
	}

	var dcrResult map[string]interface{}
	json.NewDecoder(dcrResp.Body).Decode(&dcrResult)
	clientID := dcrResult["client_id"].(string)

	// Step 2: Generate PKCE
	verifier := generateSecureRandom(64)
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Step 3: Create user and session
	testEmail := "claude-conformance-" + generateSecureRandom(8) + "@example.com"
	user, err := env.userService.FindOrCreateByEmail(context.Background(), testEmail)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	sessionID, err := env.sessionService.Create(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Step 4: Authorization request
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

	jar, _ := cookiejar.New(nil)
	authClient := env.server.Client()
	authClient.Jar = jar

	serverURL, _ := url.Parse(env.server.URL)
	jar.SetCookies(serverURL, []*http.Cookie{{
		Name:  "session_id",
		Value: sessionID,
		Path:  "/",
	}})

	authClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	authResp, err := authClient.Get(env.server.URL + "/oauth/authorize?" + authParams.Encode())
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
		authResp.Body.Close()

		consentResp, err := authClient.PostForm(env.server.URL+"/oauth/consent", url.Values{
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

	// Step 5: Token exchange (NO client_secret - public client)
	tokenParams := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {authCode},
		"redirect_uri":  {"http://localhost:8080/callback"},
		"code_verifier": {verifier},
	}

	tokenResp, err := client.PostForm(env.server.URL+"/oauth/token", tokenParams)
	if err != nil {
		t.Fatalf("Token exchange failed: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("Token exchange returned %d: %s", tokenResp.StatusCode, string(body))
	}

	var tokenResult map[string]interface{}
	json.NewDecoder(tokenResp.Body).Decode(&tokenResult)
	accessToken := tokenResult["access_token"].(string)

	t.Logf("[OAuth] Successfully obtained access token for Claude test")

	return accessToken, user.ID
}

func generateSecureRandom(length int) string {
	bytes := make([]byte, length)
	crand.Read(bytes)
	return hex.EncodeToString(bytes)[:length]
}

func findTemplatesDir() string {
	candidates := []string{
		"../../../web/templates",
		"../../../../web/templates",
		"web/templates",
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
// OAuth Integration Tests (Parity with OpenAI)
// =============================================================================

// TestClaude_OAuth_Integration tests the OAuth flow for Claude-style public client
// This provides parity with TestOpenAI_OAuth_Integration
func TestClaude_OAuth_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	// Skip if running as part of quick tests (to avoid mutex contention)
	if os.Getenv("CLAUDE_SKIP_OAUTH_TEST") == "1" {
		t.Skip("Skipping OAuth test to avoid mutex contention")
	}

	env := setupOAuthTestEnv(t)
	defer env.cleanup()

	t.Logf("[OAuth Integration] Using access token for authenticated requests")
	t.Logf("[OAuth Integration] User ID: %s", env.userID)

	// Test 1: Verify OAuth token works for MCP requests
	t.Run("OAuthMCPCreate", func(t *testing.T) {
		// Make authenticated MCP request
		mcpReq := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "note_create",
				"arguments": map[string]string{
					"title":   "OAuth Integration Test Note",
					"content": "Testing OAuth authentication for Claude",
				},
			},
			"id": 1,
		}
		body, _ := json.Marshal(mcpReq)

		req, _ := http.NewRequest("POST", env.server.URL+"/mcp", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+env.accessToken)

		resp, err := env.httpClient.Do(req)
		if err != nil {
			t.Fatalf("MCP request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected 200, got %d: %s", resp.StatusCode, string(respBody))
		}

		t.Log("OAuth MCP create succeeded")
	})

	// Test 2: Verify unauthorized MCP request fails
	t.Run("UnauthorizedMCPFails", func(t *testing.T) {
		mcpReq := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "tools/list",
			"id":      1,
		}
		body, _ := json.Marshal(mcpReq)

		req, _ := http.NewRequest("POST", env.server.URL+"/mcp", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
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

		t.Logf("Correctly returned 401 with WWW-Authenticate: %s", wwwAuth)
	})

	// Test 3: Verify OAuth metadata endpoints work
	t.Run("OAuthMetadataEndpoints", func(t *testing.T) {
		// Protected Resource Metadata
		prmResp, err := env.httpClient.Get(env.server.URL + "/.well-known/oauth-protected-resource")
		if err != nil {
			t.Fatalf("Failed to fetch protected resource metadata: %v", err)
		}
		defer prmResp.Body.Close()

		if prmResp.StatusCode != http.StatusOK {
			t.Fatalf("Expected 200, got %d", prmResp.StatusCode)
		}

		var prm map[string]interface{}
		json.NewDecoder(prmResp.Body).Decode(&prm)

		if prm["resource"] == nil {
			t.Fatal("Missing 'resource' in protected resource metadata")
		}

		// Authorization Server Metadata
		asmResp, err := env.httpClient.Get(env.server.URL + "/.well-known/oauth-authorization-server")
		if err != nil {
			t.Fatalf("Failed to fetch auth server metadata: %v", err)
		}
		defer asmResp.Body.Close()

		if asmResp.StatusCode != http.StatusOK {
			t.Fatalf("Expected 200, got %d", asmResp.StatusCode)
		}

		var asm map[string]interface{}
		json.NewDecoder(asmResp.Body).Decode(&asm)

		if asm["authorization_endpoint"] == nil {
			t.Fatal("Missing 'authorization_endpoint' in auth server metadata")
		}

		// Verify S256 is supported (required by Claude)
		challengeMethods, ok := asm["code_challenge_methods_supported"].([]interface{})
		if !ok {
			t.Fatal("Missing 'code_challenge_methods_supported'")
		}

		hasS256 := false
		for _, method := range challengeMethods {
			if method == "S256" {
				hasS256 = true
				break
			}
		}
		if !hasS256 {
			t.Fatal("S256 not in code_challenge_methods_supported")
		}

		t.Log("OAuth metadata endpoints verified successfully")
	})

	// Test 4: Verify public client registration works
	t.Run("PublicClientDCR", func(t *testing.T) {
		dcrReq := map[string]interface{}{
			"client_name":                "TestPublicClient",
			"redirect_uris":              []string{"https://claude.ai/api/mcp/auth_callback"},
			"grant_types":                []string{"authorization_code", "refresh_token"},
			"response_types":             []string{"code"},
			"token_endpoint_auth_method": "none", // Claude uses public client
		}
		dcrBody, _ := json.Marshal(dcrReq)

		resp, err := env.httpClient.Post(env.server.URL+"/oauth/register", "application/json", strings.NewReader(string(dcrBody)))
		if err != nil {
			t.Fatalf("DCR failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("DCR failed with status %d: %s", resp.StatusCode, string(body))
		}

		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)

		if result["client_id"] == nil {
			t.Fatal("Missing client_id in DCR response")
		}

		// Public client should NOT receive client_secret
		if result["client_secret"] != nil {
			t.Fatal("Public client should not receive client_secret")
		}

		t.Logf("Public client registered successfully: %s", result["client_id"])
	})
}

// =============================================================================
// Streaming Message Types
// =============================================================================

// StreamMessage represents a message in Claude's streaming JSON format
type StreamMessage struct {
	Type      string `json:"type"`
	Subtype   string `json:"subtype,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Result    string `json:"result,omitempty"`
	IsError   bool   `json:"is_error,omitempty"`
	// For assistant messages
	Message *AssistantMessage `json:"message,omitempty"`
}

// AssistantMessage represents the assistant message within a StreamMessage
type AssistantMessage struct {
	ID      string         `json:"id"`
	Role    string         `json:"role"`
	Content []ContentBlock `json:"content"`
}

// ContentBlock represents a content block in assistant messages
type ContentBlock struct {
	Type      string `json:"type"`
	Text      string `json:"text,omitempty"`
	ToolUseID string `json:"id,omitempty"`    // For tool_use blocks
	Name      string `json:"name,omitempty"`  // Tool name
	Input     any    `json:"input,omitempty"` // Tool input
	ServerID  string `json:"server_id,omitempty"`
}

// ToolCall represents an MCP tool call
type ToolCall struct {
	Name     string
	ToolID   string
	ServerID string
}

// Conversation manages a streaming conversation with Claude CLI
type Conversation struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	scanner *bufio.Scanner
	mu      sync.Mutex
	closed  bool
}

// NewConversation starts a new streaming conversation with Claude
func NewConversation(t *testing.T, mcpConfig string) *Conversation {
	t.Helper()

	cmd := exec.Command("claude",
		"-p",
		"--verbose", // Required for stream-json output
		"--input-format", "stream-json",
		"--output-format", "stream-json",
		"--mcp-config", mcpConfig,
		"--dangerously-skip-permissions", // Allow MCP tool calls without prompts
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("Failed to get stdin pipe: %v", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Failed to get stdout pipe: %v", err)
	}

	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start claude: %v", err)
	}

	return &Conversation{
		cmd:     cmd,
		stdin:   stdin,
		stdout:  stdout,
		scanner: bufio.NewScanner(stdout),
	}
}

// SendMessage sends a user message and collects the response
// Returns the final text response and tool calls made
func (c *Conversation) SendMessage(t *testing.T, message string) (string, []ToolCall) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		t.Fatal("Conversation is closed")
	}

	// Send user message as JSON in the correct format:
	// {"type":"user","message":{"role":"user","content":"..."}}
	userMsg := map[string]any{
		"type": "user",
		"message": map[string]string{
			"role":    "user",
			"content": message,
		},
	}
	msgBytes, _ := json.Marshal(userMsg)
	t.Logf("Sending: %s", string(msgBytes))

	if _, err := c.stdin.Write(append(msgBytes, '\n')); err != nil {
		t.Fatalf("Failed to write to stdin: %v", err)
	}

	// Collect response
	var toolCalls []ToolCall
	var responseText strings.Builder
	var sessionID string

	for c.scanner.Scan() {
		line := c.scanner.Text()
		if line == "" {
			continue
		}

		t.Logf("Received: %s", line)

		var msg StreamMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Logf("Failed to parse JSON: %v", err)
			continue
		}

		// Track session ID to prove conversation continuity
		if msg.SessionID != "" {
			if sessionID == "" {
				sessionID = msg.SessionID
				t.Logf("Session ID (proves multi-turn): %s", sessionID)
			} else if sessionID != msg.SessionID {
				t.Logf("WARNING: Session ID changed from %s to %s", sessionID, msg.SessionID)
			}
		}

		switch msg.Type {
		case "system":
			// Init or other system message - continue
			continue

		case "assistant":
			// Parse content blocks from the assistant message
			if msg.Message != nil {
				for _, block := range msg.Message.Content {
					switch block.Type {
					case "text":
						responseText.WriteString(block.Text)
					case "tool_use":
						toolCalls = append(toolCalls, ToolCall{
							Name:     block.Name,
							ToolID:   block.ToolUseID,
							ServerID: block.ServerID,
						})
						t.Logf("Tool call: %s (ID: %s)", block.Name, block.ToolUseID)
					}
				}
			}

		case "result":
			// End of response - use the result field if present
			if msg.Result != "" && responseText.Len() == 0 {
				responseText.WriteString(msg.Result)
			}
			return responseText.String(), toolCalls

		case "error":
			t.Logf("Error from Claude: %v", msg)
		}
	}

	if err := c.scanner.Err(); err != nil {
		t.Logf("Scanner error: %v", err)
	}

	return responseText.String(), toolCalls
}

// Close terminates the conversation
func (c *Conversation) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	c.stdin.Close()
	c.stdout.Close()
	return c.cmd.Wait()
}

// runOneShotClaude runs a one-shot prompt (fallback if streaming doesn't work)
func (env *testEnv) runOneShotClaude(t *testing.T, prompt string) (string, []ToolCall) {
	t.Helper()

	cmd := exec.Command("claude", "-p", prompt,
		"--verbose", // Required for stream-json output
		"--output-format", "stream-json",
		"--mcp-config", env.mcpConfig,
		"--dangerously-skip-permissions") // Allow MCP tool calls without prompts

	output, err := cmd.Output()
	if err != nil {
		t.Logf("claude error: %v", err)
		t.Fatalf("claude failed: %v", err)
	}

	var toolCalls []ToolCall
	var responseText strings.Builder

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var msg StreamMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}

		switch msg.Type {
		case "assistant":
			// Parse content blocks from the assistant message
			if msg.Message != nil {
				for _, block := range msg.Message.Content {
					switch block.Type {
					case "text":
						responseText.WriteString(block.Text)
					case "tool_use":
						toolCalls = append(toolCalls, ToolCall{
							Name:     block.Name,
							ToolID:   block.ToolUseID,
							ServerID: block.ServerID,
						})
						t.Logf("Tool call: %s (ID: %s)", block.Name, block.ToolUseID)
					}
				}
			}
		case "result":
			// Use the result field if present and we have no text yet
			if msg.Result != "" && responseText.Len() == 0 {
				responseText.WriteString(msg.Result)
			}
		}
	}

	return responseText.String(), toolCalls
}

// =============================================================================
// Multi-turn Streaming Tests (SAME prompts as OpenAI for parity)
// =============================================================================

func TestClaude_MultiTurn_Streaming(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	// Start streaming conversation
	conv := NewConversation(t, env.mcpConfig)
	defer conv.Close()

	var noteID string

	// Turn 1: Create a note (SAME PROMPT AS OPENAI TEST)
	t.Run("Turn1_Create", func(t *testing.T) {
		resp, toolCalls := conv.SendMessage(t,
			"Create a note titled 'Team Meeting Notes' with content 'Discussed Q1 roadmap and assigned action items.'")

		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))

		// Verify in DB
		list, err := env.notesSvc.List(100, 0)
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}
		for _, n := range list.Notes {
			if strings.Contains(strings.ToLower(n.Title), "meeting") {
				noteID = n.ID
				break
			}
		}
		if noteID == "" {
			t.Fatal("Note not created")
		}
		t.Logf("Created note: %s", noteID)
	})

	// Turn 2: List notes (SAME PROMPT AS OPENAI TEST)
	t.Run("Turn2_List", func(t *testing.T) {
		resp, toolCalls := conv.SendMessage(t,
			"List all my notes and tell me how many there are.")

		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))
	})

	// Turn 3: Search notes (SAME PROMPT AS OPENAI TEST)
	t.Run("Turn3_Search", func(t *testing.T) {
		resp, toolCalls := conv.SendMessage(t,
			"Search for notes containing 'meeting'.")

		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))
	})

	// Turn 4: Update note (SAME PROMPT AS OPENAI TEST)
	t.Run("Turn4_Update", func(t *testing.T) {
		if noteID == "" {
			t.Skip("No note ID")
		}
		prompt := fmt.Sprintf("Update the note with ID '%s' to add 'Follow-up: Monday' to the content.", noteID)
		resp, toolCalls := conv.SendMessage(t, prompt)

		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))

		// Verify in DB
		note, err := env.notesSvc.Read(noteID)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		t.Logf("Updated content: %s", note.Content)
	})

	// Turn 5: Delete note (SAME PROMPT AS OPENAI TEST)
	t.Run("Turn5_Delete", func(t *testing.T) {
		if noteID == "" {
			t.Skip("No note ID")
		}
		prompt := fmt.Sprintf("Delete the note with ID '%s'.", noteID)
		resp, toolCalls := conv.SendMessage(t, prompt)

		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))

		// Verify deletion in DB
		_, err := env.notesSvc.Read(noteID)
		if err == nil {
			t.Fatal("Note still exists")
		}
		t.Log("Note deleted successfully")
	})
}

// =============================================================================
// One-shot Tests (fallback)
// =============================================================================

func TestClaude_OneShot_CRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	var noteID string

	// Create
	t.Run("Create", func(t *testing.T) {
		resp, toolCalls := env.runOneShotClaude(t,
			"Create a note titled 'Team Meeting Notes' with content 'Discussed Q1 roadmap.'")
		t.Logf("Response: %s, Tools: %d", resp, len(toolCalls))

		list, _ := env.notesSvc.List(100, 0)
		for _, n := range list.Notes {
			if strings.Contains(strings.ToLower(n.Title), "meeting") {
				noteID = n.ID
				break
			}
		}
		if noteID == "" {
			t.Fatal("Note not created")
		}
	})

	// List
	t.Run("List", func(t *testing.T) {
		resp, toolCalls := env.runOneShotClaude(t, "List all my notes.")
		t.Logf("Response: %s, Tools: %d", resp, len(toolCalls))
	})

	// Search
	t.Run("Search", func(t *testing.T) {
		resp, toolCalls := env.runOneShotClaude(t, "Search for notes about meeting.")
		t.Logf("Response: %s, Tools: %d", resp, len(toolCalls))
	})

	// Update
	t.Run("Update", func(t *testing.T) {
		if noteID == "" {
			t.Skip("No note")
		}
		resp, toolCalls := env.runOneShotClaude(t,
			fmt.Sprintf("Update note %s to add 'Follow-up Monday'.", noteID))
		t.Logf("Response: %s, Tools: %d", resp, len(toolCalls))
	})

	// Delete
	t.Run("Delete", func(t *testing.T) {
		if noteID == "" {
			t.Skip("No note")
		}
		resp, toolCalls := env.runOneShotClaude(t,
			fmt.Sprintf("Delete the note with ID %s.", noteID))
		t.Logf("Response: %s, Tools: %d", resp, len(toolCalls))

		_, err := env.notesSvc.Read(noteID)
		if err == nil {
			t.Fatal("Note still exists")
		}
	})
}
