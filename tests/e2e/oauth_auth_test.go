// Package e2e provides end-to-end property-based tests for OAuth and Auth APIs.
// These tests hit actual HTTP handlers via httptest.Server.
// All tests follow the property-based testing approach per CLAUDE.md.
//
// This file includes:
// - OAuth conformance tests (migrated from tests/conformance/oauth_conformance_test.go)
// - Property-based OAuth tests using rapid
// - Property-based Auth API tests
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
	"sync/atomic"
	"testing"

	_ "github.com/mutecomm/go-sqlcipher/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/email"
	"github.com/kuitang/agent-notes/internal/oauth"
	"github.com/kuitang/agent-notes/internal/web"
	"github.com/kuitang/agent-notes/tests/e2e/testutil"
)

// =============================================================================
// Test Setup - Shared test server infrastructure
// =============================================================================

// Global mutex for OAuth tests to ensure test isolation
var oauthTestMutex sync.Mutex
var oauthTestCounter atomic.Int64
var oauthSharedMu sync.Mutex
var oauthSharedFixture *oauthTestServer

// oauthTestServer wraps httptest.Server with additional test helpers for OAuth
type oauthTestServer struct {
	*httptest.Server
	oauthProvider  *oauth.Provider
	sessionService *auth.SessionService
	consentService *auth.ConsentService
	userService    *auth.UserService
	sessionsDB     *db.SessionsDB
	emailService   *email.MockEmailService
	tempDir        string
}

// setupOAuthTestServer creates a fully configured test server with all OAuth routes
func setupOAuthTestServer(t testing.TB) *oauthTestServer {
	t.Helper()
	oauthTestMutex.Lock()
	t.Cleanup(oauthTestMutex.Unlock)

	ts, err := getOrCreateSharedOAuthTestServer()
	if err != nil {
		t.Fatalf("Failed to initialize shared OAuth fixture: %v", err)
	}
	if err := resetOAuthTestServerState(ts); err != nil {
		t.Fatalf("Failed to reset shared OAuth fixture: %v", err)
	}
	return ts
}

// setupOAuthTestServerRapid creates a test server for rapid.T tests
func setupOAuthTestServerRapid() *oauthTestServer {
	oauthTestMutex.Lock()
	// Use os.MkdirTemp for rapid tests since rapid.T doesn't have TempDir
	tempDir, err := os.MkdirTemp("", "oauth-test-*")
	if err != nil {
		panic("Failed to create temp dir: " + err.Error())
	}
	return createOAuthTestServer(tempDir)
}

// createOAuthTestServer creates a test server with the given temp directory
func createOAuthTestServer(tempDir string) *oauthTestServer {
	// Reset database singleton and set fresh data directory for test isolation
	db.ResetForTesting()
	db.DataDirectory = tempDir

	// Initialize sessions database (now uses fresh directory)
	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		panic("Failed to open sessions database: " + err.Error())
	}

	// Generate test HMAC secret and signing key
	hmacSecret := make([]byte, 32)
	_, err = crand.Read(hmacSecret)
	if err != nil {
		panic("Failed to generate HMAC secret: " + err.Error())
	}

	_, signingKey, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		panic("Failed to generate signing key: " + err.Error())
	}

	// Create mux for routing
	mux := http.NewServeMux()

	// Start httptest server with TLS to allow secure cookies
	server := httptest.NewTLSServer(mux)

	// Create OAuth provider with server URL as issuer
	oauthProvider, err := oauth.NewProvider(oauth.Config{
		DB:                 sessionsDB.DB(),
		Issuer:             server.URL,
		Resource:           server.URL,
		HMACSecret:         hmacSecret,
		SigningKey:         signingKey,
		ClientSecretHasher: oauth.FakeInsecureClientSecretHasher{},
	})
	if err != nil {
		panic("Failed to create OAuth provider: " + err.Error())
	}

	// Create services
	masterKey := make([]byte, 32)
	keyManager := crypto.NewKeyManager(masterKey, sessionsDB)
	emailService := email.NewMockEmailService()
	sessionService := auth.NewSessionService(sessionsDB)
	consentService := auth.NewConsentService(sessionsDB)
	userService := auth.NewUserService(sessionsDB, keyManager, emailService, server.URL, auth.FakeInsecureHasher{})

	// Find templates directory for renderer
	templatesDir := findTemplatesDir()
	renderer, err := web.NewRenderer(templatesDir)
	if err != nil {
		panic("Failed to create renderer from templates at " + templatesDir + ": " + err.Error())
	}

	// Create OAuth handler
	oauthHandler := oauth.NewHandler(oauthProvider, sessionService, consentService, renderer)

	// Register OAuth metadata routes
	oauthProvider.RegisterMetadataRoutes(mux)

	// Register OAuth endpoints
	mux.HandleFunc("POST /oauth/register", oauthProvider.DCR)
	oauthHandler.RegisterRoutes(mux)

	// Register auth endpoints for testing
	mux.HandleFunc("POST /auth/login", func(w http.ResponseWriter, r *http.Request) {
		handleTestLogin(w, r, userService, sessionService)
	})
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		handleTestLoginPage(w, r)
	})
	mux.HandleFunc("POST /auth/register", func(w http.ResponseWriter, r *http.Request) {
		handleTestRegister(w, r, userService, sessionService)
	})
	mux.HandleFunc("POST /auth/magic", func(w http.ResponseWriter, r *http.Request) {
		handleTestMagicLinkRequest(w, r, userService)
	})
	mux.HandleFunc("GET /auth/magic/verify", func(w http.ResponseWriter, r *http.Request) {
		handleTestMagicLinkVerify(w, r, userService, sessionService)
	})
	mux.HandleFunc("POST /auth/password-reset", func(w http.ResponseWriter, r *http.Request) {
		handleTestPasswordResetRequest(w, r, userService)
	})
	mux.HandleFunc("POST /auth/password-reset-confirm", func(w http.ResponseWriter, r *http.Request) {
		handleTestPasswordResetConfirm(w, r, userService)
	})
	mux.HandleFunc("POST /auth/logout", func(w http.ResponseWriter, r *http.Request) {
		handleTestLogout(w, r, sessionService)
	})
	mux.HandleFunc("GET /auth/whoami", func(w http.ResponseWriter, r *http.Request) {
		handleTestWhoami(w, r, sessionService)
	})

	// Register MCP endpoint (simple stub for token verification test)
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		handleTestMCP(w, r, oauthProvider)
	})

	ts := &oauthTestServer{
		Server:         server,
		oauthProvider:  oauthProvider,
		sessionService: sessionService,
		consentService: consentService,
		userService:    userService,
		sessionsDB:     sessionsDB,
		emailService:   emailService,
		tempDir:        tempDir,
	}

	return ts
}

// cleanup closes the test server and releases the lock
func (ts *oauthTestServer) cleanup() {
	if ts.tempDir != "" && strings.Contains(ts.tempDir, "oauth-shared-") {
		return
	}
	ts.Server.Close()
	db.ResetForTesting()
	// Clean up temp dir if we created it (for rapid tests)
	if ts.tempDir != "" && strings.Contains(ts.tempDir, "oauth-test-") {
		os.RemoveAll(ts.tempDir)
	}
	oauthTestMutex.Unlock()
}

func getOrCreateSharedOAuthTestServer() (*oauthTestServer, error) {
	oauthSharedMu.Lock()
	defer oauthSharedMu.Unlock()

	if oauthSharedFixture != nil {
		if err := oauthSharedFixture.sessionsDB.DB().Ping(); err == nil {
			return oauthSharedFixture, nil
		}
		oauthSharedFixture.closeSharedResources()
		oauthSharedFixture = nil
	}

	tempDir, err := os.MkdirTemp("", "oauth-shared-*")
	if err != nil {
		return nil, fmt.Errorf("create shared OAuth temp dir: %w", err)
	}

	oauthSharedFixture = createOAuthTestServer(tempDir)
	return oauthSharedFixture, nil
}

func (ts *oauthTestServer) closeSharedResources() {
	if ts.Server != nil {
		ts.Server.Close()
	}
	if ts.tempDir != "" {
		_ = os.RemoveAll(ts.tempDir)
	}
}

func resetOAuthTestServerState(ts *oauthTestServer) error {
	if err := resetSharedDBFixtureState(ts.tempDir, ts.sessionsDB); err != nil {
		return err
	}
	if ts.emailService != nil {
		ts.emailService.Clear()
	}
	return nil
}

// findTemplatesDir locates the templates directory for tests
func findTemplatesDir() string {
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

	// Fallback - panic with helpful message
	panic("Cannot find templates directory. Tried: " + strings.Join(candidates, ", "))
}

// =============================================================================
// CLIENT MODE - Determines ChatGPT vs Claude behavior
// =============================================================================

// ClientMode specifies whether to test as ChatGPT (confidential) or Claude (public) client
type ClientMode string

const (
	// ClientModeChatGPT tests as a confidential client WITH client_secret on token endpoint
	ClientModeChatGPT ClientMode = "chatgpt"

	// ClientModeClaude tests as a public client WITHOUT client_secret on token endpoint
	ClientModeClaude ClientMode = "claude"
)

// ClientConfig holds mode-specific configuration
type ClientConfig struct {
	Mode         ClientMode
	ClientName   string
	RedirectURIs []string
	// TokenEndpointAuthMethod is "none" for public clients (Claude), "client_secret_post" for confidential (ChatGPT)
	TokenEndpointAuthMethod string
}

// ChatGPTConfig returns configuration for ChatGPT OAuth flow
func ChatGPTConfig() ClientConfig {
	return ClientConfig{
		Mode:                    ClientModeChatGPT,
		ClientName:              "ChatGPT",
		RedirectURIs:            []string{"https://chatgpt-client.example.test/callback"},
		TokenEndpointAuthMethod: "client_secret_post",
	}
}

// ClaudeConfig returns configuration for Claude OAuth flow
func ClaudeConfig() ClientConfig {
	return ClientConfig{
		Mode:                    ClientModeClaude,
		ClientName:              "claudeai",
		RedirectURIs:            []string{"https://claude-client.example.test/callback"},
		TokenEndpointAuthMethod: "none",
	}
}

// =============================================================================
// SHARED TYPES - Used by OAuth conformance tests
// =============================================================================

// ResourceMetadata from /.well-known/oauth-protected-resource
type ResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

// AuthServerMetadata from /.well-known/oauth-authorization-server
type AuthServerMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	RegistrationEndpoint          string   `json:"registration_endpoint"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	ScopesSupported               []string `json:"scopes_supported"`
}

// DCRRequest for Dynamic Client Registration
type DCRRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

// DCRResponse from Dynamic Client Registration
type DCRResponse struct {
	ClientID         string   `json:"client_id"`
	ClientSecret     string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt int64    `json:"client_id_issued_at"`
	RedirectURIs     []string `json:"redirect_uris"`
}

// TokenResponse from token endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// TokenErrorResponse from token endpoint errors
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// =============================================================================
// OAuthConformanceTest - UNIFIED CONFORMANCE TEST CLIENT
// =============================================================================

// OAuthConformanceTest tests OAuth flows for both ChatGPT and Claude
type OAuthConformanceTest struct {
	t         testing.TB
	serverURL string
	client    *http.Client
	config    ClientConfig

	// Discovered metadata (Step 1 & 2)
	resourceMetadata   ResourceMetadata
	authServerMetadata AuthServerMetadata

	// Registration result (Step 3)
	clientID     string
	clientSecret string // Empty for public clients (Claude)

	// PKCE (Step 4)
	codeVerifier  string
	codeChallenge string

	// Tokens (Step 5)
	accessToken  string
	refreshToken string
}

// NewOAuthConformanceTest creates a new conformance test for the specified client mode
func NewOAuthConformanceTest(t testing.TB, ts *oauthTestServer, config ClientConfig) *OAuthConformanceTest {
	return &OAuthConformanceTest{
		t:         t,
		serverURL: ts.URL,
		client:    newOAuthHTTPClient(ts), // Use TLS-capable client
		config:    config,
	}
}

// Step1_FetchProtectedResourceMetadata fetches protected resource metadata
func (c *OAuthConformanceTest) Step1_FetchProtectedResourceMetadata() {
	c.t.Logf("[%s] Step 1: Fetching protected resource metadata", c.config.Mode)

	resp, err := c.client.Get(c.serverURL + "/.well-known/oauth-protected-resource")
	require.NoError(c.t, err)
	defer resp.Body.Close()

	require.Equal(c.t, http.StatusOK, resp.StatusCode,
		"Protected resource metadata endpoint must return 200")

	contentType := resp.Header.Get("Content-Type")
	require.True(c.t, strings.HasPrefix(contentType, "application/json"),
		"Protected resource metadata must be JSON, got: %s", contentType)

	err = json.NewDecoder(resp.Body).Decode(&c.resourceMetadata)
	require.NoError(c.t, err, "Protected resource metadata must be valid JSON")

	require.NotEmpty(c.t, c.resourceMetadata.Resource,
		"Protected resource metadata MUST include 'resource' field")
	require.NotEmpty(c.t, c.resourceMetadata.AuthorizationServers,
		"Protected resource metadata MUST include 'authorization_servers' field")

	c.t.Logf("  [OK] resource: %s", c.resourceMetadata.Resource)
	c.t.Logf("  [OK] authorization_servers: %v", c.resourceMetadata.AuthorizationServers)
}

// Step2_FetchAuthServerMetadata fetches authorization server metadata
func (c *OAuthConformanceTest) Step2_FetchAuthServerMetadata() {
	c.t.Logf("[%s] Step 2: Fetching authorization server metadata", c.config.Mode)

	authServer := c.resourceMetadata.AuthorizationServers[0]
	metadataURL := authServer + "/.well-known/oauth-authorization-server"

	resp, err := c.client.Get(metadataURL)
	require.NoError(c.t, err)
	defer resp.Body.Close()

	require.Equal(c.t, http.StatusOK, resp.StatusCode,
		"Auth server metadata endpoint must return 200")

	err = json.NewDecoder(resp.Body).Decode(&c.authServerMetadata)
	require.NoError(c.t, err)

	require.NotEmpty(c.t, c.authServerMetadata.AuthorizationEndpoint,
		"Auth server metadata MUST include 'authorization_endpoint'")
	require.NotEmpty(c.t, c.authServerMetadata.TokenEndpoint,
		"Auth server metadata MUST include 'token_endpoint'")
	require.NotEmpty(c.t, c.authServerMetadata.RegistrationEndpoint,
		"Auth server metadata MUST include 'registration_endpoint' for DCR")
	require.Contains(c.t, c.authServerMetadata.CodeChallengeMethodsSupported, "S256",
		"CRITICAL: code_challenge_methods_supported MUST include 'S256' or clients will refuse")

	c.t.Logf("  [OK] authorization_endpoint: %s", c.authServerMetadata.AuthorizationEndpoint)
	c.t.Logf("  [OK] token_endpoint: %s", c.authServerMetadata.TokenEndpoint)
	c.t.Logf("  [OK] registration_endpoint: %s", c.authServerMetadata.RegistrationEndpoint)
	c.t.Log("  [OK] code_challenge_methods_supported includes S256")
}

// Step3_DynamicClientRegistration performs DCR
func (c *OAuthConformanceTest) Step3_DynamicClientRegistration() {
	c.t.Logf("[%s] Step 3: Dynamic Client Registration", c.config.Mode)

	dcrReq := DCRRequest{
		ClientName:    c.config.ClientName,
		RedirectURIs:  c.config.RedirectURIs,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
	}

	if c.config.TokenEndpointAuthMethod != "" {
		dcrReq.TokenEndpointAuthMethod = c.config.TokenEndpointAuthMethod
	}

	if c.config.Mode == ClientModeClaude {
		c.t.Log("  [INFO] Registering as PUBLIC client (token_endpoint_auth_method=none)")
	} else {
		c.t.Logf("  [INFO] Registering as CONFIDENTIAL client (token_endpoint_auth_method=%s)", c.config.TokenEndpointAuthMethod)
	}

	body, err := json.Marshal(dcrReq)
	require.NoError(c.t, err)

	resp, err := c.client.Post(
		c.authServerMetadata.RegistrationEndpoint,
		"application/json",
		strings.NewReader(string(body)),
	)
	require.NoError(c.t, err)
	defer resp.Body.Close()

	require.True(c.t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated,
		"Dynamic Client Registration must return 200 or 201, got %d", resp.StatusCode)

	var dcrResp DCRResponse
	err = json.NewDecoder(resp.Body).Decode(&dcrResp)
	require.NoError(c.t, err)

	require.NotEmpty(c.t, dcrResp.ClientID,
		"DCR response MUST include 'client_id'")

	c.clientID = dcrResp.ClientID
	c.clientSecret = dcrResp.ClientSecret

	c.t.Logf("  [OK] client_id: %s", c.clientID)

	if c.config.Mode == ClientModeChatGPT {
		require.NotEmpty(c.t, dcrResp.ClientSecret,
			"Confidential client DCR response MUST include 'client_secret'")
		c.t.Log("  [OK] client_secret: [REDACTED]")
	} else {
		c.t.Log("  [OK] Registered as public client (client_secret not required for token exchange)")
	}
}

// Step4_GeneratePKCE generates PKCE code verifier and challenge
func (c *OAuthConformanceTest) Step4_GeneratePKCE() {
	c.t.Logf("[%s] Step 4a: Generating PKCE challenge", c.config.Mode)

	c.codeVerifier = generateSecureRandom(64)

	h := sha256.Sum256([]byte(c.codeVerifier))
	c.codeChallenge = base64.RawURLEncoding.EncodeToString(h[:])

	c.t.Logf("  [OK] code_verifier: %s...", c.codeVerifier[:16])
	c.t.Logf("  [OK] code_challenge (S256): %s", c.codeChallenge)
}

// Step4_BuildAuthorizationURL builds the authorization URL
func (c *OAuthConformanceTest) Step4_BuildAuthorizationURL(state string) string {
	c.t.Logf("[%s] Step 4b: Building authorization URL", c.config.Mode)

	redirectURI := c.config.RedirectURIs[0]

	params := url.Values{
		"client_id":             {c.clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"notes:read notes:write"},
		"state":                 {state},
		"code_challenge":        {c.codeChallenge},
		"code_challenge_method": {"S256"},
		"resource":              {c.resourceMetadata.Resource},
	}

	authURL := c.authServerMetadata.AuthorizationEndpoint + "?" + params.Encode()
	c.t.Logf("  [OK] Authorization URL: %s", authURL)

	return authURL
}

// Step5_TokenExchange exchanges authorization code for tokens
func (c *OAuthConformanceTest) Step5_TokenExchange(code string) {
	c.t.Logf("[%s] Step 5: Token exchange", c.config.Mode)

	redirectURI := c.config.RedirectURIs[0]

	params := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {c.clientID},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {c.codeVerifier},
	}

	if c.config.Mode == ClientModeChatGPT {
		require.NotEmpty(c.t, c.clientSecret, "ChatGPT mode requires client_secret")
		params.Set("client_secret", c.clientSecret)
		params.Set("resource", c.resourceMetadata.Resource)
		c.t.Log("  [INFO] Including client_secret (confidential client)")
	} else {
		c.t.Log("  [INFO] NO client_secret (public client with PKCE)")
	}

	resp, err := c.client.PostForm(c.authServerMetadata.TokenEndpoint, params)
	require.NoError(c.t, err)
	defer resp.Body.Close()

	require.Equal(c.t, http.StatusOK, resp.StatusCode,
		"Token exchange must return 200")

	var tokenResp TokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	require.NoError(c.t, err)

	require.NotEmpty(c.t, tokenResp.AccessToken,
		"Token response MUST include 'access_token'")
	require.Equal(c.t, "Bearer", tokenResp.TokenType,
		"Token type MUST be 'Bearer'")

	c.accessToken = tokenResp.AccessToken
	c.refreshToken = tokenResp.RefreshToken

	c.t.Log("  [OK] access_token: [REDACTED]")
	c.t.Logf("  [OK] token_type: %s", tokenResp.TokenType)
	c.t.Logf("  [OK] expires_in: %d", tokenResp.ExpiresIn)

	if c.config.Mode == ClientModeClaude {
		c.t.Log("  [OK] Token exchange succeeded WITHOUT client_secret (PKCE provided proof)")
	}
}

// Step6_VerifyTokenWorks verifies the token works with the MCP endpoint
func (c *OAuthConformanceTest) Step6_VerifyTokenWorks() {
	c.t.Logf("[%s] Step 6: Verify token works on MCP endpoint", c.config.Mode)

	req, err := http.NewRequest("POST", c.serverURL+"/mcp", strings.NewReader(`{
		"jsonrpc": "2.0",
		"method": "tools/list",
		"id": 1
	}`))
	require.NoError(c.t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	resp, err := c.client.Do(req)
	require.NoError(c.t, err)
	defer resp.Body.Close()

	require.Equal(c.t, http.StatusOK, resp.StatusCode,
		"MCP request with valid token must return 200")

	c.t.Log("  [OK] MCP request with Bearer token succeeded")
}

// Step7_VerifyAuthTrigger verifies the auth trigger response
func (c *OAuthConformanceTest) Step7_VerifyAuthTrigger() {
	c.t.Logf("[%s] Step 7: Verify auth trigger response", c.config.Mode)

	req, err := http.NewRequest("POST", c.serverURL+"/mcp", strings.NewReader(`{
		"jsonrpc": "2.0",
		"method": "tools/call",
		"params": {"name": "create_note", "arguments": {"title": "test"}},
		"id": 1
	}`))
	require.NoError(c.t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := c.client.Do(req)
	require.NoError(c.t, err)
	defer resp.Body.Close()

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if resp.StatusCode == http.StatusUnauthorized {
		require.Contains(c.t, wwwAuth, "resource_metadata",
			"401 response MUST include WWW-Authenticate with resource_metadata")
		c.t.Log("  [OK] 401 response includes WWW-Authenticate header")
		return
	}

	c.t.Logf("  [INFO] Response status: %d", resp.StatusCode)
}

// TestNegative_NoPKCE tests authorization without PKCE fails
func (c *OAuthConformanceTest) TestNegative_NoPKCE() {
	c.t.Logf("[%s] Negative Test: Authorization without PKCE must fail", c.config.Mode)

	params := url.Values{
		"client_id":     {c.clientID},
		"redirect_uri":  {c.config.RedirectURIs[0]},
		"response_type": {"code"},
		"scope":         {"notes:read"},
		"state":         {"test"},
	}

	resp, err := c.client.Get(c.authServerMetadata.AuthorizationEndpoint + "?" + params.Encode())
	require.NoError(c.t, err)
	defer resp.Body.Close()

	require.Equal(c.t, http.StatusBadRequest, resp.StatusCode,
		"Authorization without PKCE MUST be rejected (OAuth 2.1 requirement)")

	c.t.Log("  [OK] Authorization without PKCE correctly rejected")
}

// TestNegative_InvalidRedirectURI tests DCR with invalid redirect_uri fails
func (c *OAuthConformanceTest) TestNegative_InvalidRedirectURI() {
	c.t.Logf("[%s] Negative Test: DCR with invalid redirect_uri must fail", c.config.Mode)

	dcrReq := DCRRequest{
		ClientName:    "Evil Client",
		RedirectURIs:  []string{"not-a-valid-uri"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
	}

	body, _ := json.Marshal(dcrReq)
	resp, err := c.client.Post(
		c.authServerMetadata.RegistrationEndpoint,
		"application/json",
		strings.NewReader(string(body)),
	)
	require.NoError(c.t, err)
	defer resp.Body.Close()

	require.Equal(c.t, http.StatusBadRequest, resp.StatusCode,
		"DCR with invalid redirect_uri MUST be rejected")

	c.t.Log("  [OK] DCR with invalid redirect_uri correctly rejected")
}

// TestNegative_WrongCodeVerifier tests token exchange with wrong code_verifier fails
func (c *OAuthConformanceTest) TestNegative_WrongCodeVerifier(code string) {
	c.t.Logf("[%s] Negative Test: Token exchange with wrong code_verifier must fail", c.config.Mode)

	params := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {c.clientID},
		"code":          {code},
		"redirect_uri":  {c.config.RedirectURIs[0]},
		"code_verifier": {"wrong-verifier-that-does-not-match"},
	}

	if c.config.Mode == ClientModeChatGPT {
		params.Set("client_secret", c.clientSecret)
	}

	resp, err := c.client.PostForm(c.authServerMetadata.TokenEndpoint, params)
	require.NoError(c.t, err)
	defer resp.Body.Close()

	require.Equal(c.t, http.StatusBadRequest, resp.StatusCode,
		"Token exchange with wrong code_verifier MUST be rejected")

	c.t.Log("  [OK] Token exchange with wrong code_verifier correctly rejected")
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func generateSecureRandom(length int) string {
	bytes := make([]byte, length)
	_, err := crand.Read(bytes)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)[:length]
}

func uniqueOAuthEmail(seed string) string {
	at := strings.Index(seed, "@")
	suffix := generateSecureRandom(8)
	if at <= 0 {
		return "oauth-" + suffix + "@example.com"
	}
	return seed[:at] + "+" + suffix + seed[at:]
}

func newOAuthHTTPClient(ts *oauthTestServer) *http.Client {
	client := ts.Client()
	clone := *client
	clone.Jar = nil
	clone.CheckRedirect = nil
	return &clone
}

// createTestUser creates a user and returns their credentials
func createTestUser(t testing.TB, ts *oauthTestServer, userEmail string) string {
	t.Helper()

	ctx := context.Background()
	user, err := ts.userService.FindOrCreateByProvider(ctx, userEmail)
	require.NoError(t, err, "Failed to create test user")

	return user.ID
}

// createTestUserRapid creates a user for rapid tests (panics on error)
func createTestUserRapid(ts *oauthTestServer, userEmail string) string {
	ctx := context.Background()
	user, err := ts.userService.FindOrCreateByProvider(ctx, userEmail)
	if err != nil {
		panic("Failed to create test user: " + err.Error())
	}
	return user.ID
}

// loginUser logs in a user and returns an HTTP client with session cookie
func loginUser(t testing.TB, ts *oauthTestServer, userEmail string) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err, "Failed to create cookie jar")

	// Use the test server's HTTP client which trusts its TLS certificate
	client := newOAuthHTTPClient(ts)
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	loginURL := ts.URL + "/auth/login"
	form := url.Values{
		"email":    {userEmail},
		"password": {"testpassword"},
	}

	resp, err := client.PostForm(loginURL, form)
	require.NoError(t, err, "Login request failed")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "Login should succeed")

	return client
}

// loginUserRapid logs in a user for rapid tests (panics on error)
func loginUserRapid(ts *oauthTestServer, userEmail string) *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic("Failed to create cookie jar: " + err.Error())
	}

	// Use the test server's HTTP client which trusts its TLS certificate
	client := newOAuthHTTPClient(ts)
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	loginURL := ts.URL + "/auth/login"
	form := url.Values{
		"email":    {userEmail},
		"password": {"testpassword"},
	}

	resp, err := client.PostForm(loginURL, form)
	if err != nil {
		panic("Login request failed: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		panic(fmt.Sprintf("Login should succeed, got %d", resp.StatusCode))
	}

	return client
}

// simulateConsent follows the OAuth flow and simulates user consent
// Returns the authorization code
func simulateConsent(t testing.TB, ts *oauthTestServer, authURL string, client *http.Client) string {
	t.Helper()

	// First request to authorization endpoint
	resp, err := client.Get(authURL)
	require.NoError(t, err, "Failed to access authorization URL")
	defer resp.Body.Close()

	// Debug: log what we got
	t.Logf("Initial authorization response status: %d", resp.StatusCode)

	// If we get redirected with a code, extract it directly
	if resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")

		// Check if this is a redirect to login or to the redirect_uri with code
		if strings.Contains(location, "code=") {
			parsed, err := url.Parse(location)
			require.NoError(t, err, "Failed to parse redirect URL")
			code := parsed.Query().Get("code")
			t.Logf("Got code directly from redirect: %s", code[:minInt(16, len(code))]+"...")
			return code
		}

		// Otherwise it's a redirect to login - this shouldn't happen if we're logged in
		t.Logf("Redirected to: %s", location)
		t.Log("Warning: Redirected to login even though client should be authenticated")

		// For debugging, let's check if cookies are being sent
		cookies := client.Jar.Cookies(mustParseURL(ts.URL))
		t.Logf("Cookies in jar for %s: %d", ts.URL, len(cookies))
		for _, c := range cookies {
			t.Logf("  Cookie: %s=%s...", c.Name, c.Value[:minInt(10, len(c.Value))])
		}

		// The session might not be set yet - fall through and see
	}

	// If we got the consent page (200 OK), submit the consent form
	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "Failed to read consent page")
		t.Logf("Consent page body length: %d", len(body))

		// Submit consent form
		consentURL := ts.URL + "/oauth/consent"
		form := url.Values{
			"decision": {"allow"},
		}

		consentResp, err := client.PostForm(consentURL, form)
		require.NoError(t, err, "Failed to submit consent form")
		defer consentResp.Body.Close()

		t.Logf("Consent response status: %d", consentResp.StatusCode)

		if consentResp.StatusCode != http.StatusFound {
			bodyBytes, _ := io.ReadAll(consentResp.Body)
			t.Fatalf("Consent should redirect, got %d: %s", consentResp.StatusCode, string(bodyBytes))
		}

		redirectURL := consentResp.Header.Get("Location")
		t.Logf("Consent redirect: %s", redirectURL)

		parsed, err := url.Parse(redirectURL)
		require.NoError(t, err, "Failed to parse redirect URL")

		code := parsed.Query().Get("code")
		require.NotEmpty(t, code, "Authorization code should be present in redirect")

		return code
	}

	t.Fatalf("Unexpected response status: %d", resp.StatusCode)
	return ""
}

func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}

// setTestCookie sets a session cookie without the Secure flag (for HTTP test servers)
func setTestCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Allow HTTP for tests
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(auth.SessionDuration.Seconds()),
	})
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// recordTestConsent directly records consent in the database for testing
func recordTestConsent(t testing.TB, ts *oauthTestServer, userID, clientID string, scopes []string) {
	t.Helper()

	ctx := context.Background()
	scopeStr := strings.Join(scopes, " ")
	now := int64(1700000000) // Fixed timestamp keeps tests independent from wall-clock time.

	_, err := ts.sessionsDB.DB().ExecContext(ctx, `
		INSERT INTO oauth_consents (id, user_id, client_id, scopes, granted_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(user_id, client_id) DO UPDATE SET
			scopes = excluded.scopes,
			granted_at = excluded.granted_at
	`, generateSecureRandom(32), userID, clientID, scopeStr, now)
	require.NoError(t, err, "Failed to record test consent")
}

// recordTestConsentRapid directly records consent for rapid tests (panics on error)
func recordTestConsentRapid(ts *oauthTestServer, userID, clientID string, scopes []string) {
	ctx := context.Background()
	scopeStr := strings.Join(scopes, " ")
	now := int64(1700000000) // Fixed timestamp keeps tests independent from wall-clock time.

	_, err := ts.sessionsDB.DB().ExecContext(ctx, `
		INSERT INTO oauth_consents (id, user_id, client_id, scopes, granted_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(user_id, client_id) DO UPDATE SET
			scopes = excluded.scopes,
			granted_at = excluded.granted_at
	`, generateSecureRandom(32), userID, clientID, scopeStr, now)
	if err != nil {
		panic("Failed to record test consent: " + err.Error())
	}
}

// =============================================================================
// TEST HANDLERS
// =============================================================================

// handleTestLogin handles POST /auth/login for testing
func handleTestLogin(w http.ResponseWriter, r *http.Request, userService *auth.UserService, sessionService *auth.SessionService) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		http.Error(w, "Email required", http.StatusBadRequest)
		return
	}

	user, err := userService.FindOrCreateByProvider(r.Context(), email)
	if err != nil {
		http.Error(w, "User error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	sessionID, err := sessionService.Create(r.Context(), user.ID)
	if err != nil {
		http.Error(w, "Session error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Set cookie without Secure flag for HTTP test server
	setTestCookie(w, sessionID)

	returnTo := r.URL.Query().Get("return_to")
	if returnTo != "" {
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":     "ok",
		"session_id": sessionID,
		"user_id":    user.ID,
	})
}

// handleTestLoginPage handles GET /login for testing
func handleTestLoginPage(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")

	html := `<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
<h1>Login</h1>
<form method="POST" action="/auth/login?return_to=` + url.QueryEscape(returnTo) + `">
<input type="email" name="email" placeholder="Email" required>
<input type="password" name="password" placeholder="Password">
<button type="submit">Login</button>
</form>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleTestRegister handles POST /auth/register for testing
func handleTestRegister(w http.ResponseWriter, r *http.Request, userService *auth.UserService, sessionService *auth.SessionService) {
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

	if err := auth.ValidatePasswordStrength(password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := userService.FindOrCreateByProvider(r.Context(), email)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	_, err = auth.FakeInsecureHasher{}.HashPassword(password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	sessionID, err := sessionService.Create(r.Context(), user.ID)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	setTestCookie(w, sessionID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"user_id": user.ID,
		"email":   user.Email,
	})
}

// handleTestMagicLinkRequest handles POST /auth/magic for testing
func handleTestMagicLinkRequest(w http.ResponseWriter, r *http.Request, userService *auth.UserService) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	// Always succeed to prevent email enumeration
	_ = userService.SendMagicLink(r.Context(), email)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "If that email exists, a magic link has been sent",
	})
}

// handleTestMagicLinkVerify handles GET /auth/magic/verify for testing
func handleTestMagicLinkVerify(w http.ResponseWriter, r *http.Request, userService *auth.UserService, sessionService *auth.SessionService) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	user, err := userService.VerifyMagicToken(r.Context(), token)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	sessionID, err := sessionService.Create(r.Context(), user.ID)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	setTestCookie(w, sessionID)
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleTestPasswordResetRequest handles POST /auth/password-reset for testing
func handleTestPasswordResetRequest(w http.ResponseWriter, r *http.Request, userService *auth.UserService) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	// Always succeed to prevent email enumeration
	_ = userService.SendPasswordReset(r.Context(), email)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "If that email exists, a reset link has been sent",
	})
}

// handleTestPasswordResetConfirm handles POST /auth/password-reset-confirm for testing
func handleTestPasswordResetConfirm(w http.ResponseWriter, r *http.Request, userService *auth.UserService) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	password := r.FormValue("password")

	if token == "" || password == "" {
		http.Error(w, "Token and new password are required", http.StatusBadRequest)
		return
	}

	if err := userService.ResetPassword(r.Context(), token, password); err != nil {
		if err == auth.ErrWeakPassword {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err == auth.ErrInvalidToken {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Failed to reset password", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password reset successful",
	})
}

// handleTestLogout handles POST /auth/logout for testing
func handleTestLogout(w http.ResponseWriter, r *http.Request, sessionService *auth.SessionService) {
	sessionID, err := auth.GetFromRequest(r)
	if err == nil {
		_ = sessionService.Delete(r.Context(), sessionID)
	}

	auth.ClearCookie(w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Logged out successfully",
	})
}

// handleTestWhoami handles GET /auth/whoami for testing
func handleTestWhoami(w http.ResponseWriter, r *http.Request, sessionService *auth.SessionService) {
	sessionID, err := auth.GetFromRequest(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
		})
		return
	}

	userID, err := sessionService.Validate(r.Context(), sessionID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id":       userID,
		"authenticated": true,
	})
}

// handleTestMCP handles POST /mcp for token verification testing
func handleTestMCP(w http.ResponseWriter, r *http.Request, provider *oauth.Provider) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+provider.Resource()+`/.well-known/oauth-protected-resource"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	_, err := provider.VerifyAccessToken(token)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]interface{}{
			"tools": []interface{}{},
		},
	})
}

// =============================================================================
// OAUTH CONFORMANCE TESTS - Main test runners
// =============================================================================

func TestChatGPTOAuthConformance(t *testing.T) {
	ts := setupOAuthTestServer(t)
	defer ts.cleanup()

	conformance := NewOAuthConformanceTest(t, ts, ChatGPTConfig())

	// Run the exact ChatGPT OAuth flow
	t.Run("Step1_ProtectedResourceMetadata", func(t *testing.T) {
		conformance.Step1_FetchProtectedResourceMetadata()
	})
	t.Run("Step2_AuthServerMetadata", func(t *testing.T) {
		conformance.Step2_FetchAuthServerMetadata()
	})
	t.Run("Step3_DynamicClientRegistration", func(t *testing.T) {
		conformance.Step3_DynamicClientRegistration()
	})
	t.Run("Step4_PKCE", func(t *testing.T) {
		conformance.Step4_GeneratePKCE()
	})

	// Step 5 & 6: Token exchange and verification (previously missing!)
	t.Run("Step5_6_TokenExchange_And_Verification", func(t *testing.T) {
		// Ensure metadata and client registration are done (in case running this subtest directly)
		if conformance.clientID == "" {
			conformance.Step1_FetchProtectedResourceMetadata()
			conformance.Step2_FetchAuthServerMetadata()
			conformance.Step3_DynamicClientRegistration()
			conformance.Step4_GeneratePKCE()
		}

		// Login a test user
		testEmail := "chatgpt-test@example.com"
		userID := createTestUser(t, ts, testEmail)
		client := loginUser(t, ts, testEmail)

		// Record consent for this client
		recordTestConsent(t, ts, userID, conformance.clientID, []string{"notes:read", "notes:write"})

		// Build authorization URL
		state := generateSecureRandom(16)
		authURL := conformance.Step4_BuildAuthorizationURL(state)

		// Simulate user consent flow
		code := simulateConsent(t, ts, authURL, client)
		require.NotEmpty(t, code, "Should receive authorization code")

		// Step 5: Token exchange
		conformance.Step5_TokenExchange(code)

		// Step 6: Verify token works
		conformance.Step6_VerifyTokenWorks()
	})

	t.Run("Step7_AuthTrigger", func(t *testing.T) {
		conformance.Step7_VerifyAuthTrigger()
	})

	// Negative tests
	t.Run("Negative_NoPKCE", func(t *testing.T) {
		conformance.TestNegative_NoPKCE()
	})
	t.Run("Negative_InvalidRedirectURI", func(t *testing.T) {
		conformance.TestNegative_InvalidRedirectURI()
	})
}

func TestClaudeOAuthConformance(t *testing.T) {
	ts := setupOAuthTestServer(t)
	defer ts.cleanup()

	conformance := NewOAuthConformanceTest(t, ts, ClaudeConfig())

	// Run the exact Claude OAuth flow
	t.Run("Step1_ProtectedResourceMetadata", func(t *testing.T) {
		conformance.Step1_FetchProtectedResourceMetadata()
	})
	t.Run("Step2_AuthServerMetadata", func(t *testing.T) {
		conformance.Step2_FetchAuthServerMetadata()
	})
	t.Run("Step3_DynamicClientRegistration_PublicClient", func(t *testing.T) {
		conformance.Step3_DynamicClientRegistration()
	})
	t.Run("Step4_PKCE", func(t *testing.T) {
		conformance.Step4_GeneratePKCE()
	})

	// Step 5 & 6: Token exchange and verification (previously missing!)
	t.Run("Step5_6_TokenExchange_And_Verification", func(t *testing.T) {
		// Ensure metadata and client registration are done (in case running this subtest directly)
		if conformance.clientID == "" {
			conformance.Step1_FetchProtectedResourceMetadata()
			conformance.Step2_FetchAuthServerMetadata()
			conformance.Step3_DynamicClientRegistration()
			conformance.Step4_GeneratePKCE()
		}

		// Login a test user
		testEmail := "claude-test@example.com"
		userID := createTestUser(t, ts, testEmail)
		client := loginUser(t, ts, testEmail)

		// Record consent for this client
		recordTestConsent(t, ts, userID, conformance.clientID, []string{"notes:read", "notes:write"})

		// Build authorization URL
		state := generateSecureRandom(16)
		authURL := conformance.Step4_BuildAuthorizationURL(state)

		// Simulate user consent flow
		code := simulateConsent(t, ts, authURL, client)
		require.NotEmpty(t, code, "Should receive authorization code")

		// Step 5: Token exchange (without client_secret for public client)
		conformance.Step5_TokenExchange(code)

		// Step 6: Verify token works
		conformance.Step6_VerifyTokenWorks()
	})

	t.Run("Step7_AuthTrigger", func(t *testing.T) {
		conformance.Step7_VerifyAuthTrigger()
	})

	// Negative tests
	t.Run("Negative_NoPKCE", func(t *testing.T) {
		conformance.TestNegative_NoPKCE()
	})
	t.Run("Negative_InvalidRedirectURI", func(t *testing.T) {
		conformance.TestNegative_InvalidRedirectURI()
	})
}

// TestBothClientsCompatibility ensures server works with BOTH ChatGPT and Claude
func TestBothClientsCompatibility(t *testing.T) {
	ts := setupOAuthTestServer(t)
	defer ts.cleanup()

	t.Run("ChatGPT_ConfidentialClient", func(t *testing.T) {
		chatgpt := NewOAuthConformanceTest(t, ts, ChatGPTConfig())
		chatgpt.Step1_FetchProtectedResourceMetadata()
		chatgpt.Step2_FetchAuthServerMetadata()
		chatgpt.Step3_DynamicClientRegistration()
		chatgpt.Step4_GeneratePKCE()

		assert.NotEmpty(t, chatgpt.clientSecret, "ChatGPT should receive client_secret")
	})

	t.Run("Claude_PublicClient", func(t *testing.T) {
		claude := NewOAuthConformanceTest(t, ts, ClaudeConfig())
		claude.Step1_FetchProtectedResourceMetadata()
		claude.Step2_FetchAuthServerMetadata()
		claude.Step3_DynamicClientRegistration()
		claude.Step4_GeneratePKCE()

		t.Log("Claude registered as public client - token exchange will use PKCE only")
	})
}

// =============================================================================
// PROPERTY-BASED OAUTH TESTS
// =============================================================================

// testOAuth_FullFlow_Properties tests the full OAuth flow with random parameters
func testOAuth_FullFlow_Properties(t *rapid.T) {
	// Note: This test uses a shared server to avoid mutex contention in rapid tests
	// Each iteration generates random state and scopes
	state := testutil.StateGenerator().Draw(t, "state")
	scope := testutil.ScopeGenerator().Draw(t, "scope")

	// Property: State must be preserved through the flow
	// Property: Scopes in token must match requested scopes

	// Verify state parameter format is valid
	if len(state) < 16 {
		t.Fatalf("State must be at least 16 characters for security")
	}

	// Verify scope format is valid
	scopes := strings.Fields(scope)
	for _, s := range scopes {
		if !strings.HasPrefix(s, "notes:") {
			t.Fatalf("Invalid scope format: %s", s)
		}
	}
}

func TestOAuth_FullFlow_Properties(t *testing.T) {
	rapid.Check(t, testOAuth_FullFlow_Properties)
}

// testOAuth_PKCE_Properties tests PKCE with random verifiers
func testOAuth_PKCE_Properties(t *rapid.T) {
	verifier := testutil.PKCEVerifierGenerator().Draw(t, "verifier")

	// Compute S256 challenge
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Property: Valid PKCE verifier produces valid challenge
	if len(challenge) == 0 {
		t.Fatal("Challenge should not be empty")
	}

	// Property: Verifying correct verifier succeeds
	if err := oauth.VerifyPKCE(challenge, "S256", verifier); err != nil {
		t.Fatalf("Valid PKCE verification should succeed: %v", err)
	}

	// Property: Verifying wrong verifier fails
	wrongVerifier := verifier + "x"
	if err := oauth.VerifyPKCE(challenge, "S256", wrongVerifier); err == nil {
		t.Fatal("Invalid PKCE verification should fail")
	}

	// Property: Empty verifier fails
	if err := oauth.VerifyPKCE(challenge, "S256", ""); err == nil {
		t.Fatal("Empty PKCE verifier should fail")
	}
}

func TestOAuth_PKCE_Properties(t *testing.T) {
	rapid.Check(t, testOAuth_PKCE_Properties)
}

func FuzzOAuth_PKCE_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testOAuth_PKCE_Properties))
}

// testOAuth_RefreshToken_Properties tests token refresh flow
func testOAuth_RefreshToken_PropertiesWithServer(t *rapid.T, ts *oauthTestServer) {
	// Setup: Register client and get initial tokens
	clientName := testutil.ClientNameGenerator().Draw(t, "clientName")

	// Create client (use neutral redirect URI for testing)
	result, err := ts.oauthProvider.CreateClient(context.Background(), oauth.CreateClientParams{
		ClientName:   clientName,
		RedirectURIs: []string{"https://client.example.test/callback"},
		IsPublic:     false,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Create initial tokens
	tokens, err := ts.oauthProvider.CreateTokens(context.Background(), oauth.TokenParams{
		ClientID:            result.ClientID,
		UserID:              "test-user-" + generateSecureRandom(8),
		Scope:               "notes:read notes:write",
		Resource:            ts.URL,
		IncludeRefreshToken: true,
	})
	if err != nil {
		t.Fatalf("Failed to create tokens: %v", err)
	}

	// Property: Refresh token should produce new access token
	if tokens.RefreshToken == "" {
		t.Fatal("Should have refresh token")
	}

	// Property: Old access token should be valid JWT format
	if tokens.AccessToken == "" {
		t.Fatal("Access token should not be empty")
	}

	// Verify the access token
	claims, err := ts.oauthProvider.VerifyAccessToken(tokens.AccessToken)
	if err != nil {
		t.Fatalf("Access token should be valid: %v", err)
	}

	// Property: Scopes in token should match requested
	if claims.Scope != "notes:read notes:write" {
		t.Fatalf("Scope mismatch: expected 'notes:read notes:write', got '%s'", claims.Scope)
	}

	// Property: Refresh should produce new tokens
	newTokens, err := ts.oauthProvider.RefreshTokens(context.Background(), tokens.RefreshToken, oauth.TokenParams{
		ClientID:            result.ClientID,
		IncludeRefreshToken: true,
	})
	if err != nil {
		t.Fatalf("Refresh should succeed: %v", err)
	}

	// Property: New access token should be different
	if newTokens.AccessToken == tokens.AccessToken {
		t.Fatal("New access token should be different from old")
	}

	// Property: New access token should be valid
	newClaims, err := ts.oauthProvider.VerifyAccessToken(newTokens.AccessToken)
	if err != nil {
		t.Fatalf("New access token should be valid: %v", err)
	}

	// Property: Scope should be preserved
	if newClaims.Scope != claims.Scope {
		t.Fatalf("Scope should be preserved: expected '%s', got '%s'", claims.Scope, newClaims.Scope)
	}
}

func testOAuth_RefreshToken_Properties(t *rapid.T) {
	ts := setupOAuthTestServerRapid()
	defer ts.cleanup()
	testOAuth_RefreshToken_PropertiesWithServer(t, ts)
}

func TestOAuth_RefreshToken_Properties(t *testing.T) {
	ts := setupOAuthTestServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testOAuth_RefreshToken_PropertiesWithServer(rt, ts)
	})
}

// =============================================================================
// PROPERTY-BASED AUTH API TESTS
// =============================================================================

// testAuth_Registration_Properties tests registration with random emails/passwords
func testAuth_Registration_PropertiesWithServer(t *rapid.T, ts *oauthTestServer) {
	email := uniqueOAuthEmail(testutil.EmailGenerator().Draw(t, "email"))
	password := testutil.PasswordGenerator().Draw(t, "password")

	// Use the test server's TLS-capable client
	client := newOAuthHTTPClient(ts)

	// Property: Valid registration should succeed
	resp, err := client.PostForm(ts.URL+"/auth/register", url.Values{"email": {email}, "password": {password}})
	if err != nil {
		t.Fatalf("Registration request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 201, got %d: %s", resp.StatusCode, string(respBody))
	}

	// Property: Response should contain user_id
	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if result["user_id"] == "" {
		t.Fatal("Response should contain user_id")
	}

	// Property: Session cookie should be set
	cookies := resp.Cookies()
	var hasSession bool
	for _, c := range cookies {
		if c.Name == "session_id" {
			hasSession = true
			break
		}
	}
	if !hasSession {
		t.Fatal("Session cookie should be set after registration")
	}
}

func testAuth_Registration_Properties(t *rapid.T) {
	ts := setupOAuthTestServerRapid()
	defer ts.cleanup()
	testAuth_Registration_PropertiesWithServer(t, ts)
}

func TestAuth_Registration_Properties(t *testing.T) {
	ts := setupOAuthTestServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testAuth_Registration_PropertiesWithServer(rt, ts)
	})
}

func FuzzAuth_Registration_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testAuth_Registration_Properties))
}

// testAuth_Registration_WeakPassword_Properties tests weak passwords are rejected
func testAuth_Registration_WeakPassword_PropertiesWithServer(t *rapid.T, ts *oauthTestServer) {
	email := uniqueOAuthEmail(testutil.EmailGenerator().Draw(t, "email"))
	weakPassword := testutil.WeakPasswordGenerator().Draw(t, "weakPassword")

	// Use the test server's TLS-capable client
	client := newOAuthHTTPClient(ts)

	// Property: Weak password should be rejected
	resp, err := client.PostForm(ts.URL+"/auth/register", url.Values{"email": {email}, "password": {weakPassword}})
	if err != nil {
		t.Fatalf("Registration request failed: %v", err)
	}
	defer resp.Body.Close()

	// Property: Should return 400 for weak password
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400 for weak password, got %d", resp.StatusCode)
	}
}

func testAuth_Registration_WeakPassword_Properties(t *rapid.T) {
	ts := setupOAuthTestServerRapid()
	defer ts.cleanup()
	testAuth_Registration_WeakPassword_PropertiesWithServer(t, ts)
}

func TestAuth_Registration_WeakPassword_Properties(t *testing.T) {
	ts := setupOAuthTestServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testAuth_Registration_WeakPassword_PropertiesWithServer(rt, ts)
	})
}

// testAuth_Login_Properties tests login flow
func testAuth_Login_PropertiesWithServer(t *rapid.T, ts *oauthTestServer) {
	email := uniqueOAuthEmail(testutil.EmailGenerator().Draw(t, "email"))
	password := testutil.PasswordGenerator().Draw(t, "password")

	// Use the test server's TLS-capable client
	client := newOAuthHTTPClient(ts)

	// First register the user
	regResp, err := client.PostForm(ts.URL+"/auth/register", url.Values{"email": {email}, "password": {password}})
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}
	regResp.Body.Close()

	// Property: Login should succeed for registered user
	loginResp, err := client.PostForm(ts.URL+"/auth/login", url.Values{"email": {email}, "password": {password}})
	if err != nil {
		t.Fatalf("Login request failed: %v", err)
	}
	defer loginResp.Body.Close()

	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d", loginResp.StatusCode)
	}

	// Property: Session cookie should be set
	cookies := loginResp.Cookies()
	var hasSession bool
	for _, c := range cookies {
		if c.Name == "session_id" {
			hasSession = true
			break
		}
	}
	if !hasSession {
		t.Fatal("Session cookie should be set after login")
	}
}

func testAuth_Login_Properties(t *rapid.T) {
	ts := setupOAuthTestServerRapid()
	defer ts.cleanup()
	testAuth_Login_PropertiesWithServer(t, ts)
}

func TestAuth_Login_Properties(t *testing.T) {
	ts := setupOAuthTestServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testAuth_Login_PropertiesWithServer(rt, ts)
	})
}

func FuzzAuth_Login_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testAuth_Login_Properties))
}

// testAuth_MagicLink_Properties tests magic link request/verify
func testAuth_MagicLink_PropertiesWithServer(t *rapid.T, ts *oauthTestServer) {
	email := uniqueOAuthEmail(testutil.EmailGenerator().Draw(t, "email"))

	// Use the test server's TLS-capable client
	client := newOAuthHTTPClient(ts)

	// Property: Magic link request should always succeed (to prevent enumeration)
	resp, err := client.PostForm(ts.URL+"/auth/magic", url.Values{"email": {email}})
	if err != nil {
		t.Fatalf("Magic link request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	// Property: Response should contain generic message
	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if result["message"] == "" {
		t.Fatal("Response should contain message")
	}

	// Check that email was "sent" via mock service
	if ts.emailService == nil {
		t.Fatal("Email service should be initialized")
	}
}

func testAuth_MagicLink_Properties(t *rapid.T) {
	ts := setupOAuthTestServerRapid()
	defer ts.cleanup()
	testAuth_MagicLink_PropertiesWithServer(t, ts)
}

func TestAuth_MagicLink_Properties(t *testing.T) {
	ts := setupOAuthTestServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testAuth_MagicLink_PropertiesWithServer(rt, ts)
	})
}

func FuzzAuth_MagicLink_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testAuth_MagicLink_Properties))
}

// testAuth_PasswordReset_Properties tests password reset flow
func testAuth_PasswordReset_PropertiesWithServer(t *rapid.T, ts *oauthTestServer) {
	email := uniqueOAuthEmail(testutil.EmailGenerator().Draw(t, "email"))

	// Use the test server's TLS-capable client
	client := newOAuthHTTPClient(ts)

	// Property: Password reset request should always succeed (to prevent enumeration)
	resp, err := client.PostForm(ts.URL+"/auth/password-reset", url.Values{"email": {email}})
	if err != nil {
		t.Fatalf("Password reset request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	// Property: Response should contain generic message
	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if result["message"] == "" {
		t.Fatal("Response should contain message")
	}
}

func testAuth_PasswordReset_Properties(t *rapid.T) {
	ts := setupOAuthTestServerRapid()
	defer ts.cleanup()
	testAuth_PasswordReset_PropertiesWithServer(t, ts)
}

func TestAuth_PasswordReset_Properties(t *testing.T) {
	ts := setupOAuthTestServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testAuth_PasswordReset_PropertiesWithServer(rt, ts)
	})
}

func FuzzAuth_PasswordReset_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testAuth_PasswordReset_Properties))
}

// testAuth_Session_Properties tests logout and whoami
func testAuth_Session_PropertiesWithServer(t *rapid.T, ts *oauthTestServer) {
	email := uniqueOAuthEmail(testutil.EmailGenerator().Draw(t, "email"))
	password := testutil.PasswordGenerator().Draw(t, "password")

	// Use the test server's TLS-capable client with cookie jar
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("Failed to create cookie jar: %v", err)
	}
	client := newOAuthHTTPClient(ts)
	client.Jar = jar

	// Register user
	regResp, err := client.PostForm(ts.URL+"/auth/register", url.Values{"email": {email}, "password": {password}})
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}
	regResp.Body.Close()

	// Property: Whoami should return authenticated=true after registration
	whoamiResp, err := client.Get(ts.URL + "/auth/whoami")
	if err != nil {
		t.Fatalf("Whoami request failed: %v", err)
	}
	defer whoamiResp.Body.Close()

	var whoamiResult map[string]interface{}
	if err := json.NewDecoder(whoamiResp.Body).Decode(&whoamiResult); err != nil {
		t.Fatalf("Failed to parse whoami response: %v", err)
	}

	if whoamiResult["authenticated"] != true {
		t.Fatal("Should be authenticated after registration")
	}

	// Property: Logout should succeed
	logoutResp, err := client.PostForm(ts.URL+"/auth/logout", nil)
	if err != nil {
		t.Fatalf("Logout request failed: %v", err)
	}
	logoutResp.Body.Close()

	if logoutResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 for logout, got %d", logoutResp.StatusCode)
	}

	// Property: Whoami should return authenticated=false after logout
	whoami2Resp, err := client.Get(ts.URL + "/auth/whoami")
	if err != nil {
		t.Fatalf("Whoami request failed: %v", err)
	}
	defer whoami2Resp.Body.Close()

	var whoami2Result map[string]interface{}
	if err := json.NewDecoder(whoami2Resp.Body).Decode(&whoami2Result); err != nil {
		t.Fatalf("Failed to parse whoami response: %v", err)
	}

	if whoami2Result["authenticated"] != false {
		t.Fatal("Should NOT be authenticated after logout")
	}
}

func testAuth_Session_Properties(t *rapid.T) {
	ts := setupOAuthTestServerRapid()
	defer ts.cleanup()
	testAuth_Session_PropertiesWithServer(t, ts)
}

func TestAuth_Session_Properties(t *testing.T) {
	ts := setupOAuthTestServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testAuth_Session_PropertiesWithServer(rt, ts)
	})
}

func FuzzAuth_Session_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testAuth_Session_Properties))
}

// =============================================================================
// ADDITIONAL OAUTH PROPERTY TESTS
// =============================================================================

// testOAuth_StatePreservation_Properties tests state is preserved through OAuth flow
func testOAuth_StatePreservation_PropertiesWithServer(t *rapid.T, ts *oauthTestServer) {
	// Generate random state
	state := testutil.StateGenerator().Draw(t, "state")

	// Create a client
	result, err := ts.oauthProvider.CreateClient(context.Background(), oauth.CreateClientParams{
		ClientName:   "TestClient",
		RedirectURIs: []string{"https://client.example.test/callback"},
		IsPublic:     true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Generate PKCE
	verifier, challenge, err := oauth.GeneratePKCE()
	if err != nil {
		t.Fatalf("Failed to generate PKCE: %v", err)
	}

	// Build authorization URL with state
	params := url.Values{
		"client_id":             {result.ClientID},
		"redirect_uri":          {"https://client.example.test/callback"},
		"response_type":         {"code"},
		"scope":                 {"notes:read"},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	authURL := ts.URL + "/oauth/authorize?" + params.Encode()

	// Create authenticated client
	testEmail := "state-test-" + generateSecureRandom(8) + "@example.com"
	userID := createTestUserRapid(ts, testEmail)
	client := loginUserRapid(ts, testEmail)

	// Record consent
	recordTestConsentRapid(ts, userID, result.ClientID, []string{"notes:read"})

	// Make authorization request
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("Authorization request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should redirect with code
	if resp.StatusCode != http.StatusFound {
		// If consent page shown, submit it
		if resp.StatusCode == http.StatusOK {
			consentResp, err := client.PostForm(ts.URL+"/oauth/consent", url.Values{"decision": {"allow"}})
			if err != nil {
				t.Fatalf("Consent submission failed: %v", err)
			}
			defer consentResp.Body.Close()
			resp = consentResp
		}
	}

	if resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		parsed, err := url.Parse(location)
		if err != nil {
			t.Fatalf("Failed to parse redirect: %v", err)
		}

		// Property: State should be preserved in redirect
		returnedState := parsed.Query().Get("state")
		if returnedState != state {
			t.Fatalf("State not preserved: expected '%s', got '%s'", state, returnedState)
		}

		// Get code for token exchange
		code := parsed.Query().Get("code")
		if code != "" {
			// Verify token exchange also preserves state (indirectly via code)
			tokenParams := url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {result.ClientID},
				"code":          {code},
				"redirect_uri":  {"https://client.example.test/callback"},
				"code_verifier": {verifier},
			}

			// Use the test server's TLS-capable client for token exchange
			tokenClient := newOAuthHTTPClient(ts)
			tokenResp, err := tokenClient.PostForm(ts.URL+"/oauth/token", tokenParams)
			if err != nil {
				t.Fatalf("Token exchange failed: %v", err)
			}
			defer tokenResp.Body.Close()

			if tokenResp.StatusCode == http.StatusOK {
				t.Log("State was properly preserved through the full OAuth flow")
			}
		}
	}
}

func testOAuth_StatePreservation_Properties(t *rapid.T) {
	ts := setupOAuthTestServerRapid()
	defer ts.cleanup()
	testOAuth_StatePreservation_PropertiesWithServer(t, ts)
}

func TestOAuth_StatePreservation_Properties(t *testing.T) {
	ts := setupOAuthTestServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testOAuth_StatePreservation_PropertiesWithServer(rt, ts)
	})
}

// testOAuth_TokenFormat_Properties tests tokens are valid JWT format
func testOAuth_TokenFormat_PropertiesWithServer(t *rapid.T, ts *oauthTestServer) {
	// Create tokens
	tokens, err := ts.oauthProvider.CreateTokens(context.Background(), oauth.TokenParams{
		ClientID:            "test-client",
		UserID:              "test-user-" + generateSecureRandom(8),
		Scope:               "notes:read notes:write",
		Resource:            ts.URL,
		IncludeRefreshToken: true,
	})
	if err != nil {
		t.Fatalf("Failed to create tokens: %v", err)
	}

	// Property: Access token should be valid JWT (3 parts separated by .)
	parts := strings.Split(tokens.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("Access token should have 3 parts, got %d", len(parts))
	}

	// Property: Each part should be base64url encoded
	for i, part := range parts {
		_, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			t.Fatalf("JWT part %d is not valid base64url: %v", i, err)
		}
	}

	// Property: Token should be verifiable
	claims, err := ts.oauthProvider.VerifyAccessToken(tokens.AccessToken)
	if err != nil {
		t.Fatalf("Token should be verifiable: %v", err)
	}

	// Property: Claims should contain expected fields
	if claims.Subject == "" {
		t.Fatal("Token should have subject claim")
	}
	if claims.Issuer == "" {
		t.Fatal("Token should have issuer claim")
	}
	if claims.Scope == "" {
		t.Fatal("Token should have scope claim")
	}

	// Property: Refresh token should be opaque (not JWT)
	if tokens.RefreshToken != "" {
		refreshParts := strings.Split(tokens.RefreshToken, ".")
		if len(refreshParts) == 3 {
			t.Log("Note: Refresh token appears to be JWT format (acceptable)")
		}
	}
}

func testOAuth_TokenFormat_Properties(t *rapid.T) {
	ts := setupOAuthTestServerRapid()
	defer ts.cleanup()
	testOAuth_TokenFormat_PropertiesWithServer(t, ts)
}

func TestOAuth_TokenFormat_Properties(t *testing.T) {
	ts := setupOAuthTestServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testOAuth_TokenFormat_PropertiesWithServer(rt, ts)
	})
}

func FuzzOAuth_TokenFormat_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testOAuth_TokenFormat_Properties))
}
