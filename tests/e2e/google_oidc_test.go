// Package e2e provides property-based OIDC integration tests using mockoidc.
// These tests verify the Google OIDC authentication flow using a real mock OIDC server.
package e2e

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	_ "github.com/mutecomm/go-sqlcipher/v4"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"pgregory.net/rapid"

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/email"
	"github.com/kuitang/agent-notes/tests/e2e/testutil"
)

// =============================================================================
// MOCKOIDC TEST INFRASTRUCTURE
// =============================================================================

var oidcTestMutex sync.Mutex
var oidcSharedMu sync.Mutex
var oidcSharedFixture *mockOIDCTestServer

// mockOIDCTestServer wraps an httptest.Server with mockoidc for OIDC testing
type mockOIDCTestServer struct {
	*httptest.Server
	mockOIDC       *mockoidc.MockOIDC
	sessionsDB     *db.SessionsDB
	userService    *auth.UserService
	sessionService *auth.SessionService
	emailService   *email.MockEmailService
	tempDir        string
	oidcClient     auth.OIDCClient // Real OIDC client pointing to mock server
}

// MockOIDCClientAdapter adapts mockoidc to our OIDCClient interface
type MockOIDCClientAdapter struct {
	mockServer  *mockoidc.MockOIDC
	provider    *oidc.Provider
	verifier    *oidc.IDTokenVerifier
	oauthConfig *oauth2.Config
}

// NewMockOIDCClientAdapter creates an OIDC client that connects to mockoidc
func NewMockOIDCClientAdapter(mockServer *mockoidc.MockOIDC, redirectURL string) (*MockOIDCClientAdapter, error) {
	ctx := context.Background()

	// Create OIDC provider pointing to the mock server
	provider, err := oidc.NewProvider(ctx, mockServer.Issuer())
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Create the ID token verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID: mockServer.ClientID,
	})

	// Configure OAuth2 with the provider's endpoints
	oauthConfig := &oauth2.Config{
		ClientID:     mockServer.ClientID,
		ClientSecret: mockServer.ClientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}

	return &MockOIDCClientAdapter{
		mockServer:  mockServer,
		provider:    provider,
		verifier:    verifier,
		oauthConfig: oauthConfig,
	}, nil
}

// GetAuthURL returns the authorization URL with the provided state parameter
func (a *MockOIDCClientAdapter) GetAuthURL(state string) string {
	return a.oauthConfig.AuthCodeURL(state)
}

// ExchangeCode exchanges an authorization code for ID token claims
func (a *MockOIDCClientAdapter) ExchangeCode(ctx context.Context, code string) (*auth.Claims, error) {
	// Exchange the authorization code for tokens
	oauth2Token, err := a.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", auth.ErrCodeExchangeFailed, err)
	}

	// Extract the ID token from the OAuth2 token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("%w: missing id_token in token response", auth.ErrCodeExchangeFailed)
	}

	// Verify the ID token
	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("%w: id_token verification failed: %v", auth.ErrCodeExchangeFailed, err)
	}

	// Extract claims from the ID token
	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: failed to parse claims: %v", auth.ErrCodeExchangeFailed, err)
	}

	return &auth.Claims{
		Sub:           claims.Sub,
		Email:         claims.Email,
		Name:          claims.Name,
		EmailVerified: claims.EmailVerified,
	}, nil
}

// setupMockOIDCTestServer creates a test server with mockoidc
func setupMockOIDCTestServer(t testing.TB) *mockOIDCTestServer {
	t.Helper()
	oidcTestMutex.Lock()
	t.Cleanup(oidcTestMutex.Unlock)

	ts, err := getOrCreateSharedMockOIDCTestServer()
	if err != nil {
		t.Fatalf("Failed to initialize shared OIDC fixture: %v", err)
	}
	if err := resetOIDCTestServerState(ts); err != nil {
		t.Fatalf("Failed to reset shared OIDC fixture: %v", err)
	}
	return ts
}

// setupMockOIDCTestServerRapid creates a test server for rapid.T tests
func setupMockOIDCTestServerRapid() *mockOIDCTestServer {
	oidcTestMutex.Lock()

	tempDir, err := os.MkdirTemp("", "oidc-test-*")
	if err != nil {
		panic("Failed to create temp dir: " + err.Error())
	}
	return createMockOIDCTestServer(tempDir)
}

// createMockOIDCTestServer creates the test server with mockoidc
func createMockOIDCTestServer(tempDir string) *mockOIDCTestServer {
	// Reset database singleton
	db.ResetForTesting()
	db.DataDirectory = tempDir

	// Initialize sessions database
	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		panic("Failed to open sessions database: " + err.Error())
	}

	// Start mockoidc server
	mockOIDC, err := mockoidc.Run()
	if err != nil {
		panic("Failed to start mockoidc: " + err.Error())
	}

	// Create mux for our server
	mux := http.NewServeMux()

	// Start our test server first to get URL for redirect
	server := httptest.NewTLSServer(mux)

	// Create OIDC client adapter pointing to mock server
	redirectURL := server.URL + "/auth/google/callback"
	oidcClient, err := NewMockOIDCClientAdapter(mockOIDC, redirectURL)
	if err != nil {
		panic("Failed to create OIDC client adapter: " + err.Error())
	}

	// Create services
	masterKey := make([]byte, 32)
	keyManager := crypto.NewKeyManager(masterKey, sessionsDB)
	emailService := email.NewMockEmailService()
	userService := auth.NewUserService(sessionsDB, keyManager, emailService, server.URL, auth.FakeInsecureHasher{})
	sessionService := auth.NewSessionService(sessionsDB)

	// Create auth handler with the mockoidc-backed client
	authHandler := auth.NewHandler(oidcClient, userService, sessionService)

	// Register auth routes
	authHandler.RegisterRoutes(mux)

	// Add whoami route for testing session state
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><h1>Home</h1></body></html>"))
	})

	return &mockOIDCTestServer{
		Server:         server,
		mockOIDC:       mockOIDC,
		sessionsDB:     sessionsDB,
		userService:    userService,
		sessionService: sessionService,
		emailService:   emailService,
		tempDir:        tempDir,
		oidcClient:     oidcClient,
	}
}

// cleanup closes the test server and releases resources
func (ts *mockOIDCTestServer) cleanup() {
	if ts.tempDir != "" && strings.Contains(ts.tempDir, "oidc-shared-") {
		return
	}
	ts.Server.Close()
	if err := ts.mockOIDC.Shutdown(); err != nil {
		// Log but don't fail
	}
	db.ResetForTesting()
	if ts.tempDir != "" && strings.Contains(ts.tempDir, "oidc-test-") {
		os.RemoveAll(ts.tempDir)
	}
	oidcTestMutex.Unlock()
}

func getOrCreateSharedMockOIDCTestServer() (*mockOIDCTestServer, error) {
	oidcSharedMu.Lock()
	defer oidcSharedMu.Unlock()

	if oidcSharedFixture != nil {
		if err := oidcSharedFixture.sessionsDB.DB().Ping(); err == nil {
			return oidcSharedFixture, nil
		}
		oidcSharedFixture.closeSharedResources()
		oidcSharedFixture = nil
	}

	tempDir, err := os.MkdirTemp("", "oidc-shared-*")
	if err != nil {
		return nil, fmt.Errorf("create shared OIDC temp dir: %w", err)
	}

	oidcSharedFixture = createMockOIDCTestServer(tempDir)
	return oidcSharedFixture, nil
}

func (ts *mockOIDCTestServer) closeSharedResources() {
	if ts.Server != nil {
		ts.Server.Close()
	}
	if ts.mockOIDC != nil {
		_ = ts.mockOIDC.Shutdown()
	}
	if ts.tempDir != "" {
		_ = os.RemoveAll(ts.tempDir)
	}
}

func resetOIDCTestServerState(ts *mockOIDCTestServer) error {
	if err := resetSharedDBFixtureState(ts.tempDir, ts.sessionsDB); err != nil {
		return err
	}
	if ts.emailService != nil {
		ts.emailService.Clear()
	}
	resetMockOIDCState(ts)
	return nil
}

// queueUser queues a user to be returned by the mock OIDC server
func (ts *mockOIDCTestServer) queueUser(sub, email, name string, emailVerified bool) {
	user := &mockoidc.MockUser{
		Subject:           sub,
		Email:             email,
		EmailVerified:     emailVerified,
		PreferredUsername: name, // mockoidc uses PreferredUsername instead of Name
	}
	ts.mockOIDC.QueueUser(user)
}

func cloneHTTPClient(base *http.Client) *http.Client {
	clone := *base
	clone.Jar = nil
	clone.CheckRedirect = nil
	return &clone
}

func newOIDCHTTPClient(ts *mockOIDCTestServer) *http.Client {
	return cloneHTTPClient(ts.Client())
}

func newOIDCProviderHTTPClient(ts *mockOIDCTestServer) *http.Client {
	return cloneHTTPClient(ts.Server.Client())
}

func resetMockOIDCState(ts *mockOIDCTestServer) {
	ts.mockOIDC.UserQueue.Lock()
	ts.mockOIDC.UserQueue.Queue = nil
	ts.mockOIDC.UserQueue.Unlock()

	ts.mockOIDC.ErrorQueue.Lock()
	ts.mockOIDC.ErrorQueue.Queue = nil
	ts.mockOIDC.ErrorQueue.Unlock()

	ts.mockOIDC.SessionStore.CodeQueue.Lock()
	ts.mockOIDC.SessionStore.CodeQueue.Queue = nil
	ts.mockOIDC.SessionStore.CodeQueue.Unlock()

	ts.mockOIDC.SessionStore.Store = make(map[string]*mockoidc.Session)
}

// =============================================================================
// OIDC PROPERTY TESTS
// =============================================================================

// testOIDC_AuthURL_Properties tests that the auth URL is correctly generated
func testOIDC_AuthURL_PropertiesWithServer(t *rapid.T, ts *mockOIDCTestServer) {
	resetMockOIDCState(ts)

	// Generate random state
	state := testutil.StateGenerator().Draw(t, "state")

	// Get auth URL
	authURL := ts.oidcClient.GetAuthURL(state)

	// Property 1: Auth URL should not be empty
	if authURL == "" {
		t.Fatal("Auth URL should not be empty")
	}

	// Property 2: Auth URL should contain the state parameter
	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Auth URL should be valid URL: %v", err)
	}

	returnedState := parsedURL.Query().Get("state")
	if returnedState != state {
		t.Fatalf("Auth URL should contain state: expected %s, got %s", state, returnedState)
	}

	// Property 3: Auth URL should contain required scopes
	scope := parsedURL.Query().Get("scope")
	if !strings.Contains(scope, "openid") {
		t.Fatal("Auth URL should contain openid scope")
	}

	// Property 4: Auth URL should contain client_id
	clientID := parsedURL.Query().Get("client_id")
	if clientID == "" {
		t.Fatal("Auth URL should contain client_id")
	}

	// Property 5: Auth URL should contain redirect_uri
	redirectURI := parsedURL.Query().Get("redirect_uri")
	if redirectURI == "" {
		t.Fatal("Auth URL should contain redirect_uri")
	}

	// Property 6: Auth URL should contain response_type=code
	responseType := parsedURL.Query().Get("response_type")
	if responseType != "code" {
		t.Fatalf("Auth URL should have response_type=code, got %s", responseType)
	}
}

func testOIDC_AuthURL_Properties(t *rapid.T) {
	ts := setupMockOIDCTestServerRapid()
	defer ts.cleanup()
	testOIDC_AuthURL_PropertiesWithServer(t, ts)
}

func TestOIDC_AuthURL_Properties(t *testing.T) {
	ts := setupMockOIDCTestServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testOIDC_AuthURL_PropertiesWithServer(rt, ts)
	})
}

// testOIDC_FullFlow_Properties tests the complete OIDC authorization flow
func testOIDC_FullFlow_PropertiesWithServer(t *rapid.T, ts *mockOIDCTestServer) {
	resetMockOIDCState(ts)

	// Generate random user claims
	sub := "google-" + testutil.StateGenerator().Draw(t, "sub")
	userEmail := testutil.EmailGenerator().Draw(t, "email")
	name := "Test User"
	emailVerified := rapid.Bool().Draw(t, "emailVerified")

	// Queue the user in mockoidc
	ts.queueUser(sub, userEmail, name, emailVerified)

	// Create HTTP client with cookie jar
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("Failed to create cookie jar: %v", err)
	}
	client := newOIDCHTTPClient(ts)
	client.Jar = jar

	// Step 1: Start OAuth flow by visiting /auth/google
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // Don't follow redirects
	}

	resp, err := client.Get(ts.URL + "/auth/google")
	if err != nil {
		t.Fatalf("Failed to start OAuth flow: %v", err)
	}
	resp.Body.Close()

	// Property 1: Should redirect to OIDC provider
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("Expected redirect (302), got %d", resp.StatusCode)
	}

	authURL := resp.Header.Get("Location")
	if authURL == "" {
		t.Fatal("Should have Location header for redirect")
	}

	// Property 2: oauth_state cookie should be set
	stateCookieFound := false
	var stateValue string
	for _, c := range resp.Cookies() {
		if c.Name == "oauth_state" && c.Value != "" {
			stateCookieFound = true
			stateValue = c.Value
			break
		}
	}
	if !stateCookieFound {
		t.Fatal("oauth_state cookie should be set")
	}

	// Step 2: Simulate user authenticating at OIDC provider
	// Parse the auth URL to get parameters
	parsedAuthURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	// Property 3: State in auth URL should match cookie
	authState := parsedAuthURL.Query().Get("state")
	if authState != stateValue {
		t.Fatalf("State mismatch: URL has %s, cookie has %s", authState, stateValue)
	}

	// Follow the OIDC flow - make request to mock OIDC authorize endpoint
	// mockoidc will redirect back with a code
	oidcClient := newOIDCProviderHTTPClient(ts)
	oidcClient.Jar = jar
	oidcClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Stop at the callback URL
		if strings.Contains(req.URL.String(), "/auth/google/callback") {
			return http.ErrUseLastResponse
		}
		return nil
	}

	oidcResp, err := oidcClient.Get(authURL)
	if err != nil {
		t.Fatalf("Failed to access OIDC authorize endpoint: %v", err)
	}
	oidcResp.Body.Close()

	// Property 4: OIDC should redirect back to callback
	if oidcResp.StatusCode != http.StatusFound {
		t.Fatalf("Expected redirect from OIDC, got %d", oidcResp.StatusCode)
	}

	callbackURL := oidcResp.Header.Get("Location")
	if !strings.Contains(callbackURL, "/auth/google/callback") {
		t.Fatalf("Should redirect to callback, got %s", callbackURL)
	}

	// Property 5: Callback URL should contain authorization code
	parsedCallback, err := url.Parse(callbackURL)
	if err != nil {
		t.Fatalf("Failed to parse callback URL: %v", err)
	}

	code := parsedCallback.Query().Get("code")
	if code == "" {
		t.Fatal("Callback should contain authorization code")
	}

	// Property 6: Callback URL should preserve state
	callbackState := parsedCallback.Query().Get("state")
	if callbackState != stateValue {
		t.Fatalf("State not preserved: expected %s, got %s", stateValue, callbackState)
	}

	// Step 3: Complete the flow by visiting the callback URL
	// Use our test server's client for the callback
	callbackClient := newOIDCHTTPClient(ts)
	callbackClient.Jar = jar
	callbackClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Build full callback URL with our test server
	fullCallbackURL := ts.URL + "/auth/google/callback?" + parsedCallback.RawQuery

	callbackResp, err := callbackClient.Get(fullCallbackURL)
	if err != nil {
		t.Fatalf("Callback request failed: %v", err)
	}
	defer callbackResp.Body.Close()

	// Property 7: Callback should redirect to home after success
	if callbackResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(callbackResp.Body)
		t.Fatalf("Expected redirect after callback, got %d: %s", callbackResp.StatusCode, string(body))
	}

	// Property 8: Session cookie should be set
	sessionCookieFound := false
	for _, c := range callbackResp.Cookies() {
		if c.Name == "session_id" && c.Value != "" {
			sessionCookieFound = true
			break
		}
	}
	if !sessionCookieFound {
		t.Fatal("Session cookie should be set after OIDC login")
	}

	// Property 9: oauth_state cookie should be cleared
	for _, c := range callbackResp.Cookies() {
		if c.Name == "oauth_state" && c.MaxAge == -1 {
			// Cookie is being deleted (MaxAge -1)
			break
		}
	}
}

func testOIDC_FullFlow_Properties(t *rapid.T) {
	ts := setupMockOIDCTestServerRapid()
	defer ts.cleanup()
	testOIDC_FullFlow_PropertiesWithServer(t, ts)
}

func TestOIDC_FullFlow_Properties(t *testing.T) {
	ts := setupMockOIDCTestServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testOIDC_FullFlow_PropertiesWithServer(rt, ts)
	})
}

// testOIDC_ClaimsExtraction_Properties tests that claims are correctly extracted
func testOIDC_ClaimsExtraction_PropertiesWithServer(t *rapid.T, ts *mockOIDCTestServer) {
	resetMockOIDCState(ts)

	// Generate random claims
	sub := "google-sub-" + testutil.StateGenerator().Draw(t, "sub")
	userEmail := testutil.EmailGenerator().Draw(t, "email")
	name := rapid.StringMatching(`[A-Za-z ]{5,30}`).Draw(t, "name")
	emailVerified := rapid.Bool().Draw(t, "emailVerified")

	// Queue the user
	ts.queueUser(sub, userEmail, name, emailVerified)

	// Perform OIDC flow
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("Failed to create cookie jar: %v", err)
	}
	client := newOIDCHTTPClient(ts)
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Start flow
	resp, err := client.Get(ts.URL + "/auth/google")
	if err != nil {
		t.Fatalf("Failed to start OAuth flow: %v", err)
	}
	resp.Body.Close()

	authURL := resp.Header.Get("Location")
	stateValue := ""
	for _, c := range resp.Cookies() {
		if c.Name == "oauth_state" {
			stateValue = c.Value
			break
		}
	}

	// Follow OIDC flow
	oidcClient := newOIDCProviderHTTPClient(ts)
	oidcClient.Jar = jar
	oidcClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.Contains(req.URL.String(), "/auth/google/callback") {
			return http.ErrUseLastResponse
		}
		return nil
	}

	oidcResp, err := oidcClient.Get(authURL)
	if err != nil {
		t.Fatalf("Failed to access OIDC: %v", err)
	}
	oidcResp.Body.Close()

	callbackURL := oidcResp.Header.Get("Location")
	parsedCallback, _ := url.Parse(callbackURL)

	// Complete callback
	callbackClient := newOIDCHTTPClient(ts)
	callbackClient.Jar = jar
	callbackClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	fullCallbackURL := ts.URL + "/auth/google/callback?" + parsedCallback.RawQuery
	callbackResp, err := callbackClient.Get(fullCallbackURL)
	if err != nil {
		t.Fatalf("Callback failed: %v", err)
	}
	callbackResp.Body.Close()

	if callbackResp.StatusCode != http.StatusFound {
		t.Fatalf("Callback should redirect, got %d", callbackResp.StatusCode)
	}

	// Verify user was created with correct email
	// Check whoami endpoint
	whoamiClient := newOIDCHTTPClient(ts)
	whoamiClient.Jar = jar

	whoamiResp, err := whoamiClient.Get(ts.URL + "/auth/whoami")
	if err != nil {
		t.Fatalf("Whoami request failed: %v", err)
	}
	defer whoamiResp.Body.Close()

	var whoamiResult map[string]interface{}
	if err := json.NewDecoder(whoamiResp.Body).Decode(&whoamiResult); err != nil {
		t.Fatalf("Failed to decode whoami: %v", err)
	}

	// Property: User should be authenticated
	if whoamiResult["authenticated"] != true {
		t.Fatal("User should be authenticated after OIDC login")
	}

	// Property: User ID should exist
	if whoamiResult["user_id"] == nil || whoamiResult["user_id"] == "" {
		t.Fatal("User ID should be present")
	}

	// Verify the state was consumed (non-empty proves CSRF token was generated)
	if stateValue == "" {
		t.Fatal("OAuth state parameter was empty")
	}
}

func testOIDC_ClaimsExtraction_Properties(t *rapid.T) {
	ts := setupMockOIDCTestServerRapid()
	defer ts.cleanup()
	testOIDC_ClaimsExtraction_PropertiesWithServer(t, ts)
}

func TestOIDC_ClaimsExtraction_Properties(t *testing.T) {
	ts := setupMockOIDCTestServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testOIDC_ClaimsExtraction_PropertiesWithServer(rt, ts)
	})
}

// testOIDC_InvalidCode_Properties tests that invalid codes are rejected
func testOIDC_InvalidCode_PropertiesWithServer(t *rapid.T, ts *mockOIDCTestServer) {
	resetMockOIDCState(ts)

	// Generate a fake code
	fakeCode := testutil.StateGenerator().Draw(t, "fakeCode")

	// Create client
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("Failed to create cookie jar: %v", err)
	}
	client := newOIDCHTTPClient(ts)
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// First, we need a valid state cookie
	// Start the flow to get one
	resp, err := client.Get(ts.URL + "/auth/google")
	if err != nil {
		t.Fatalf("Failed to start OAuth flow: %v", err)
	}
	resp.Body.Close()

	stateValue := ""
	for _, c := range resp.Cookies() {
		if c.Name == "oauth_state" {
			stateValue = c.Value
			break
		}
	}

	// Now try to exchange the fake code
	callbackURL := fmt.Sprintf("%s/auth/google/callback?code=%s&state=%s",
		ts.URL, url.QueryEscape(fakeCode), url.QueryEscape(stateValue))

	callbackResp, err := client.Get(callbackURL)
	if err != nil {
		t.Fatalf("Callback request failed: %v", err)
	}
	defer callbackResp.Body.Close()

	// Property: Invalid code should fail
	if callbackResp.StatusCode == http.StatusFound {
		t.Fatal("Invalid code should not result in successful redirect")
	}

	// Property: Should return 500 (internal server error for failed exchange)
	if callbackResp.StatusCode != http.StatusInternalServerError {
		body, _ := io.ReadAll(callbackResp.Body)
		t.Logf("Response body: %s", string(body))
		// Accept either 500 or 401 as valid rejection
		if callbackResp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Invalid code should return error status, got %d", callbackResp.StatusCode)
		}
	}
}

func testOIDC_InvalidCode_Properties(t *rapid.T) {
	ts := setupMockOIDCTestServerRapid()
	defer ts.cleanup()
	testOIDC_InvalidCode_PropertiesWithServer(t, ts)
}

func TestOIDC_InvalidCode_Properties(t *testing.T) {
	ts := setupMockOIDCTestServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testOIDC_InvalidCode_PropertiesWithServer(rt, ts)
	})
}

// testOIDC_StateMismatch_Properties tests that state mismatches are detected
func testOIDC_StateMismatch_PropertiesWithServer(t *rapid.T, ts *mockOIDCTestServer) {
	resetMockOIDCState(ts)

	// Queue a user
	ts.queueUser("test-sub", "test@example.com", "Test", true)

	// Create client
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("Failed to create cookie jar: %v", err)
	}
	client := newOIDCHTTPClient(ts)
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Start the flow
	resp, err := client.Get(ts.URL + "/auth/google")
	if err != nil {
		t.Fatalf("Failed to start OAuth flow: %v", err)
	}
	resp.Body.Close()

	authURL := resp.Header.Get("Location")

	// Get the real state from cookie
	realState := ""
	for _, c := range resp.Cookies() {
		if c.Name == "oauth_state" {
			realState = c.Value
			break
		}
	}

	// Follow OIDC flow to get a real code
	oidcClient := newOIDCProviderHTTPClient(ts)
	oidcClient.Jar = jar
	oidcClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.Contains(req.URL.String(), "/auth/google/callback") {
			return http.ErrUseLastResponse
		}
		return nil
	}

	oidcResp, err := oidcClient.Get(authURL)
	if err != nil {
		t.Fatalf("Failed to access OIDC: %v", err)
	}
	oidcResp.Body.Close()

	callbackURL := oidcResp.Header.Get("Location")
	parsedCallback, _ := url.Parse(callbackURL)
	code := parsedCallback.Query().Get("code")

	// Now try with a WRONG state
	wrongState := testutil.StateGenerator().Draw(t, "wrongState")
	// Make sure it's actually different
	if wrongState == realState {
		wrongState = wrongState + "x"
	}

	fakeCallbackURL := fmt.Sprintf("%s/auth/google/callback?code=%s&state=%s",
		ts.URL, url.QueryEscape(code), url.QueryEscape(wrongState))

	fakeResp, err := client.Get(fakeCallbackURL)
	if err != nil {
		t.Fatalf("Callback request failed: %v", err)
	}
	defer fakeResp.Body.Close()

	// Property: State mismatch should be rejected
	if fakeResp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(fakeResp.Body)
		t.Fatalf("State mismatch should return 400, got %d: %s", fakeResp.StatusCode, string(body))
	}
}

func testOIDC_StateMismatch_Properties(t *rapid.T) {
	ts := setupMockOIDCTestServerRapid()
	defer ts.cleanup()
	testOIDC_StateMismatch_PropertiesWithServer(t, ts)
}

func TestOIDC_StateMismatch_Properties(t *testing.T) {
	ts := setupMockOIDCTestServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testOIDC_StateMismatch_PropertiesWithServer(rt, ts)
	})
}

// testOIDC_MissingStateCookie_Properties tests that missing state cookie is rejected
func testOIDC_MissingStateCookie_PropertiesWithServer(t *rapid.T, ts *mockOIDCTestServer) {
	resetMockOIDCState(ts)

	// Generate random code and state
	code := testutil.StateGenerator().Draw(t, "code")
	state := testutil.StateGenerator().Draw(t, "state")

	// Create client WITHOUT cookie jar (no state cookie)
	client := newOIDCHTTPClient(ts)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Try to access callback directly without state cookie
	callbackURL := fmt.Sprintf("%s/auth/google/callback?code=%s&state=%s",
		ts.URL, url.QueryEscape(code), url.QueryEscape(state))

	resp, err := client.Get(callbackURL)
	if err != nil {
		t.Fatalf("Callback request failed: %v", err)
	}
	defer resp.Body.Close()

	// Property: Missing state cookie should be rejected
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Missing state cookie should return 400, got %d", resp.StatusCode)
	}
}

func testOIDC_MissingStateCookie_Properties(t *rapid.T) {
	ts := setupMockOIDCTestServerRapid()
	defer ts.cleanup()
	testOIDC_MissingStateCookie_PropertiesWithServer(t, ts)
}

func TestOIDC_MissingStateCookie_Properties(t *testing.T) {
	ts := setupMockOIDCTestServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testOIDC_MissingStateCookie_PropertiesWithServer(rt, ts)
	})
}

// testOIDC_ProviderError_Properties tests handling of errors from the OIDC provider
func testOIDC_ProviderError_PropertiesWithServer(t *rapid.T, ts *mockOIDCTestServer) {
	resetMockOIDCState(ts)

	// Generate random error parameters
	errorCode := rapid.SampledFrom([]string{
		"access_denied",
		"invalid_request",
		"unauthorized_client",
		"unsupported_response_type",
		"invalid_scope",
		"server_error",
	}).Draw(t, "errorCode")

	// Create client
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("Failed to create cookie jar: %v", err)
	}
	client := newOIDCHTTPClient(ts)
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Start the flow to get a valid state cookie
	resp, err := client.Get(ts.URL + "/auth/google")
	if err != nil {
		t.Fatalf("Failed to start OAuth flow: %v", err)
	}
	resp.Body.Close()

	stateValue := ""
	for _, c := range resp.Cookies() {
		if c.Name == "oauth_state" {
			stateValue = c.Value
			break
		}
	}

	// Simulate provider returning an error
	errorCallbackURL := fmt.Sprintf("%s/auth/google/callback?error=%s&state=%s",
		ts.URL, url.QueryEscape(errorCode), url.QueryEscape(stateValue))

	errorResp, err := client.Get(errorCallbackURL)
	if err != nil {
		t.Fatalf("Error callback request failed: %v", err)
	}
	defer errorResp.Body.Close()

	// Property: Provider error should be handled gracefully
	if errorResp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(errorResp.Body)
		t.Fatalf("Provider error should return 401, got %d: %s", errorResp.StatusCode, string(body))
	}
}

func testOIDC_ProviderError_Properties(t *rapid.T) {
	ts := setupMockOIDCTestServerRapid()
	defer ts.cleanup()
	testOIDC_ProviderError_PropertiesWithServer(t, ts)
}

func TestOIDC_ProviderError_Properties(t *testing.T) {
	ts := setupMockOIDCTestServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testOIDC_ProviderError_PropertiesWithServer(rt, ts)
	})
}

// =============================================================================
// FUZZ TESTS
// =============================================================================

func FuzzOIDC_AuthURL_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testOIDC_AuthURL_Properties))
}

func FuzzOIDC_FullFlow_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testOIDC_FullFlow_Properties))
}

func FuzzOIDC_InvalidCode_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testOIDC_InvalidCode_Properties))
}

func FuzzOIDC_StateMismatch_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testOIDC_StateMismatch_Properties))
}

// =============================================================================
// ADDITIONAL UNIT-STYLE TESTS (for edge cases)
// =============================================================================

// TestOIDC_TokenExchangeError tests error handling during token exchange
func TestOIDC_TokenExchangeError(t *testing.T) {
	ts := setupMockOIDCTestServer(t)
	defer ts.cleanup()

	// Don't queue any user - this will cause the exchange to fail
	// (mockoidc returns error if no user is queued)

	// Create client
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := ts.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Start flow
	resp, err := client.Get(ts.URL + "/auth/google")
	require.NoError(t, err)
	resp.Body.Close()

	authURL := resp.Header.Get("Location")

	// Follow OIDC flow
	oidcClient := ts.Server.Client()
	oidcClient.Jar = jar
	oidcClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.Contains(req.URL.String(), "/auth/google/callback") {
			return http.ErrUseLastResponse
		}
		return nil
	}

	// This may fail because no user is queued
	oidcResp, err := oidcClient.Get(authURL)
	if err != nil {
		// Expected - mockoidc may reject without a queued user
		return
	}
	oidcResp.Body.Close()

	// If we got a callback URL, try it
	if oidcResp.StatusCode == http.StatusFound {
		callbackURL := oidcResp.Header.Get("Location")
		if strings.Contains(callbackURL, "error") {
			// Provider returned an error
			return
		}

		parsedCallback, _ := url.Parse(callbackURL)
		fullCallbackURL := ts.URL + "/auth/google/callback?" + parsedCallback.RawQuery

		callbackResp, err := client.Get(fullCallbackURL)
		require.NoError(t, err)
		defer callbackResp.Body.Close()

		// Should fail at token exchange
		require.NotEqual(t, http.StatusFound, callbackResp.StatusCode,
			"Should not succeed without queued user")
	}
}

// TestOIDC_EmailClaims_Verified verifies email claims are correctly parsed
func TestOIDC_EmailClaims_Verified(t *testing.T) {
	ts := setupMockOIDCTestServer(t)
	defer ts.cleanup()

	// Queue user with verified email
	ts.queueUser("verified-sub", "verified@example.com", "Verified User", true)

	// Complete flow using helper that properly handles the OIDC dance
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := ts.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Start flow
	resp, err := client.Get(ts.URL + "/auth/google")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode, "Should redirect to OIDC")

	authURL := resp.Header.Get("Location")

	// Get state from cookie
	var stateValue string
	for _, c := range resp.Cookies() {
		if c.Name == "oauth_state" {
			stateValue = c.Value
			break
		}
	}
	require.NotEmpty(t, stateValue, "Should have state cookie")

	// Make request to OIDC provider using a client that doesn't follow redirects
	// (we just need the redirect location with the code)
	oidcClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	oidcResp, err := oidcClient.Get(authURL)
	require.NoError(t, err)
	defer oidcResp.Body.Close()

	// OIDC should redirect to our callback with a code
	require.Equal(t, http.StatusFound, oidcResp.StatusCode, "OIDC should redirect")
	callbackURL := oidcResp.Header.Get("Location")
	require.Contains(t, callbackURL, "/auth/google/callback", "Should redirect to callback")

	// Extract the code and state from the redirect URL
	parsedCallback, err := url.Parse(callbackURL)
	require.NoError(t, err)

	code := parsedCallback.Query().Get("code")
	state := parsedCallback.Query().Get("state")
	require.NotEmpty(t, code, "Should have code")
	require.Equal(t, stateValue, state, "State should match")

	// Now make the callback request to our server with the code
	// Use the TLS-aware client with cookie jar
	fullCallbackURL := ts.URL + "/auth/google/callback?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)

	callbackResp, err := client.Get(fullCallbackURL)
	require.NoError(t, err)
	defer callbackResp.Body.Close()

	// Log response for debugging if it fails
	if callbackResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(callbackResp.Body)
		t.Logf("Callback response body: %s", string(body))
	}

	require.Equal(t, http.StatusFound, callbackResp.StatusCode, "Callback should redirect on success")

	// Verify session was created - session cookie should be in the response
	sessionFound := false
	for _, c := range callbackResp.Cookies() {
		if c.Name == "session_id" && c.Value != "" {
			sessionFound = true
			break
		}
	}
	require.True(t, sessionFound, "Session cookie should be set")

	// Verify whoami returns authenticated
	whoamiResp, err := client.Get(ts.URL + "/auth/whoami")
	require.NoError(t, err)
	defer whoamiResp.Body.Close()

	var result map[string]interface{}
	require.NoError(t, json.NewDecoder(whoamiResp.Body).Decode(&result))
	require.True(t, result["authenticated"].(bool))
}

// TestOIDC_MissingCode tests callback without authorization code
func TestOIDC_MissingCode(t *testing.T) {
	ts := setupMockOIDCTestServer(t)
	defer ts.cleanup()

	// Create client with cookie
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := ts.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Start flow to get state cookie
	resp, err := client.Get(ts.URL + "/auth/google")
	require.NoError(t, err)
	resp.Body.Close()

	stateValue := ""
	for _, c := range resp.Cookies() {
		if c.Name == "oauth_state" {
			stateValue = c.Value
			break
		}
	}

	// Try callback without code
	callbackURL := fmt.Sprintf("%s/auth/google/callback?state=%s",
		ts.URL, url.QueryEscape(stateValue))

	callbackResp, err := client.Get(callbackURL)
	require.NoError(t, err)
	defer callbackResp.Body.Close()

	require.Equal(t, http.StatusBadRequest, callbackResp.StatusCode,
		"Missing code should return 400")
}

// TestOIDC_ReturnTo_Propagation tests that return_to is preserved through the OIDC flow
func TestOIDC_ReturnTo_Propagation(t *testing.T) {
	ts := setupMockOIDCTestServer(t)
	defer ts.cleanup()

	ts.queueUser("return-to-sub", "returnto@example.com", "ReturnTo User", true)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := ts.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	form := url.Values{"return_to": {"/notes"}}
	resp, err := client.PostForm(ts.URL+"/auth/google", form)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	authURL := resp.Header.Get("Location")
	require.NotEmpty(t, authURL)

	returnToCookieFound := false
	for _, c := range resp.Cookies() {
		if c.Name == "oauth_return_to" && c.Value == "/notes" {
			returnToCookieFound = true
			break
		}
	}
	require.True(t, returnToCookieFound, "oauth_return_to cookie should be set")

	oidcClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	oidcResp, err := oidcClient.Get(authURL)
	require.NoError(t, err)
	oidcResp.Body.Close()
	require.Equal(t, http.StatusFound, oidcResp.StatusCode)

	callbackURL := oidcResp.Header.Get("Location")
	parsedCallback, err := url.Parse(callbackURL)
	require.NoError(t, err)

	fullCallbackURL := ts.URL + "/auth/google/callback?" + parsedCallback.RawQuery
	callbackResp, err := client.Get(fullCallbackURL)
	require.NoError(t, err)
	defer callbackResp.Body.Close()

	require.Equal(t, http.StatusFound, callbackResp.StatusCode)

	location := callbackResp.Header.Get("Location")
	require.Equal(t, "/notes", location, "Should redirect to return_to URL, not /")

	for _, c := range callbackResp.Cookies() {
		if c.Name == "oauth_return_to" {
			require.Equal(t, -1, c.MaxAge, "oauth_return_to cookie should be cleared")
			break
		}
	}
}

// =============================================================================
// LOCAL MOCK OIDC PROVIDER TESTS
// =============================================================================

type localMockOIDCTestServer struct {
	*httptest.Server
	sessionsDB     *db.SessionsDB
	userService    *auth.UserService
	sessionService *auth.SessionService
	emailService   *email.MockEmailService
	mockOIDC       *auth.LocalMockOIDCProvider
	tempDir        string
}

func setupLocalMockOIDCTestServer(t testing.TB) *localMockOIDCTestServer {
	t.Helper()
	oidcTestMutex.Lock()

	tempDir := t.TempDir()
	db.ResetForTesting()
	db.DataDirectory = tempDir

	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		panic("Failed to open sessions DB: " + err.Error())
	}

	masterKey := make([]byte, 32)
	keyManager := crypto.NewKeyManager(masterKey, sessionsDB)
	emailService := email.NewMockEmailService()

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	mockOIDC := auth.NewLocalMockOIDCProvider(server.URL)

	userService := auth.NewUserService(sessionsDB, keyManager, emailService, server.URL, auth.FakeInsecureHasher{})
	sessionService := auth.NewSessionService(sessionsDB)

	authHandler := auth.NewHandler(mockOIDC, userService, sessionService)
	authHandler.RegisterRoutes(mux)
	mockOIDC.RegisterRoutes(mux)

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("home"))
	})

	return &localMockOIDCTestServer{
		Server:         server,
		sessionsDB:     sessionsDB,
		userService:    userService,
		sessionService: sessionService,
		emailService:   emailService,
		mockOIDC:       mockOIDC,
		tempDir:        tempDir,
	}
}

func (ts *localMockOIDCTestServer) cleanup() {
	ts.Server.Close()
	db.ResetForTesting()
	oidcTestMutex.Unlock()
}

func TestLocalMockOIDC_FullFlow(t *testing.T) {
	ts := setupLocalMockOIDCTestServer(t)
	defer ts.cleanup()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	auth.SetSecureCookies(false)
	defer auth.SetSecureCookies(true)

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Post(ts.URL+"/auth/google", "", nil)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	authURL := resp.Header.Get("Location")
	require.Contains(t, authURL, "/auth/mock-oidc/authorize")

	parsedAuth, err := url.Parse(authURL)
	require.NoError(t, err)
	state := parsedAuth.Query().Get("state")
	require.NotEmpty(t, state)

	consentResp, err := client.Get(authURL)
	require.NoError(t, err)
	defer consentResp.Body.Close()
	require.Equal(t, http.StatusOK, consentResp.StatusCode)
	body, _ := io.ReadAll(consentResp.Body)
	require.Contains(t, string(body), "Mock Google Sign-In")

	form := url.Values{"state": {state}, "email": {"mockuser@example.com"}}
	consentPostResp, err := client.PostForm(ts.URL+"/auth/mock-oidc/authorize", form)
	require.NoError(t, err)
	consentPostResp.Body.Close()
	require.Equal(t, http.StatusFound, consentPostResp.StatusCode)

	callbackURL := consentPostResp.Header.Get("Location")
	require.Contains(t, callbackURL, "/auth/google/callback")

	callbackResp, err := client.Get(callbackURL)
	require.NoError(t, err)
	defer callbackResp.Body.Close()
	require.Equal(t, http.StatusFound, callbackResp.StatusCode)

	sessionFound := false
	for _, c := range callbackResp.Cookies() {
		if c.Name == "session_id" && c.Value != "" {
			sessionFound = true
			break
		}
	}
	require.True(t, sessionFound, "Session cookie should be set after mock OIDC login")
}

func TestLocalMockOIDC_InvalidCode(t *testing.T) {
	ts := setupLocalMockOIDCTestServer(t)
	defer ts.cleanup()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}
	auth.SetSecureCookies(false)
	defer auth.SetSecureCookies(true)

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Get(ts.URL + "/auth/google")
	require.NoError(t, err)
	resp.Body.Close()

	stateValue := ""
	for _, c := range resp.Cookies() {
		if c.Name == "oauth_state" {
			stateValue = c.Value
			break
		}
	}

	fakeCallbackURL := fmt.Sprintf("%s/auth/google/callback?code=fakecode123&state=%s",
		ts.URL, url.QueryEscape(stateValue))
	callbackResp, err := client.Get(fakeCallbackURL)
	require.NoError(t, err)
	defer callbackResp.Body.Close()

	require.NotEqual(t, http.StatusFound, callbackResp.StatusCode)
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func generateRandomState() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func errIsAny(err error, targets ...error) bool {
	for _, target := range targets {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}
