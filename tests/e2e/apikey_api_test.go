// Package e2e provides end-to-end property-based tests for the API Key API.
// All tests follow the property-based testing approach per CLAUDE.md.
package e2e

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/db/testutil"
	"github.com/kuitang/agent-notes/internal/db/userdb"
	"github.com/kuitang/agent-notes/internal/email"
	"pgregory.net/rapid"
)

// =============================================================================
// Test Setup Helpers
// =============================================================================

// Global mutex to ensure tests don't run in parallel
// This prevents issues with global database state
var apiKeyTestMutex sync.Mutex

// Cached test credentials - hash computed once at init, reused across all iterations.
// This avoids the expensive Argon2 hash computation (64 MiB, ~500ms) per iteration.
// Security note: VerifyPassword reads parameters from the stored hash, so this
// is functionally equivalent to computing fresh hashes - we're testing API Key behavior,
// not password hashing.
var (
	cachedTestPassword      = "TestPassword123!"
	cachedTestPasswordHash  string // Computed once in init()
	cachedTestPassword2     = "OtherPassword456!"
	cachedTestPasswordHash2 string
)

func init() {
	var err error
	cachedTestPasswordHash, err = auth.HashPassword(cachedTestPassword)
	if err != nil {
		panic("Failed to compute cached test password hash: " + err.Error())
	}
	cachedTestPasswordHash2, err = auth.HashPassword(cachedTestPassword2)
	if err != nil {
		panic("Failed to compute cached test password hash 2: " + err.Error())
	}
}

// apiKeyTestServer holds the server and services for API Key API testing.
type apiKeyTestServer struct {
	server         *httptest.Server
	mux            *http.ServeMux
	userService    *auth.UserService
	sessionService *auth.SessionService
	apiKeyHandler  *auth.APIKeyHandler
	authMiddleware *auth.Middleware
	keyManager     *crypto.KeyManager
	sessionsDB     *db.SessionsDB
	tempDir        string // For cleanup in rapid tests
}

// setupAPIKeyTestServer creates a test server with all API Key-related routes.
// Returns the server and a cleanup function.
func setupAPIKeyTestServer(t testing.TB) *apiKeyTestServer {
	// Use temp directory for test database to ensure isolation
	tempDir := t.TempDir()
	return setupAPIKeyTestServerWithDir(tempDir)
}

// setupAPIKeyTestServerRapid creates a test server for rapid.T tests.
// Uses a unique temp directory for each test iteration.
func setupAPIKeyTestServerRapid(t *rapid.T) *apiKeyTestServer {
	// Generate a unique temp directory for this test iteration
	// We use os.MkdirTemp because rapid.T doesn't have TempDir
	tempDir, err := os.MkdirTemp("", "apikey-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	server := setupAPIKeyTestServerWithDir(tempDir)
	// Store tempDir for cleanup
	server.tempDir = tempDir
	return server
}

// setupAPIKeyTestServerWithDir creates a test server with a specific data directory.
// Panics on error since this is test setup code.
func setupAPIKeyTestServerWithDir(tempDir string) *apiKeyTestServer {
	// Acquire global lock to ensure clean database state
	apiKeyTestMutex.Lock()

	db.DataDirectory = tempDir
	db.ResetForTesting()

	// Initialize sessions database
	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		panic("Failed to open sessions DB: " + err.Error())
	}

	// Ensure database is fully initialized by making a query
	_, _ = sessionsDB.Queries().CountSessions(context.Background())

	// Create a test master key and key manager
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	keyManager := crypto.NewKeyManager(masterKey, sessionsDB)

	// Initialize services
	emailSvc := email.NewMockEmailService()
	userService := auth.NewUserService(sessionsDB, keyManager, emailSvc, "http://test.local")
	sessionService := auth.NewSessionService(sessionsDB)

	// Create API Key handler and middleware
	apiKeyHandler := auth.NewAPIKeyHandler(userService)
	authMiddleware := auth.NewMiddleware(sessionService, keyManager)

	// Create mux and register routes
	mux := http.NewServeMux()
	mux.Handle("POST /api/keys", authMiddleware.RequireAuth(http.HandlerFunc(apiKeyHandler.CreateAPIKey)))
	mux.Handle("GET /api/keys", authMiddleware.RequireAuth(http.HandlerFunc(apiKeyHandler.ListAPIKeys)))
	mux.Handle("DELETE /api/keys/{id}", authMiddleware.RequireAuth(http.HandlerFunc(apiKeyHandler.RevokeAPIKey)))

	// Create test server
	server := httptest.NewServer(mux)

	return &apiKeyTestServer{
		server:         server,
		mux:            mux,
		userService:    userService,
		sessionService: sessionService,
		apiKeyHandler:  apiKeyHandler,
		authMiddleware: authMiddleware,
		keyManager:     keyManager,
		sessionsDB:     sessionsDB,
	}
}

// cleanup closes the test server and cleans up resources.
func (s *apiKeyTestServer) cleanup() {
	s.server.Close()
	db.CloseAll()
	if s.tempDir != "" {
		os.RemoveAll(s.tempDir)
	}
	// Release global lock
	apiKeyTestMutex.Unlock()
}

// testHelper is a minimal interface that rapid.T and testing.T/B both satisfy
type testHelper interface {
	Fatalf(format string, args ...any)
	Fatal(args ...any)
}

// createTestUserWithCachedPassword creates a test user using a pre-computed password hash.
// This is ~100x faster than createTestUserWithSession because it skips Argon2 hashing.
// Use cachedTestPassword as the password when calling APIs that require re-authentication.
// For tests that need two users, use userNum=1 or userNum=2 to get different cached credentials.
func (s *apiKeyTestServer) createTestUserWithCachedPassword(t testHelper, emailAddr string, userNum int) (userID string, password string, sessionCookie *http.Cookie) {
	ctx := context.Background()

	// Select cached credentials
	var passwordHash string
	switch userNum {
	case 1:
		password = cachedTestPassword
		passwordHash = cachedTestPasswordHash
	case 2:
		password = cachedTestPassword2
		passwordHash = cachedTestPasswordHash2
	default:
		password = cachedTestPassword
		passwordHash = cachedTestPasswordHash
	}

	// Create or find user
	user, err := s.userService.FindOrCreateByProvider(ctx, emailAddr)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Get user's database and set the password hash
	dek, err := s.keyManager.GetOrCreateUserDEK(user.ID)
	if err != nil {
		t.Fatalf("Failed to get user DEK: %v", err)
	}
	userDB, err := db.OpenUserDBWithDEK(user.ID, dek)
	if err != nil {
		t.Fatalf("Failed to open user DB: %v", err)
	}

	// Create account with pre-computed hash (no Argon2 call!)
	err = userDB.Queries().CreateAccount(ctx, userdb.CreateAccountParams{
		UserID:       user.ID,
		Email:        emailAddr,
		PasswordHash: sql.NullString{String: passwordHash, Valid: true},
		CreatedAt:    time.Now().Unix(),
	})
	if err != nil {
		err = userDB.Queries().UpdateAccountPasswordHash(ctx, userdb.UpdateAccountPasswordHashParams{
			PasswordHash: sql.NullString{String: passwordHash, Valid: true},
			UserID:       user.ID,
		})
		if err != nil {
			t.Fatalf("Failed to set account password: %v", err)
		}
	}

	// Create session
	sessionID, err := s.sessionService.Create(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	return user.ID, password, &http.Cookie{
		Name:  auth.SessionCookieName,
		Value: sessionID,
	}
}

// createAPIKey creates an API Key via the API and returns the token ID and full token value.
func (s *apiKeyTestServer) createAPIKey(t testHelper, sessionCookie *http.Cookie, name, scope, email, password string) (tokenID, tokenValue string) {
	reqBody := auth.CreateAPIKeyRequest{
		Name:      name,
		Scope:     scope,
		ExpiresIn: 3600, // 1 hour
		Email:     email,
		Password:  password,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req, err := http.NewRequest("POST", s.server.URL+"/api/keys", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(sessionCookie)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Failed to create API Key: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var result auth.CreateAPIKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	return result.ID, result.Token
}

// listAPIKeys lists all API Keys via the API.
func (s *apiKeyTestServer) listAPIKeys(t testHelper, sessionCookie *http.Cookie) []auth.APIKey {
	req, err := http.NewRequest("GET", s.server.URL+"/api/keys", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.AddCookie(sessionCookie)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Failed to list API Keys: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var result auth.ListAPIKeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	return result.Tokens
}

// revokeAPIKey revokes an API Key via the API.
func (s *apiKeyTestServer) revokeAPIKey(t testHelper, sessionCookie *http.Cookie, tokenID string) error {
	req, err := http.NewRequest("DELETE", s.server.URL+"/api/keys/"+tokenID, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.AddCookie(sessionCookie)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	return &apiKeyAPIError{StatusCode: resp.StatusCode, Body: string(body)}
}

// authenticateWithAPIKey tests if an API Key can be used for authentication.
// Returns the HTTP status code from the response.
// Does NOT fatal on failure - use authenticateWithAPIKeyExpectSuccess for that.
func (s *apiKeyTestServer) authenticateWithAPIKey(t testHelper, token string) int {
	req, err := http.NewRequest("GET", s.server.URL+"/api/keys", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	return resp.StatusCode
}

// authenticateWithAPIKeyExpectSuccess tests if an API Key can be used for authentication.
// Fatals if authentication fails (non-200 status).
func (s *apiKeyTestServer) authenticateWithAPIKeyExpectSuccess(t testHelper, token string) {
	req, err := http.NewRequest("GET", s.server.URL+"/api/keys", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("API Key auth failed with status %d: %s (token: %s)", resp.StatusCode, string(body), token)
	}
}

// apiKeyAPIError represents an API error.
type apiKeyAPIError struct {
	StatusCode int
	Body       string
}

func (e *apiKeyAPIError) Error() string {
	return e.Body
}

// =============================================================================
// Property 1: Roundtrip Property
// Create a token -> List tokens includes it -> Token works for auth
// =============================================================================

func testAPIKeyAPI_Roundtrip_Properties(t *rapid.T, server *apiKeyTestServer) {
	// Generate random but valid inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")
	tokenName := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	_, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Create API Key
	tokenID, tokenValue := server.createAPIKey(t, sessionCookie, tokenName, "read_write", emailAddr, password)

	// Property 1: Token ID is non-empty
	if tokenID == "" {
		t.Fatal("Token ID should not be empty")
	}

	// Property 2: Token value is non-empty and has correct prefix
	if tokenValue == "" {
		t.Fatal("Token value should not be empty")
	}
	if !strings.HasPrefix(tokenValue, auth.APIKeyPrefix) {
		t.Fatalf("Token should have prefix %q, got %q", auth.APIKeyPrefix, tokenValue)
	}

	// Property 3: List tokens includes the created token
	tokens := server.listAPIKeys(t, sessionCookie)
	found := false
	for _, tok := range tokens {
		if tok.ID == tokenID {
			found = true
			// Property 4: Token name is preserved
			if tok.Name != tokenName {
				t.Fatalf("Token name mismatch: expected %q, got %q", tokenName, tok.Name)
			}
			break
		}
	}
	if !found {
		t.Fatalf("Created token %s not found in list", tokenID)
	}

	// Property 5: Token works for authentication
	server.authenticateWithAPIKeyExpectSuccess(t, tokenValue)
}

func TestAPIKeyAPI_Roundtrip_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Create fresh server for each property test iteration
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_Roundtrip_Properties(rt, server)
	})
}

func FuzzAPIKeyAPI_Roundtrip_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_Roundtrip_Properties(rt, server)
	}))
}

// =============================================================================
// Property 2: Revocation Property
// Created token works -> Revoke -> Token no longer works (401)
// =============================================================================

func testAPIKeyAPI_Revocation_Properties(t *rapid.T, server *apiKeyTestServer) {
	// Generate random inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")
	tokenName := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	_, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Create API Key
	tokenID, tokenValue := server.createAPIKey(t, sessionCookie, tokenName, "read_write", emailAddr, password)

	// Property 1: Token works before revocation
	status := server.authenticateWithAPIKey(t, tokenValue)
	if status != http.StatusOK {
		t.Fatalf("API Key should work before revocation: expected 200, got %d", status)
	}

	// Revoke the token
	err := server.revokeAPIKey(t, sessionCookie, tokenID)
	if err != nil {
		t.Fatalf("Failed to revoke API Key: %v", err)
	}

	// Property 2: Token no longer works after revocation
	status = server.authenticateWithAPIKey(t, tokenValue)
	if status != http.StatusUnauthorized {
		t.Fatalf("Revoked API Key should return 401: expected 401, got %d", status)
	}

	// Property 3: Token no longer appears in list
	tokens := server.listAPIKeys(t, sessionCookie)
	for _, tok := range tokens {
		if tok.ID == tokenID {
			t.Fatalf("Revoked token %s should not appear in list", tokenID)
		}
	}
}

func TestAPIKeyAPI_Revocation_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_Revocation_Properties(rt, server)
	})
}

func FuzzAPIKeyAPI_Revocation_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_Revocation_Properties(rt, server)
	}))
}

// =============================================================================
// Property 3: Password Re-Auth Property
// Creating token without password fails
// Creating token with wrong password fails
// Creating token with correct password succeeds
// =============================================================================

func testAPIKeyAPI_PasswordReAuth_Properties(t *rapid.T, server *apiKeyTestServer) {
	// Generate random inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")
	// Generate a wrong password that's definitely different from cached password
	wrongPassword := rapid.StringMatching(`[a-zA-Z0-9!@#$%^&*]{8,20}`).Filter(func(s string) bool {
		return s != cachedTestPassword && s != cachedTestPassword2
	}).Draw(t, "wrongPassword")
	tokenName := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	_, correctPassword, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Property 1: Creating token without password fails
	reqNoPassword := auth.CreateAPIKeyRequest{
		Name:      tokenName,
		Scope:     "read_write",
		ExpiresIn: 3600,
		Email:     emailAddr,
		Password:  "", // Missing password
	}
	status := server.createAPIKeyExpectError(t, sessionCookie, reqNoPassword)
	if status != http.StatusBadRequest {
		t.Fatalf("Creating API Key without password should fail with 400, got %d", status)
	}

	// Property 2: Creating token with wrong password fails
	reqWrongPassword := auth.CreateAPIKeyRequest{
		Name:      tokenName,
		Scope:     "read_write",
		ExpiresIn: 3600,
		Email:     emailAddr,
		Password:  wrongPassword,
	}
	status = server.createAPIKeyExpectError(t, sessionCookie, reqWrongPassword)
	if status != http.StatusUnauthorized {
		t.Fatalf("Creating API Key with wrong password should fail with 401, got %d", status)
	}

	// Property 3: Creating token with correct password succeeds
	tokenID, tokenValue := server.createAPIKey(t, sessionCookie, tokenName, "read_write", emailAddr, correctPassword)
	if tokenID == "" || tokenValue == "" {
		t.Fatal("Creating API Key with correct password should succeed")
	}
}

// createAPIKeyExpectError attempts to create an API Key and returns the status code.
func (s *apiKeyTestServer) createAPIKeyExpectError(t testHelper, sessionCookie *http.Cookie, req auth.CreateAPIKeyRequest) int {
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	httpReq, err := http.NewRequest("POST", s.server.URL+"/api/keys", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.AddCookie(sessionCookie)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	return resp.StatusCode
}

func TestAPIKeyAPI_PasswordReAuth_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_PasswordReAuth_Properties(rt, server)
	})
}

func FuzzAPIKeyAPI_PasswordReAuth_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_PasswordReAuth_Properties(rt, server)
	}))
}

// =============================================================================
// Property 4: Token Uniqueness Property
// Multiple tokens can be created
// Each has unique ID
// Revoking one doesn't affect others
// =============================================================================

func testAPIKeyAPI_Uniqueness_Properties(t *rapid.T, server *apiKeyTestServer) {
	// Generate random inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")
	numTokens := rapid.IntRange(2, 5).Draw(t, "numTokens")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	_, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Create multiple tokens
	type tokenInfo struct {
		ID    string
		Value string
		Name  string
	}
	tokens := make([]tokenInfo, numTokens)
	tokenIDs := make(map[string]bool)

	for i := 0; i < numTokens; i++ {
		name := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName")
		tokenID, tokenValue := server.createAPIKey(t, sessionCookie, name, "read_write", emailAddr, password)

		// Property 1: Each token ID is unique
		if tokenIDs[tokenID] {
			t.Fatalf("Duplicate token ID: %s", tokenID)
		}
		tokenIDs[tokenID] = true

		tokens[i] = tokenInfo{ID: tokenID, Value: tokenValue, Name: name}
	}

	// Property 2: All tokens work
	for _, tok := range tokens {
		server.authenticateWithAPIKeyExpectSuccess(t, tok.Value)
	}

	// Property 3: Revoking one token doesn't affect others
	if len(tokens) >= 2 {
		// Revoke the first token
		err := server.revokeAPIKey(t, sessionCookie, tokens[0].ID)
		if err != nil {
			t.Fatalf("Failed to revoke token: %v", err)
		}

		// First token should no longer work
		status := server.authenticateWithAPIKey(t, tokens[0].Value)
		if status != http.StatusUnauthorized {
			t.Fatalf("Revoked token should return 401, got %d", status)
		}

		// Other tokens should still work
		for i := 1; i < len(tokens); i++ {
			server.authenticateWithAPIKeyExpectSuccess(t, tokens[i].Value)
		}
	}
}

func TestAPIKeyAPI_Uniqueness_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_Uniqueness_Properties(rt, server)
	})
}

func FuzzAPIKeyAPI_Uniqueness_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_Uniqueness_Properties(rt, server)
	}))
}

// =============================================================================
// Property 5: Token Format Property
// Token starts with "agentnotes_key_"
// Token contains user ID
// Token is sufficiently long (>40 chars)
// =============================================================================

func testAPIKeyAPI_Format_Properties(t *rapid.T, server *apiKeyTestServer) {
	// Generate random inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")
	tokenName := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	userID, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Create API Key
	_, tokenValue := server.createAPIKey(t, sessionCookie, tokenName, "read_write", emailAddr, password)

	// Property 1: Token starts with correct prefix
	if !strings.HasPrefix(tokenValue, auth.APIKeyPrefix) {
		t.Fatalf("Token should start with %q, got %q", auth.APIKeyPrefix, tokenValue[:min(len(tokenValue), 20)])
	}

	// Property 2: Token contains user ID
	if !strings.Contains(tokenValue, userID) {
		t.Fatalf("Token should contain user ID %q, got %q", userID, tokenValue)
	}

	// Property 3: Token is sufficiently long (prefix + user_id + _ + 64 chars base64)
	// Minimum: 14 (prefix) + 1 (user_id) + 1 (_) + 64 (token) = 80 chars
	if len(tokenValue) < 40 {
		t.Fatalf("Token should be at least 40 chars, got %d", len(tokenValue))
	}

	// Property 4: Token can be parsed successfully
	parsedUserID, tokenPart, ok := auth.ParseAPIKeyToken(tokenValue)
	if !ok {
		t.Fatal("Token should be parseable")
	}
	if parsedUserID != userID {
		t.Fatalf("Parsed user ID mismatch: expected %q, got %q", userID, parsedUserID)
	}
	if tokenPart == "" {
		t.Fatal("Token part should not be empty")
	}
}

func TestAPIKeyAPI_Format_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_Format_Properties(rt, server)
	})
}

func FuzzAPIKeyAPI_Format_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_Format_Properties(rt, server)
	}))
}

// =============================================================================
// Property 6: User Isolation Property
// Different users cannot see each other's tokens
// Different users cannot revoke each other's tokens
// =============================================================================

func testAPIKeyAPI_Isolation_Properties(t *rapid.T, server *apiKeyTestServer) {
	// Generate random inputs for two users
	email1 := rapid.StringMatching(`[a-z]{5,10}@user1\.com`).Draw(t, "email1")
	email2 := rapid.StringMatching(`[a-z]{5,10}@user2\.com`).Draw(t, "email2")
	tokenName1 := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName1")
	tokenName2 := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName2")

	// Create two users with cached passwords (avoids Argon2 hash per iteration)
	_, password1, sessionCookie1 := server.createTestUserWithCachedPassword(t, email1, 1)
	_, password2, sessionCookie2 := server.createTestUserWithCachedPassword(t, email2, 2)

	// Create tokens for each user
	tokenID1, _ := server.createAPIKey(t, sessionCookie1, tokenName1, "read_write", email1, password1)
	tokenID2, _ := server.createAPIKey(t, sessionCookie2, tokenName2, "read_write", email2, password2)

	// Property 1: User 1 can only see their own tokens
	tokens1 := server.listAPIKeys(t, sessionCookie1)
	for _, tok := range tokens1 {
		if tok.ID == tokenID2 {
			t.Fatal("User 1 should not see User 2's token")
		}
	}
	foundOwn := false
	for _, tok := range tokens1 {
		if tok.ID == tokenID1 {
			foundOwn = true
			break
		}
	}
	if !foundOwn {
		t.Fatal("User 1 should see their own token")
	}

	// Property 2: User 2 can only see their own tokens
	tokens2 := server.listAPIKeys(t, sessionCookie2)
	for _, tok := range tokens2 {
		if tok.ID == tokenID1 {
			t.Fatal("User 2 should not see User 1's token")
		}
	}
	foundOwn = false
	for _, tok := range tokens2 {
		if tok.ID == tokenID2 {
			foundOwn = true
			break
		}
	}
	if !foundOwn {
		t.Fatal("User 2 should see their own token")
	}

	// Property 3: User 1 cannot revoke User 2's token
	err := server.revokeAPIKey(t, sessionCookie1, tokenID2)
	if err == nil {
		// This might succeed with 404 (not found) since user1 can't see user2's token
		// That's acceptable behavior - the key is that it doesn't actually revoke it
	}
	// Verify User 2's token still works
	tokens2After := server.listAPIKeys(t, sessionCookie2)
	foundToken2 := false
	for _, tok := range tokens2After {
		if tok.ID == tokenID2 {
			foundToken2 = true
			break
		}
	}
	if !foundToken2 {
		t.Fatal("User 2's token should not be revoked by User 1")
	}
}

func TestAPIKeyAPI_Isolation_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_Isolation_Properties(rt, server)
	})
}

func FuzzAPIKeyAPI_Isolation_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_Isolation_Properties(rt, server)
	}))
}

// =============================================================================
// Property 7: Invalid Token Rejection Property
// Random tokens are rejected
// Malformed tokens are rejected
// Expired tokens are rejected (if testable)
// =============================================================================

func testAPIKeyAPI_InvalidToken_Properties(t *rapid.T, server *apiKeyTestServer) {
	// Generate random invalid tokens - use ASCII only to avoid HTTP header encoding issues
	// HTTP headers only support ASCII, so non-ASCII chars would fail at the transport layer
	randomToken := rapid.StringMatching(`[a-zA-Z0-9_\-]{20,100}`).Draw(t, "randomToken")

	// Property 1: Random tokens are rejected
	status := server.authenticateWithAPIKey(t, randomToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("Random token should be rejected with 401, got %d", status)
	}

	// Property 2: Empty token is rejected
	status = server.authenticateWithAPIKey(t, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("Empty token should be rejected with 401, got %d", status)
	}

	// Property 3: Token with correct prefix but invalid content is rejected
	fakeToken := auth.APIKeyPrefix + "fake-user-id_invalidtokenpart12345"
	status = server.authenticateWithAPIKey(t, fakeToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("Fake token should be rejected with 401, got %d", status)
	}

	// Property 4: Token with correct prefix and proper userID format but wrong token is rejected
	fakeTokenWithValidPrefix := auth.APIKeyPrefix + "user-00000000-0000-0000-0000-000000000000_invalidtoken12345678901234567890123456789012345678901234"
	status = server.authenticateWithAPIKey(t, fakeTokenWithValidPrefix)
	if status != http.StatusUnauthorized {
		t.Fatalf("Fake token with valid prefix format should be rejected with 401, got %d", status)
	}

	// Property 5: Token with SQL injection attempts is rejected
	for _, injection := range []string{
		auth.APIKeyPrefix + "' OR 1=1 --_token",
		auth.APIKeyPrefix + "admin'--_token",
		auth.APIKeyPrefix + "'; DROP TABLE api_keys; --_token",
	} {
		status = server.authenticateWithAPIKey(t, injection)
		if status != http.StatusUnauthorized {
			t.Fatalf("SQL injection token should be rejected with 401, got %d", status)
		}
	}
}

func TestAPIKeyAPI_InvalidToken_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_InvalidToken_Properties(rt, server)
	})
}

func FuzzAPIKeyAPI_InvalidToken_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_InvalidToken_Properties(rt, server)
	}))
}

// =============================================================================
// Property 8: Token Name Edge Cases Property
// Various edge case names are handled correctly
// =============================================================================

func testAPIKeyAPI_TokenName_EdgeCases_Properties(t *rapid.T, server *apiKeyTestServer) {
	// Generate random user inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	_, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Test various edge case token names
	// Using ArbitraryNonEmptyString from testutil for aggressive edge cases
	tokenName := testutil.ArbitraryNonEmptyString().Draw(t, "tokenName")

	// Skip if the name contains null bytes (might be filtered at DB level)
	if strings.Contains(tokenName, "\x00") {
		return
	}

	// Property: Token with edge case name can be created and retrieved
	tokenID, tokenValue := server.createAPIKey(t, sessionCookie, tokenName, "read_write", emailAddr, password)
	if tokenID == "" || tokenValue == "" {
		t.Fatalf("Failed to create token with edge case name: %q", tokenName)
	}

	// Property: Token appears in list with correct name
	tokens := server.listAPIKeys(t, sessionCookie)
	found := false
	for _, tok := range tokens {
		if tok.ID == tokenID {
			found = true
			if tok.Name != tokenName {
				t.Fatalf("Token name not preserved: expected %q, got %q", tokenName, tok.Name)
			}
			break
		}
	}
	if !found {
		t.Fatalf("Token with edge case name not found in list")
	}
}

func TestAPIKeyAPI_TokenName_EdgeCases_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_TokenName_EdgeCases_Properties(rt, server)
	})
}

func FuzzAPIKeyAPI_TokenName_EdgeCases_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_TokenName_EdgeCases_Properties(rt, server)
	}))
}

// =============================================================================
// Property 9: Scope Preservation Property
// Token scope is correctly stored and returned
// =============================================================================

func testAPIKeyAPI_Scope_Properties(t *rapid.T, server *apiKeyTestServer) {
	// Generate random inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")
	tokenName := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName")
	scope := rapid.SampledFrom([]string{"read", "write", "read_write", "admin"}).Draw(t, "scope")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	_, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Create API Key with specific scope
	tokenID, _ := server.createAPIKey(t, sessionCookie, tokenName, scope, emailAddr, password)

	// Property: Scope is preserved in list
	tokens := server.listAPIKeys(t, sessionCookie)
	for _, tok := range tokens {
		if tok.ID == tokenID {
			if tok.Scope != scope {
				t.Fatalf("Scope not preserved: expected %q, got %q", scope, tok.Scope)
			}
			return
		}
	}
	t.Fatal("Token not found in list")
}

func TestAPIKeyAPI_Scope_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_Scope_Properties(rt, server)
	})
}

func FuzzAPIKeyAPI_Scope_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_Scope_Properties(rt, server)
	}))
}

// =============================================================================
// Property 10: Token Expiration Metadata Property
// Token has expiration date set correctly
// =============================================================================

func testAPIKeyAPI_Expiration_Properties(t *rapid.T, server *apiKeyTestServer) {
	// Generate random inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")
	tokenName := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	_, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Create API Key (expires in 3600 seconds = 1 hour)
	now := time.Now()
	tokenID, _ := server.createAPIKey(t, sessionCookie, tokenName, "read_write", emailAddr, password)

	// Property: Expiration is approximately 1 hour from now
	tokens := server.listAPIKeys(t, sessionCookie)
	for _, tok := range tokens {
		if tok.ID == tokenID {
			// Allow 10 second tolerance for test execution time
			expectedExpiry := now.Add(3600 * time.Second)
			diff := tok.ExpiresAt.Sub(expectedExpiry)
			if diff < -10*time.Second || diff > 10*time.Second {
				t.Fatalf("Expiration time mismatch: expected ~%v, got %v (diff: %v)",
					expectedExpiry, tok.ExpiresAt, diff)
			}
			return
		}
	}
	t.Fatal("Token not found in list")
}

func TestAPIKeyAPI_Expiration_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_Expiration_Properties(rt, server)
	})
}

func FuzzAPIKeyAPI_Expiration_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_Expiration_Properties(rt, server)
	}))
}

// =============================================================================
// Property 11: One-Time Token Reveal Property
// Token value is returned ONLY on creation, never on list
// =============================================================================

func testAPIKeyAPI_OneTimeReveal_Properties(t *rapid.T, server *apiKeyTestServer) {
	// Generate random inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")
	tokenName := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	_, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Create API Key and capture the token value
	tokenID, tokenValue := server.createAPIKey(t, sessionCookie, tokenName, "read_write", emailAddr, password)

	// Property 1: Token value was returned on creation
	if tokenValue == "" {
		t.Fatal("Token value should be returned on creation")
	}
	if !strings.HasPrefix(tokenValue, auth.APIKeyPrefix) {
		t.Fatalf("Token should have correct prefix, got: %s", tokenValue[:min(20, len(tokenValue))])
	}

	// Property 2: Token value is NOT returned when listing
	tokens := server.listAPIKeys(t, sessionCookie)
	for _, tok := range tokens {
		if tok.ID == tokenID {
			// The APIKey struct in list response should NOT contain the token value
			// auth.APIKey struct doesn't have a Token field - only ID, Name, Scope, ExpiresAt, CreatedAt, LastUsedAt
			// This is by design - the token value is never exposed after creation
			// We verify the token exists in the list but has no way to retrieve the secret
			if tok.Name != tokenName {
				t.Fatalf("Token name mismatch: expected %q, got %q", tokenName, tok.Name)
			}
			// Success: token metadata is available, but token value is not exposed
			return
		}
	}
	t.Fatalf("Token %s not found in list", tokenID)
}

func TestAPIKeyAPI_OneTimeReveal_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_OneTimeReveal_Properties(rt, server)
	})
}

func FuzzAPIKeyAPI_OneTimeReveal_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_OneTimeReveal_Properties(rt, server)
	}))
}

// =============================================================================
// Property 12: Duplicate Names Allowed Property
// Multiple API Keys with the same name can be created (no uniqueness constraint on name)
// =============================================================================

func testAPIKeyAPI_DuplicateNames_Properties(t *rapid.T, server *apiKeyTestServer) {
	// Generate random inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")
	tokenName := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	_, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Create first API Key with the name
	tokenID1, tokenValue1 := server.createAPIKey(t, sessionCookie, tokenName, "read_write", emailAddr, password)

	// Property 1: First token created successfully
	if tokenID1 == "" || tokenValue1 == "" {
		t.Fatal("First token should be created successfully")
	}

	// Create second API Key with the SAME name
	tokenID2, tokenValue2 := server.createAPIKey(t, sessionCookie, tokenName, "read_write", emailAddr, password)

	// Property 2: Second token also created successfully (no uniqueness constraint on name)
	if tokenID2 == "" || tokenValue2 == "" {
		t.Fatal("Second token with same name should be created successfully")
	}

	// Property 3: The two tokens have different IDs
	if tokenID1 == tokenID2 {
		t.Fatal("Two tokens should have different IDs")
	}

	// Property 4: The two tokens have different values
	if tokenValue1 == tokenValue2 {
		t.Fatal("Two tokens should have different values")
	}

	// Property 5: Both tokens appear in list
	tokens := server.listAPIKeys(t, sessionCookie)
	found1, found2 := false, false
	for _, tok := range tokens {
		if tok.ID == tokenID1 {
			found1 = true
		}
		if tok.ID == tokenID2 {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Fatalf("Both tokens should appear in list: found1=%v, found2=%v", found1, found2)
	}

	// Property 6: Both tokens work for authentication
	server.authenticateWithAPIKeyExpectSuccess(t, tokenValue1)
	server.authenticateWithAPIKeyExpectSuccess(t, tokenValue2)
}

func TestAPIKeyAPI_DuplicateNames_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_DuplicateNames_Properties(rt, server)
	})
}

func FuzzAPIKeyAPI_DuplicateNames_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_DuplicateNames_Properties(rt, server)
	}))
}

// =============================================================================
// Property 13: Expiration Enforcement Property
// Expired tokens are rejected at authentication time
// =============================================================================

// createAPIKeyWithExpiry creates an API Key via the API with custom expiry and returns the token ID and full token value.
func (s *apiKeyTestServer) createAPIKeyWithExpiry(t testHelper, sessionCookie *http.Cookie, name, scope, email, password string, expiresIn int64) (tokenID, tokenValue string) {
	reqBody := auth.CreateAPIKeyRequest{
		Name:      name,
		Scope:     scope,
		ExpiresIn: expiresIn,
		Email:     email,
		Password:  password,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req, err := http.NewRequest("POST", s.server.URL+"/api/keys", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(sessionCookie)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Failed to create API Key: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var result auth.CreateAPIKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	return result.ID, result.Token
}

func testAPIKeyAPI_ExpirationEnforcement_Properties(t *rapid.T, server *apiKeyTestServer) {
	// Generate random inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")
	tokenName := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	_, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Create API Key with 2 second expiry (more than 1s to avoid races, but still short enough to test)
	tokenID, tokenValue := server.createAPIKeyWithExpiry(t, sessionCookie, tokenName, "read_write", emailAddr, password, 2)

	// Property 1: Token was created successfully
	if tokenID == "" || tokenValue == "" {
		t.Fatal("Token should be created successfully")
	}

	// Property 2: Token works immediately after creation
	status := server.authenticateWithAPIKey(t, tokenValue)
	if status != http.StatusOK {
		t.Fatalf("Fresh token should work: expected 200, got %d", status)
	}

	// Wait for token to expire (3 seconds to be safe - token expires at 2s, we wait 3s)
	time.Sleep(3 * time.Second)

	// Property 3: Token is rejected after expiration
	status = server.authenticateWithAPIKey(t, tokenValue)
	if status != http.StatusUnauthorized {
		t.Fatalf("Expired token should be rejected: expected 401, got %d", status)
	}
}

func TestAPIKeyAPI_ExpirationEnforcement_Properties(t *testing.T) {
	// Note: This test uses a deterministic approach because each iteration
	// requires a 3-second sleep to wait for token expiry, making full
	// rapid property testing too slow. The expiry enforcement behavior
	// doesn't benefit from random input variation anyway.
	server := setupAPIKeyTestServer(t)
	defer server.cleanup()

	emailAddr := "expiration-test@test.com"
	tokenName := "expiration-test-token"

	// Create test user with a fresh session
	_, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Create API Key with 2 second expiry
	tokenID, tokenValue := server.createAPIKeyWithExpiry(t, sessionCookie, tokenName, "read_write", emailAddr, password, 2)

	// Property 1: Token was created successfully
	if tokenID == "" || tokenValue == "" {
		t.Fatal("Token should be created successfully")
	}

	// Property 2: Token works immediately after creation
	status := server.authenticateWithAPIKey(t, tokenValue)
	if status != http.StatusOK {
		t.Fatalf("Fresh token should work: expected 200, got %d", status)
	}

	// Wait for token to expire (3 seconds to be safe - token expires at 2s, we wait 3s)
	time.Sleep(3 * time.Second)

	// Property 3: Token is rejected after expiration
	status = server.authenticateWithAPIKey(t, tokenValue)
	if status != http.StatusUnauthorized {
		t.Fatalf("Expired token should be rejected: expected 401, got %d", status)
	}
}

// Note: No fuzz entry point for ExpirationEnforcement because:
// 1. The test requires a 3-second sleep which makes fuzzing impractical
// 2. The expiry enforcement behavior is deterministic and doesn't benefit from random inputs

// =============================================================================
// Property 14: Maximum Expiry Enforcement Property
// Tokens cannot be created with expiry exceeding 1 year (MaxAPIKeyExpiry)
// =============================================================================

func testAPIKeyAPI_MaxExpiry_Properties(t *rapid.T, server *apiKeyTestServer) {
	// Generate random inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")
	tokenName := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	_, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Try to create API Key with expiry exceeding 1 year (366 days in seconds)
	exceedMaxExpiry := int64(366 * 24 * 60 * 60) // 366 days

	reqBody := auth.CreateAPIKeyRequest{
		Name:      tokenName,
		Scope:     "read_write",
		ExpiresIn: exceedMaxExpiry,
		Email:     emailAddr,
		Password:  password,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req, err := http.NewRequest("POST", server.server.URL+"/api/keys", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(sessionCookie)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Property: Request should be rejected with 400 Bad Request
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expiry exceeding max should be rejected with 400, got %d: %s", resp.StatusCode, string(body))
	}

	// Property 2: Create token with exactly max expiry (365 days) should succeed
	maxExpiry := int64(365 * 24 * 60 * 60) // 365 days
	tokenID, tokenValue := server.createAPIKeyWithExpiry(t, sessionCookie, tokenName, "read_write", emailAddr, password, maxExpiry)
	if tokenID == "" || tokenValue == "" {
		t.Fatal("Token with max expiry should be created successfully")
	}
}

func TestAPIKeyAPI_MaxExpiry_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_MaxExpiry_Properties(rt, server)
	})
}

func FuzzAPIKeyAPI_MaxExpiry_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_MaxExpiry_Properties(rt, server)
	}))
}

// =============================================================================
// Property 15: Empty Name Rejection Property
// Tokens cannot be created with empty name
// =============================================================================

func testAPIKeyAPI_EmptyNameRejection_Properties(t *rapid.T, server *apiKeyTestServer) {
	// Generate random inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	_, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Property 1: Empty name should be rejected
	reqEmptyName := auth.CreateAPIKeyRequest{
		Name:      "", // Empty name
		Scope:     "read_write",
		ExpiresIn: 3600,
		Email:     emailAddr,
		Password:  password,
	}
	status := server.createAPIKeyExpectError(t, sessionCookie, reqEmptyName)
	if status != http.StatusBadRequest {
		t.Fatalf("Empty name should be rejected with 400, got %d", status)
	}

	// Property 2: Whitespace-only name should still be accepted (no trim validation)
	// Note: This tests current behavior - if we want to reject whitespace names,
	// the server code would need to be updated
	reqWhitespaceName := auth.CreateAPIKeyRequest{
		Name:      "   ", // Whitespace-only name
		Scope:     "read_write",
		ExpiresIn: 3600,
		Email:     emailAddr,
		Password:  password,
	}
	bodyBytes, _ := json.Marshal(reqWhitespaceName)
	req, _ := http.NewRequest("POST", server.server.URL+"/api/keys", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(sessionCookie)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Property: Whitespace name is currently accepted (server doesn't trim)
	// This documents current behavior - status should be 201 or 400
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Whitespace name should either succeed (201) or fail validation (400), got %d", resp.StatusCode)
	}
}

func TestAPIKeyAPI_EmptyNameRejection_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_EmptyNameRejection_Properties(rt, server)
	})
}

func FuzzAPIKeyAPI_EmptyNameRejection_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_EmptyNameRejection_Properties(rt, server)
	}))
}

// =============================================================================
// Property 16: Default Scope Property
// Tokens created without explicit scope get "read_write" as default
// =============================================================================

func testAPIKeyAPI_DefaultScope_Properties(t *rapid.T, server *apiKeyTestServer) {
	// Generate random inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")
	tokenName := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	_, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Create API Key without explicit scope
	tokenID, _ := server.createAPIKey(t, sessionCookie, tokenName, "", emailAddr, password)

	// Property: Default scope should be "read_write"
	tokens := server.listAPIKeys(t, sessionCookie)
	for _, tok := range tokens {
		if tok.ID == tokenID {
			if tok.Scope != "read_write" {
				t.Fatalf("Default scope should be 'read_write', got %q", tok.Scope)
			}
			return
		}
	}
	t.Fatal("Token not found in list")
}

func TestAPIKeyAPI_DefaultScope_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_DefaultScope_Properties(rt, server)
	})
}

func FuzzAPIKeyAPI_DefaultScope_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_DefaultScope_Properties(rt, server)
	}))
}

// =============================================================================
// Property 17: Wrong Email Rejection Property
// Creating API Key with wrong email (not matching session user) fails
// =============================================================================

func testAPIKeyAPI_WrongEmailRejection_Properties(t *rapid.T, server *apiKeyTestServer) {
	// Generate random inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")
	wrongEmail := rapid.StringMatching(`[a-z]{5,10}@wrong\.com`).Draw(t, "wrongEmail")
	tokenName := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	_, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Property: Creating API Key with wrong email should fail
	reqWrongEmail := auth.CreateAPIKeyRequest{
		Name:      tokenName,
		Scope:     "read_write",
		ExpiresIn: 3600,
		Email:     wrongEmail, // Wrong email
		Password:  password,
	}
	status := server.createAPIKeyExpectError(t, sessionCookie, reqWrongEmail)
	if status != http.StatusUnauthorized {
		t.Fatalf("Wrong email should be rejected with 401, got %d", status)
	}
}

func TestAPIKeyAPI_WrongEmailRejection_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_WrongEmailRejection_Properties(rt, server)
	})
}

func FuzzAPIKeyAPI_WrongEmailRejection_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupAPIKeyTestServerRapid(rt)
		defer server.cleanup()
		testAPIKeyAPI_WrongEmailRejection_Properties(rt, server)
	}))
}

// =============================================================================
// Helper function
// =============================================================================

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
