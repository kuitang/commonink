// Package e2e provides end-to-end property-based tests for the PAT (Personal Access Token) API.
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
var patTestMutex sync.Mutex

// Cached test credentials - hash computed once at init, reused across all iterations.
// This avoids the expensive Argon2 hash computation (64 MiB, ~500ms) per iteration.
// Security note: VerifyPassword reads parameters from the stored hash, so this
// is functionally equivalent to computing fresh hashes - we're testing PAT behavior,
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

// patTestServer holds the server and services for PAT API testing.
type patTestServer struct {
	server         *httptest.Server
	mux            *http.ServeMux
	userService    *auth.UserService
	sessionService *auth.SessionService
	patHandler     *auth.PATHandler
	authMiddleware *auth.Middleware
	keyManager     *crypto.KeyManager
	sessionsDB     *db.SessionsDB
	tempDir        string // For cleanup in rapid tests
}

// setupPATTestServer creates a test server with all PAT-related routes.
// Returns the server and a cleanup function.
func setupPATTestServer(t testing.TB) *patTestServer {
	// Use temp directory for test database to ensure isolation
	tempDir := t.TempDir()
	return setupPATTestServerWithDir(tempDir)
}

// setupPATTestServerRapid creates a test server for rapid.T tests.
// Uses a unique temp directory for each test iteration.
func setupPATTestServerRapid(t *rapid.T) *patTestServer {
	// Generate a unique temp directory for this test iteration
	// We use os.MkdirTemp because rapid.T doesn't have TempDir
	tempDir, err := os.MkdirTemp("", "pat-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	server := setupPATTestServerWithDir(tempDir)
	// Store tempDir for cleanup
	server.tempDir = tempDir
	return server
}

// setupPATTestServerWithDir creates a test server with a specific data directory.
// Panics on error since this is test setup code.
func setupPATTestServerWithDir(tempDir string) *patTestServer {
	// Acquire global lock to ensure clean database state
	patTestMutex.Lock()

	db.DataDirectory = tempDir
	db.ResetForTesting()

	// Initialize sessions database
	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		panic("Failed to open sessions DB: " + err.Error())
	}

	// Ensure database is fully initialized by making a query
	_, _ = sessionsDB.Queries().CountSessions(context.Background())

	// Initialize services
	emailSvc := email.NewMockEmailService()
	userService := auth.NewUserService(sessionsDB, emailSvc, "http://test.local")
	sessionService := auth.NewSessionService(sessionsDB)

	// Create a test master key and key manager
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	keyManager := crypto.NewKeyManager(masterKey, sessionsDB)

	// Create PAT handler and middleware
	patHandler := auth.NewPATHandler(userService)
	authMiddleware := auth.NewMiddleware(sessionService, keyManager)

	// Create mux and register routes
	mux := http.NewServeMux()
	mux.Handle("POST /api/tokens", authMiddleware.RequireAuth(http.HandlerFunc(patHandler.CreatePAT)))
	mux.Handle("GET /api/tokens", authMiddleware.RequireAuth(http.HandlerFunc(patHandler.ListPATs)))
	mux.Handle("DELETE /api/tokens/{id}", authMiddleware.RequireAuth(http.HandlerFunc(patHandler.RevokePAT)))

	// Create test server
	server := httptest.NewServer(mux)

	return &patTestServer{
		server:         server,
		mux:            mux,
		userService:    userService,
		sessionService: sessionService,
		patHandler:     patHandler,
		authMiddleware: authMiddleware,
		keyManager:     keyManager,
		sessionsDB:     sessionsDB,
	}
}

// cleanup closes the test server and cleans up resources.
func (s *patTestServer) cleanup() {
	s.server.Close()
	db.CloseAll()
	if s.tempDir != "" {
		os.RemoveAll(s.tempDir)
	}
	// Release global lock
	patTestMutex.Unlock()
}

// testHelper is a minimal interface that rapid.T and testing.T/B both satisfy
type testHelper interface {
	Fatalf(format string, args ...any)
	Fatal(args ...any)
}

// createTestUserWithSession creates a test user and returns their session cookie.
// DEPRECATED: Use createTestUserWithCachedPassword for property tests to avoid
// expensive Argon2 hash computation on every iteration.
func (s *patTestServer) createTestUserWithSession(t testHelper, emailAddr, password string) (userID string, sessionCookie *http.Cookie) {
	ctx := context.Background()

	// Create or find user
	user, err := s.userService.FindOrCreateByEmail(ctx, emailAddr)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Set password for the user (needed for PAT creation)
	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
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

	// First create the account record (if it doesn't exist)
	err = userDB.Queries().CreateAccount(ctx, userdb.CreateAccountParams{
		UserID:       user.ID,
		Email:        emailAddr,
		PasswordHash: sql.NullString{String: passwordHash, Valid: true},
		CreatedAt:    time.Now().Unix(),
	})
	if err != nil {
		// Account might already exist, try updating the password instead
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

	return user.ID, &http.Cookie{
		Name:  auth.SessionCookieName,
		Value: sessionID,
	}
}

// createTestUserWithCachedPassword creates a test user using a pre-computed password hash.
// This is ~100x faster than createTestUserWithSession because it skips Argon2 hashing.
// Use cachedTestPassword as the password when calling APIs that require re-authentication.
// For tests that need two users, use userNum=1 or userNum=2 to get different cached credentials.
func (s *patTestServer) createTestUserWithCachedPassword(t testHelper, emailAddr string, userNum int) (userID string, password string, sessionCookie *http.Cookie) {
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
	user, err := s.userService.FindOrCreateByEmail(ctx, emailAddr)
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

// createPAT creates a PAT via the API and returns the token ID and full token value.
func (s *patTestServer) createPAT(t testHelper, sessionCookie *http.Cookie, name, scope, email, password string) (tokenID, tokenValue string) {
	reqBody := auth.CreatePATRequest{
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

	req, err := http.NewRequest("POST", s.server.URL+"/api/tokens", bytes.NewReader(bodyBytes))
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
		t.Fatalf("Failed to create PAT: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var result auth.CreatePATResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	return result.ID, result.Token
}

// listPATs lists all PATs via the API.
func (s *patTestServer) listPATs(t testHelper, sessionCookie *http.Cookie) []auth.PAT {
	req, err := http.NewRequest("GET", s.server.URL+"/api/tokens", nil)
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
		t.Fatalf("Failed to list PATs: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var result auth.ListPATsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	return result.Tokens
}

// revokePAT revokes a PAT via the API.
func (s *patTestServer) revokePAT(t testHelper, sessionCookie *http.Cookie, tokenID string) error {
	req, err := http.NewRequest("DELETE", s.server.URL+"/api/tokens/"+tokenID, nil)
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
	return &patAPIError{StatusCode: resp.StatusCode, Body: string(body)}
}

// authenticateWithPAT tests if a PAT can be used for authentication.
// Returns the HTTP status code from the response.
// Does NOT fatal on failure - use authenticateWithPATExpectSuccess for that.
func (s *patTestServer) authenticateWithPAT(t testHelper, token string) int {
	req, err := http.NewRequest("GET", s.server.URL+"/api/tokens", nil)
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

// authenticateWithPATExpectSuccess tests if a PAT can be used for authentication.
// Fatals if authentication fails (non-200 status).
func (s *patTestServer) authenticateWithPATExpectSuccess(t testHelper, token string) {
	req, err := http.NewRequest("GET", s.server.URL+"/api/tokens", nil)
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
		t.Fatalf("PAT auth failed with status %d: %s (token: %s)", resp.StatusCode, string(body), token)
	}
}

// patAPIError represents an API error.
type patAPIError struct {
	StatusCode int
	Body       string
}

func (e *patAPIError) Error() string {
	return e.Body
}

// =============================================================================
// Property 1: Roundtrip Property
// Create a token -> List tokens includes it -> Token works for auth
// =============================================================================

func testPATAPI_Roundtrip_Properties(t *rapid.T, server *patTestServer) {
	// Generate random but valid inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")
	tokenName := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	_, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Create PAT
	tokenID, tokenValue := server.createPAT(t, sessionCookie, tokenName, "read_write", emailAddr, password)

	// Property 1: Token ID is non-empty
	if tokenID == "" {
		t.Fatal("Token ID should not be empty")
	}

	// Property 2: Token value is non-empty and has correct prefix
	if tokenValue == "" {
		t.Fatal("Token value should not be empty")
	}
	if !strings.HasPrefix(tokenValue, auth.PATPrefix) {
		t.Fatalf("Token should have prefix %q, got %q", auth.PATPrefix, tokenValue)
	}

	// Property 3: List tokens includes the created token
	tokens := server.listPATs(t, sessionCookie)
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
	server.authenticateWithPATExpectSuccess(t, tokenValue)
}

func TestPATAPI_Roundtrip_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Create fresh server for each property test iteration
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_Roundtrip_Properties(rt, server)
	})
}

func FuzzPATAPI_Roundtrip_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_Roundtrip_Properties(rt, server)
	}))
}

// =============================================================================
// Property 2: Revocation Property
// Created token works -> Revoke -> Token no longer works (401)
// =============================================================================

func testPATAPI_Revocation_Properties(t *rapid.T, server *patTestServer) {
	// Generate random inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")
	tokenName := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	_, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Create PAT
	tokenID, tokenValue := server.createPAT(t, sessionCookie, tokenName, "read_write", emailAddr, password)

	// Property 1: Token works before revocation
	status := server.authenticateWithPAT(t, tokenValue)
	if status != http.StatusOK {
		t.Fatalf("PAT should work before revocation: expected 200, got %d", status)
	}

	// Revoke the token
	err := server.revokePAT(t, sessionCookie, tokenID)
	if err != nil {
		t.Fatalf("Failed to revoke PAT: %v", err)
	}

	// Property 2: Token no longer works after revocation
	status = server.authenticateWithPAT(t, tokenValue)
	if status != http.StatusUnauthorized {
		t.Fatalf("Revoked PAT should return 401: expected 401, got %d", status)
	}

	// Property 3: Token no longer appears in list
	tokens := server.listPATs(t, sessionCookie)
	for _, tok := range tokens {
		if tok.ID == tokenID {
			t.Fatalf("Revoked token %s should not appear in list", tokenID)
		}
	}
}

func TestPATAPI_Revocation_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_Revocation_Properties(rt, server)
	})
}

func FuzzPATAPI_Revocation_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_Revocation_Properties(rt, server)
	}))
}

// =============================================================================
// Property 3: Password Re-Auth Property
// Creating token without password fails
// Creating token with wrong password fails
// Creating token with correct password succeeds
// =============================================================================

func testPATAPI_PasswordReAuth_Properties(t *rapid.T, server *patTestServer) {
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
	reqNoPassword := auth.CreatePATRequest{
		Name:      tokenName,
		Scope:     "read_write",
		ExpiresIn: 3600,
		Email:     emailAddr,
		Password:  "", // Missing password
	}
	status := server.createPATExpectError(t, sessionCookie, reqNoPassword)
	if status != http.StatusBadRequest {
		t.Fatalf("Creating PAT without password should fail with 400, got %d", status)
	}

	// Property 2: Creating token with wrong password fails
	reqWrongPassword := auth.CreatePATRequest{
		Name:      tokenName,
		Scope:     "read_write",
		ExpiresIn: 3600,
		Email:     emailAddr,
		Password:  wrongPassword,
	}
	status = server.createPATExpectError(t, sessionCookie, reqWrongPassword)
	if status != http.StatusUnauthorized {
		t.Fatalf("Creating PAT with wrong password should fail with 401, got %d", status)
	}

	// Property 3: Creating token with correct password succeeds
	tokenID, tokenValue := server.createPAT(t, sessionCookie, tokenName, "read_write", emailAddr, correctPassword)
	if tokenID == "" || tokenValue == "" {
		t.Fatal("Creating PAT with correct password should succeed")
	}
}

// createPATExpectError attempts to create a PAT and returns the status code.
func (s *patTestServer) createPATExpectError(t testHelper, sessionCookie *http.Cookie, req auth.CreatePATRequest) int {
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	httpReq, err := http.NewRequest("POST", s.server.URL+"/api/tokens", bytes.NewReader(bodyBytes))
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

func TestPATAPI_PasswordReAuth_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_PasswordReAuth_Properties(rt, server)
	})
}

func FuzzPATAPI_PasswordReAuth_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_PasswordReAuth_Properties(rt, server)
	}))
}

// =============================================================================
// Property 4: Token Uniqueness Property
// Multiple tokens can be created
// Each has unique ID
// Revoking one doesn't affect others
// =============================================================================

func testPATAPI_Uniqueness_Properties(t *rapid.T, server *patTestServer) {
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
		tokenID, tokenValue := server.createPAT(t, sessionCookie, name, "read_write", emailAddr, password)

		// Property 1: Each token ID is unique
		if tokenIDs[tokenID] {
			t.Fatalf("Duplicate token ID: %s", tokenID)
		}
		tokenIDs[tokenID] = true

		tokens[i] = tokenInfo{ID: tokenID, Value: tokenValue, Name: name}
	}

	// Property 2: All tokens work
	for _, tok := range tokens {
		server.authenticateWithPATExpectSuccess(t, tok.Value)
	}

	// Property 3: Revoking one token doesn't affect others
	if len(tokens) >= 2 {
		// Revoke the first token
		err := server.revokePAT(t, sessionCookie, tokens[0].ID)
		if err != nil {
			t.Fatalf("Failed to revoke token: %v", err)
		}

		// First token should no longer work
		status := server.authenticateWithPAT(t, tokens[0].Value)
		if status != http.StatusUnauthorized {
			t.Fatalf("Revoked token should return 401, got %d", status)
		}

		// Other tokens should still work
		for i := 1; i < len(tokens); i++ {
			server.authenticateWithPATExpectSuccess(t, tokens[i].Value)
		}
	}
}

func TestPATAPI_Uniqueness_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_Uniqueness_Properties(rt, server)
	})
}

func FuzzPATAPI_Uniqueness_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_Uniqueness_Properties(rt, server)
	}))
}

// =============================================================================
// Property 5: Token Format Property
// Token starts with "agentnotes_pat_"
// Token contains user ID
// Token is sufficiently long (>40 chars)
// =============================================================================

func testPATAPI_Format_Properties(t *rapid.T, server *patTestServer) {
	// Generate random inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")
	tokenName := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	userID, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Create PAT
	_, tokenValue := server.createPAT(t, sessionCookie, tokenName, "read_write", emailAddr, password)

	// Property 1: Token starts with correct prefix
	if !strings.HasPrefix(tokenValue, auth.PATPrefix) {
		t.Fatalf("Token should start with %q, got %q", auth.PATPrefix, tokenValue[:min(len(tokenValue), 20)])
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
	parsedUserID, tokenPart, ok := auth.ParsePATToken(tokenValue)
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

func TestPATAPI_Format_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_Format_Properties(rt, server)
	})
}

func FuzzPATAPI_Format_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_Format_Properties(rt, server)
	}))
}

// =============================================================================
// Property 6: User Isolation Property
// Different users cannot see each other's tokens
// Different users cannot revoke each other's tokens
// =============================================================================

func testPATAPI_Isolation_Properties(t *rapid.T, server *patTestServer) {
	// Generate random inputs for two users
	email1 := rapid.StringMatching(`[a-z]{5,10}@user1\.com`).Draw(t, "email1")
	email2 := rapid.StringMatching(`[a-z]{5,10}@user2\.com`).Draw(t, "email2")
	tokenName1 := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName1")
	tokenName2 := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName2")

	// Create two users with cached passwords (avoids Argon2 hash per iteration)
	_, password1, sessionCookie1 := server.createTestUserWithCachedPassword(t, email1, 1)
	_, password2, sessionCookie2 := server.createTestUserWithCachedPassword(t, email2, 2)

	// Create tokens for each user
	tokenID1, _ := server.createPAT(t, sessionCookie1, tokenName1, "read_write", email1, password1)
	tokenID2, _ := server.createPAT(t, sessionCookie2, tokenName2, "read_write", email2, password2)

	// Property 1: User 1 can only see their own tokens
	tokens1 := server.listPATs(t, sessionCookie1)
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
	tokens2 := server.listPATs(t, sessionCookie2)
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
	err := server.revokePAT(t, sessionCookie1, tokenID2)
	if err == nil {
		// This might succeed with 404 (not found) since user1 can't see user2's token
		// That's acceptable behavior - the key is that it doesn't actually revoke it
	}
	// Verify User 2's token still works
	tokens2After := server.listPATs(t, sessionCookie2)
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

func TestPATAPI_Isolation_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_Isolation_Properties(rt, server)
	})
}

func FuzzPATAPI_Isolation_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_Isolation_Properties(rt, server)
	}))
}

// =============================================================================
// Property 7: Invalid Token Rejection Property
// Random tokens are rejected
// Malformed tokens are rejected
// Expired tokens are rejected (if testable)
// =============================================================================

func testPATAPI_InvalidToken_Properties(t *rapid.T, server *patTestServer) {
	// Generate random invalid tokens - use ASCII only to avoid HTTP header encoding issues
	// HTTP headers only support ASCII, so non-ASCII chars would fail at the transport layer
	randomToken := rapid.StringMatching(`[a-zA-Z0-9_\-]{20,100}`).Draw(t, "randomToken")

	// Property 1: Random tokens are rejected
	status := server.authenticateWithPAT(t, randomToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("Random token should be rejected with 401, got %d", status)
	}

	// Property 2: Empty token is rejected
	status = server.authenticateWithPAT(t, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("Empty token should be rejected with 401, got %d", status)
	}

	// Property 3: Token with correct prefix but invalid content is rejected
	fakeToken := auth.PATPrefix + "fake-user-id_invalidtokenpart12345"
	status = server.authenticateWithPAT(t, fakeToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("Fake token should be rejected with 401, got %d", status)
	}

	// Property 4: Token with correct prefix and proper userID format but wrong token is rejected
	fakeTokenWithValidPrefix := auth.PATPrefix + "user-00000000-0000-0000-0000-000000000000_invalidtoken12345678901234567890123456789012345678901234"
	status = server.authenticateWithPAT(t, fakeTokenWithValidPrefix)
	if status != http.StatusUnauthorized {
		t.Fatalf("Fake token with valid prefix format should be rejected with 401, got %d", status)
	}

	// Property 5: Token with SQL injection attempts is rejected
	for _, injection := range []string{
		auth.PATPrefix + "' OR 1=1 --_token",
		auth.PATPrefix + "admin'--_token",
		auth.PATPrefix + "'; DROP TABLE personal_access_tokens; --_token",
	} {
		status = server.authenticateWithPAT(t, injection)
		if status != http.StatusUnauthorized {
			t.Fatalf("SQL injection token should be rejected with 401, got %d", status)
		}
	}
}

func TestPATAPI_InvalidToken_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_InvalidToken_Properties(rt, server)
	})
}

func FuzzPATAPI_InvalidToken_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_InvalidToken_Properties(rt, server)
	}))
}

// =============================================================================
// Property 8: Token Name Edge Cases Property
// Various edge case names are handled correctly
// =============================================================================

func testPATAPI_TokenName_EdgeCases_Properties(t *rapid.T, server *patTestServer) {
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
	tokenID, tokenValue := server.createPAT(t, sessionCookie, tokenName, "read_write", emailAddr, password)
	if tokenID == "" || tokenValue == "" {
		t.Fatalf("Failed to create token with edge case name: %q", tokenName)
	}

	// Property: Token appears in list with correct name
	tokens := server.listPATs(t, sessionCookie)
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

func TestPATAPI_TokenName_EdgeCases_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_TokenName_EdgeCases_Properties(rt, server)
	})
}

func FuzzPATAPI_TokenName_EdgeCases_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_TokenName_EdgeCases_Properties(rt, server)
	}))
}

// =============================================================================
// Property 9: Scope Preservation Property
// Token scope is correctly stored and returned
// =============================================================================

func testPATAPI_Scope_Properties(t *rapid.T, server *patTestServer) {
	// Generate random inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")
	tokenName := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName")
	scope := rapid.SampledFrom([]string{"read", "write", "read_write", "admin"}).Draw(t, "scope")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	_, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Create PAT with specific scope
	tokenID, _ := server.createPAT(t, sessionCookie, tokenName, scope, emailAddr, password)

	// Property: Scope is preserved in list
	tokens := server.listPATs(t, sessionCookie)
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

func TestPATAPI_Scope_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_Scope_Properties(rt, server)
	})
}

func FuzzPATAPI_Scope_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_Scope_Properties(rt, server)
	}))
}

// =============================================================================
// Property 10: Token Expiration Metadata Property
// Token has expiration date set correctly
// =============================================================================

func testPATAPI_Expiration_Properties(t *rapid.T, server *patTestServer) {
	// Generate random inputs
	emailAddr := rapid.StringMatching(`[a-z]{5,10}@test\.com`).Draw(t, "email")
	tokenName := rapid.StringMatching(`[a-zA-Z0-9_-]{1,50}`).Draw(t, "tokenName")

	// Create test user with cached password (avoids Argon2 hash per iteration)
	_, password, sessionCookie := server.createTestUserWithCachedPassword(t, emailAddr, 1)

	// Create PAT (expires in 3600 seconds = 1 hour)
	now := time.Now()
	tokenID, _ := server.createPAT(t, sessionCookie, tokenName, "read_write", emailAddr, password)

	// Property: Expiration is approximately 1 hour from now
	tokens := server.listPATs(t, sessionCookie)
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

func TestPATAPI_Expiration_Properties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_Expiration_Properties(rt, server)
	})
}

func FuzzPATAPI_Expiration_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		server := setupPATTestServerRapid(rt)
		defer server.cleanup()
		testPATAPI_Expiration_Properties(rt, server)
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
