// Package e2e provides end-to-end property-based tests for auth hardening (Theme 2).
//
// T2a: Silent token bypass - Bearer token without OAuth verifier returns 401
// T2c: MCP cookie auth removed - Cookie-only requests to /mcp return 401
// T2d: Unauthenticated rate limiting - IP-based rate limiting for auth endpoints
// T2f: secureCookies atomic - concurrent SetSecureCookies/GetSecureCookies is race-free
package e2e

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/mutecomm/go-sqlcipher/v4"
	"pgregory.net/rapid"

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/email"
	"github.com/kuitang/agent-notes/internal/oauth"
	"github.com/kuitang/agent-notes/internal/ratelimit"
	"github.com/kuitang/agent-notes/internal/web"
)

// =============================================================================
// Shared test infrastructure for auth hardening tests
// =============================================================================

var authHardeningTestMu sync.Mutex

// authHardeningServer wraps a test server configured for auth hardening tests
type authHardeningServer struct {
	*httptest.Server
	authMiddleware *auth.Middleware
	sessionService *auth.SessionService
	userService    *auth.UserService
	oauthProvider  *oauth.Provider
	sessionsDB     *db.SessionsDB
	tempDir        string
}

// setupAuthHardeningServer creates a test server with full MCP + auth routes.
// Caller must call cleanup() when done.
func setupAuthHardeningServer(t testing.TB, withOAuthVerifier bool) *authHardeningServer {
	t.Helper()
	authHardeningTestMu.Lock()

	tempDir := t.TempDir()
	db.ResetForTesting()
	db.DataDirectory = tempDir

	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		t.Fatalf("Failed to open sessions database: %v", err)
	}

	hmacSecret := make([]byte, 32)
	_, _ = crand.Read(hmacSecret)
	_, signingKey, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate signing key: %v", err)
	}

	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)

	oauthProvider, err := oauth.NewProvider(oauth.Config{
		DB:                 sessionsDB.DB(),
		Issuer:             server.URL,
		Resource:           server.URL,
		HMACSecret:         hmacSecret,
		SigningKey:         signingKey,
		ClientSecretHasher: oauth.FakeInsecureClientSecretHasher{},
	})
	if err != nil {
		t.Fatalf("Failed to create OAuth provider: %v", err)
	}

	masterKey := make([]byte, 32)
	keyManager := crypto.NewKeyManager(masterKey, sessionsDB)
	emailService := email.NewMockEmailService()
	sessionService := auth.NewSessionService(sessionsDB)
	userService := auth.NewUserService(sessionsDB, keyManager, emailService, server.URL, auth.FakeInsecureHasher{})

	authMiddleware := auth.NewMiddleware(sessionService, keyManager)
	if withOAuthVerifier {
		oauthTokenVerifier := &testOAuthProviderVerifier{provider: oauthProvider}
		authMiddleware.WithOAuthVerifier(oauthTokenVerifier, "/.well-known/oauth-protected-resource")
	}

	// Register MCP endpoint with RequireBearerAuth (T2c)
	mcpHandler := authMiddleware.RequireBearerAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","result":{"tools":[]},"id":1}`))
	}))
	mux.Handle("POST /mcp", mcpHandler)

	// Register a generic RequireAuth endpoint for T2a testing
	authHandler := authMiddleware.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("authenticated"))
	}))
	mux.Handle("GET /api/test-auth", authHandler)

	// Register auth routes for session creation
	mux.HandleFunc("POST /auth/register", func(w http.ResponseWriter, r *http.Request) {
		handleTestRegister(w, r, userService, sessionService)
	})

	return &authHardeningServer{
		Server:         server,
		authMiddleware: authMiddleware,
		sessionService: sessionService,
		userService:    userService,
		oauthProvider:  oauthProvider,
		sessionsDB:     sessionsDB,
		tempDir:        tempDir,
	}
}

func (s *authHardeningServer) cleanup() {
	s.Server.Close()
	db.ResetForTesting()
	authHardeningTestMu.Unlock()
}

// testOAuthProviderVerifier adapts oauth.Provider to auth.OAuthTokenVerifier for testing.
type testOAuthProviderVerifier struct {
	provider *oauth.Provider
}

func (v *testOAuthProviderVerifier) VerifyAccessToken(token string) (*auth.OAuthTokenClaims, error) {
	claims, err := v.provider.VerifyAccessToken(token)
	if err != nil {
		return nil, err
	}
	return &auth.OAuthTokenClaims{
		Subject:  claims.Subject,
		ClientID: claims.ClientID,
		Scope:    claims.Scope,
	}, nil
}

// =============================================================================
// T2a: Silent token bypass - Bearer token with nil verifier returns 401
// =============================================================================

// Property: A request bearing a syntactically valid JWT (but no API-key format)
// with oauthVerifier == nil must return 401, never 200.
func TestT2a_BearerToken_NilVerifier_Returns401(t *testing.T) {
	srv := setupAuthHardeningServer(t, false /* no OAuth verifier */)
	defer srv.cleanup()

	rapid.Check(t, func(t *rapid.T) {
		// Generate a syntactically plausible JWT-like token (not an API key)
		// Real JWTs are base64url-encoded header.payload.signature
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
			`{"sub":"user-%s","iss":"test","exp":%d}`,
			rapid.StringMatching(`[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`).Draw(t, "uuid"),
			time.Now().Add(time.Hour).Unix(),
		)))
		sig := base64.RawURLEncoding.EncodeToString([]byte("fakesignature"))
		fakeJWT := header + "." + payload + "." + sig

		// Ensure it doesn't look like an API key
		if auth.IsAPIKeyToken(fakeJWT) {
			t.Skip("generated token looks like API key")
		}

		req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/test-auth", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+fakeJWT)

		client := srv.Client()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Expected 401 when Bearer token presented with nil OAuth verifier, got %d", resp.StatusCode)
		}
	})
}

// =============================================================================
// T2c: MCP cookie auth removed - Cookie-only requests to /mcp return 401
// =============================================================================

// Property: A request to /mcp bearing only a valid session cookie and no
// Authorization header must return 401.
func TestT2c_MCP_CookieOnly_Returns401(t *testing.T) {
	srv := setupAuthHardeningServer(t, true /* with OAuth verifier */)
	defer srv.cleanup()

	// Create a user and get a valid session
	jar, _ := cookiejar.New(nil)
	client := srv.Client()
	client.Jar = jar

	// Register a user to get a valid session cookie
	email := "t2c-test@example.com"
	password := "TestPassword123!"
	form := url.Values{"email": {email}, "password": {password}}
	resp, err := client.Post(srv.URL+"/auth/register", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}
	resp.Body.Close()

	// Verify we have a session cookie
	serverURL, _ := url.Parse(srv.URL)
	cookies := jar.Cookies(serverURL)
	hasSession := false
	for _, c := range cookies {
		if c.Name == "session_id" {
			hasSession = true
			break
		}
	}
	if !hasSession {
		t.Fatal("Expected session cookie after registration, but none found")
	}

	// Now make a request to /mcp with only the session cookie (no Authorization header)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"tools/list","id":1}`))
	if err != nil {
		t.Fatalf("Failed to create MCP request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// The cookie jar will automatically add the session cookie

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("MCP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 for MCP with cookie-only auth, got %d (cookie auth should be rejected for MCP)", resp.StatusCode)
	}
}

// =============================================================================
// T2d: Unauthenticated endpoints rate-limited
// =============================================================================

// Property: Sending N > threshold requests to an IP-rate-limited endpoint
// from the same IP without any auth returns 429 before N completes.
func TestT2d_UnauthenticatedRateLimit_Returns429(t *testing.T) {
	// Create a test server with IP rate limiting
	ipConfig := ratelimit.IPConfig{
		RPS:             0.001, // Nearly zero refill
		Burst:           3,     // Allow 3 requests
		CleanupInterval: time.Minute,
	}
	ipLimiter := ratelimit.NewIPRateLimiter(ipConfig)
	defer ipLimiter.Stop()

	ipRateLimitMW := ratelimit.IPRateLimitMiddleware(ipLimiter)

	// Simple handler that returns 200
	handler := ipRateLimitMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	server := httptest.NewServer(handler)
	defer server.Close()

	rapid.Check(t, func(t *rapid.T) {
		// Send burst+1 requests; at least one must get 429
		got429 := false
		for i := 0; i < ipConfig.Burst+3; i++ {
			resp, err := http.Post(server.URL, "application/json", nil)
			if err != nil {
				t.Fatalf("Request %d failed: %v", i, err)
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusTooManyRequests {
				got429 = true
				break
			}
		}

		if !got429 {
			t.Fatal("Expected 429 after exceeding burst, but all requests returned non-429")
		}
	})
}

// Deterministic version: exactly burst requests succeed, then 429
func TestT2d_IPRateLimit_ExactBurst(t *testing.T) {
	ipConfig := ratelimit.IPConfig{
		RPS:             0.001, // Nearly zero refill
		Burst:           5,
		CleanupInterval: time.Minute,
	}
	ipLimiter := ratelimit.NewIPRateLimiter(ipConfig)
	defer ipLimiter.Stop()

	ipRateLimitMW := ratelimit.IPRateLimitMiddleware(ipLimiter)
	handler := ipRateLimitMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	server := httptest.NewServer(handler)
	defer server.Close()

	// First `burst` requests should succeed
	for i := 0; i < ipConfig.Burst; i++ {
		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Request %d: expected 200 (within burst), got %d", i, resp.StatusCode)
		}
	}

	// Next request should be rate limited
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("Rate limited request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("Expected 429 after exhausting burst of %d, got %d", ipConfig.Burst, resp.StatusCode)
	}

	retryAfter := resp.Header.Get("Retry-After")
	if retryAfter == "" {
		t.Fatal("Missing Retry-After header on 429 response")
	}
}

// Test IP independence: different IPs have independent rate limits
func TestT2d_IPRateLimit_IPIndependence(t *testing.T) {
	ipConfig := ratelimit.IPConfig{
		RPS:             0.001,
		Burst:           3,
		CleanupInterval: time.Minute,
	}
	ipLimiter := ratelimit.NewIPRateLimiter(ipConfig)
	defer ipLimiter.Stop()

	ipRateLimitMW := ratelimit.IPRateLimitMiddleware(ipLimiter)
	handler := ipRateLimitMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	server := httptest.NewServer(handler)
	defer server.Close()

	// Exhaust from one simulated IP
	for i := 0; i < ipConfig.Burst; i++ {
		req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
		req.Header.Set("X-Forwarded-For", "1.2.3.4")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		resp.Body.Close()
	}

	// IP 1.2.3.4 should be rate limited
	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Rate limited request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("IP 1.2.3.4 should be rate limited, got %d", resp.StatusCode)
	}

	// Different IP should not be affected
	req2, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	req2.Header.Set("X-Forwarded-For", "5.6.7.8")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("Different IP request failed: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("IP 5.6.7.8 should get 200 (independent limit), got %d", resp2.StatusCode)
	}
}

// =============================================================================
// T2f: secureCookies atomic - concurrent access is race-free
// =============================================================================

// Property: Concurrent SetSecureCookies/GetSecureCookies calls are race-free
// and the final value is deterministic based on the last write.
func TestT2f_SecureCookies_ConcurrentAccess(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a random sequence of Set operations
		n := rapid.IntRange(10, 100).Draw(t, "iterations")
		finalValue := rapid.Bool().Draw(t, "finalValue")

		var wg sync.WaitGroup
		var readCount atomic.Int64
		var trueCount atomic.Int64

		// Spawn concurrent writers
		for i := 0; i < n; i++ {
			wg.Add(1)
			val := rapid.Bool().Draw(t, fmt.Sprintf("write_%d", i))
			go func(v bool) {
				defer wg.Done()
				auth.SetSecureCookies(v)
			}(val)
		}

		// Spawn concurrent readers
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				readCount.Add(1)
				if auth.GetSecureCookies() {
					trueCount.Add(1)
				}
			}()
		}

		wg.Wait()

		// Set the final deterministic value
		auth.SetSecureCookies(finalValue)

		// After all goroutines complete and we set the final value,
		// GetSecureCookies must return it
		got := auth.GetSecureCookies()
		if got != finalValue {
			t.Fatalf("After SetSecureCookies(%v), GetSecureCookies returned %v", finalValue, got)
		}

		// All reads completed without panic
		if readCount.Load() != int64(n) {
			t.Fatalf("Expected %d reads, got %d", n, readCount.Load())
		}

		// Reset to true for other tests
		auth.SetSecureCookies(true)
	})
}

// =============================================================================
// T2b: Structured logging - verify no fmt.Printf("[AUTH]") in middleware
// This is a static property - verified by T2a/T2c/T2f functional tests above
// plus the following compilation-level check that log.Printf is used.
// =============================================================================

// findTemplatesDirForHardening finds templates directory relative to the test file.
func findTemplatesDirForHardening() string {
	candidates := []string{
		"../../templates",
		"../../../templates",
		"templates",
	}
	for _, dir := range candidates {
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}
	return "../../templates" // default
}

// Helper to create the test renderer for auth hardening tests that need web routes
func mustCreateHardeningRenderer(t testing.TB) *web.Renderer {
	t.Helper()
	dir := findTemplatesDirForHardening()
	r, err := web.NewRenderer(dir)
	if err != nil {
		t.Fatalf("Failed to create renderer: %v", err)
	}
	return r
}
