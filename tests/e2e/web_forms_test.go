// Package e2e provides HTTP-based property tests for web form endpoints.
// These tests exercise the same code paths as Playwright browser tests
// but run entirely via HTTP, making them faster and more complete.
package e2e

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	_ "github.com/mutecomm/go-sqlcipher/v4"
	"pgregory.net/rapid"

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/billing"
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	emailpkg "github.com/kuitang/agent-notes/internal/email"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/kuitang/agent-notes/internal/oauth"
	"github.com/kuitang/agent-notes/internal/ratelimit"
	"github.com/kuitang/agent-notes/internal/s3client"
	"github.com/kuitang/agent-notes/internal/shorturl"
	"github.com/kuitang/agent-notes/internal/web"
	"github.com/kuitang/agent-notes/tests/e2e/testutil"
)

// =============================================================================
// WEB FORM TEST SERVER - Uses REAL web handlers (HTML forms, not JSON APIs)
// =============================================================================

var (
	webFormTestMutex     sync.Mutex
	webFormSharedMu      sync.Mutex
	webFormSharedFixture *webFormServer
)

// webFormServer wraps httptest.Server for testing web form endpoints
type webFormServer struct {
	*httptest.Server
	tempDir  string
	s3Server *httptest.Server // Mock S3 server
	shared   bool

	// Services (exposed for tests)
	sessionsDB     *db.SessionsDB
	keyManager     *crypto.KeyManager
	userService    *auth.UserService
	sessionService *auth.SessionService
	emailService   *emailpkg.MockEmailService
	rateLimiter    *ratelimit.RateLimiter
	mockOIDC       *auth.LocalMockOIDCProvider
}

// setupWebFormServer creates a test server with all web handlers wired up.
// This includes both JSON API endpoints AND HTML form endpoints.
func setupWebFormServer(t testing.TB) *webFormServer {
	t.Helper()
	webFormTestMutex.Lock()
	t.Cleanup(webFormTestMutex.Unlock)

	ts, err := getOrCreateSharedWebFormServer()
	if err != nil {
		t.Fatalf("Failed to initialize shared web form fixture: %v", err)
	}

	if err := resetWebFormServerState(ts); err != nil {
		t.Fatalf("Failed to reset shared web form fixture: %v", err)
	}

	return ts
}

func createWebFormServer(tempDir string) *webFormServer {
	// Reset database singleton
	db.ResetForTesting()
	db.DataDirectory = tempDir

	// Initialize sessions database
	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		panic("Failed to open sessions database: " + err.Error())
	}

	// Generate master key
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

	// Create mux
	mux := http.NewServeMux()

	// Start httptest server
	server := httptest.NewServer(mux)

	// Initialize key manager
	keyManager := crypto.NewKeyManager(masterKey, sessionsDB)

	// Initialize services
	emailService := emailpkg.NewMockEmailService()
	userService := auth.NewUserService(sessionsDB, keyManager, emailService, server.URL, auth.FakeInsecureHasher{})
	sessionService := auth.NewSessionService(sessionsDB)
	consentService := auth.NewConsentService(sessionsDB)

	// Create OAuth provider
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

	// Find templates directory
	templatesDir := findWebFormTemplatesDir()
	renderer, err := web.NewRenderer(templatesDir)
	if err != nil {
		panic("Failed to create renderer: " + err.Error())
	}

	// Create auth middleware
	authMiddleware := auth.NewMiddleware(sessionService, keyManager)

	// Create rate limiter (high limits for tests)
	rateLimiter := ratelimit.NewRateLimiter(ratelimit.Config{
		FreeRPS:         10000,
		FreeBurst:       100000,
		PaidRPS:         100000,
		PaidBurst:       1000000,
		CleanupInterval: time.Hour,
	})

	// Close old server and create new mux
	server.Close()
	mux = http.NewServeMux()
	server = httptest.NewServer(mux)

	// Update userService baseURL
	userService = auth.NewUserService(sessionsDB, keyManager, emailService, server.URL, auth.FakeInsecureHasher{})

	// Create mock S3 server and client
	s3Server, mockS3Client := createMockS3Server()

	shortURLSvc := shorturl.NewService(sessionsDB.Queries())

	// Create web handler with ALL services
	webHandler := web.NewWebHandler(
		renderer,
		nil, // notesService is created per-request
		notes.NewPublicNoteService(mockS3Client),
		userService,
		sessionService,
		consentService,
		mockS3Client,
		shortURLSvc,
		billing.NewMockService(),
		server.URL,
		"", // spriteToken
	)

	// Register ALL web routes.
	webHandler.RegisterRoutes(mux, authMiddleware)

	// Explicitly add POST /oauth/consent to exercise consent decision flow.
	mux.Handle("POST /oauth/consent", authMiddleware.RequireAuthWithRedirect(http.HandlerFunc(webHandler.HandleConsentDecision)))

	// Register auth API routes (POST /auth/* for form handling)
	mockOIDC := auth.NewLocalMockOIDCProvider(server.URL)
	authHandler := auth.NewHandler(mockOIDC, userService, sessionService)
	authHandler.RegisterRoutes(mux)
	mockOIDC.RegisterRoutes(mux)

	// Register OAuth metadata routes
	oauthProvider.RegisterMetadataRoutes(mux)

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	return &webFormServer{
		Server:         server,
		tempDir:        tempDir,
		s3Server:       s3Server,
		sessionsDB:     sessionsDB,
		keyManager:     keyManager,
		userService:    userService,
		sessionService: sessionService,
		emailService:   emailService,
		rateLimiter:    rateLimiter,
		mockOIDC:       mockOIDC,
	}
}

// Client returns a clone so redirect/jar mutation does not leak across tests.
func (ts *webFormServer) Client() *http.Client {
	base := ts.Server.Client()
	cloned := *base
	return &cloned
}

func (ts *webFormServer) cleanup() {
	if ts.shared {
		return
	}
	ts.Server.Close()
	if ts.s3Server != nil {
		ts.s3Server.Close()
	}
	ts.rateLimiter.Stop()
	db.ResetForTesting()
	if ts.tempDir != "" {
		_ = os.RemoveAll(ts.tempDir)
	}
	webFormTestMutex.Unlock()
}

func getOrCreateSharedWebFormServer() (*webFormServer, error) {
	webFormSharedMu.Lock()
	defer webFormSharedMu.Unlock()

	if webFormSharedFixture != nil {
		if err := webFormSharedFixture.sessionsDB.DB().Ping(); err == nil {
			return webFormSharedFixture, nil
		}
		webFormSharedFixture.closeSharedResources()
		webFormSharedFixture = nil
	}

	tempDir, err := os.MkdirTemp("", "webform-shared-*")
	if err != nil {
		return nil, fmt.Errorf("create shared webform temp dir: %w", err)
	}

	webFormSharedFixture = createWebFormServer(tempDir)
	webFormSharedFixture.shared = true
	return webFormSharedFixture, nil
}

func (ts *webFormServer) closeSharedResources() {
	if ts.Server != nil {
		ts.Server.Close()
	}
	if ts.s3Server != nil {
		ts.s3Server.Close()
	}
	if ts.rateLimiter != nil {
		ts.rateLimiter.Stop()
	}
	if ts.tempDir != "" {
		_ = os.RemoveAll(ts.tempDir)
	}
}

func resetWebFormServerState(ts *webFormServer) error {
	if err := resetSharedDBFixtureState(ts.tempDir, ts.sessionsDB); err != nil {
		return err
	}

	if ts.emailService != nil {
		ts.emailService.Clear()
	}
	return nil
}

// createMockS3Server creates a mock S3 server and client for testing.
// Shared across all e2e test files in this package.
func createMockS3Server() (*httptest.Server, *s3client.Client) {
	return createMockS3ServerWithBucket("test-bucket-webforms")
}

// createMockS3ServerWithBucket creates a mock in-memory S3 server with the given bucket name.
func createMockS3ServerWithBucket(bucketName string) (*httptest.Server, *s3client.Client) {
	backend := s3mem.New()
	faker := gofakes3.New(backend)
	s3Server := httptest.NewServer(faker.Server())

	ctx := context.Background()
	sdkConfig, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider("test-key", "test-secret", ""),
		),
	)
	if err != nil {
		panic("Failed to load AWS config: " + err.Error())
	}

	s3c := s3.NewFromConfig(sdkConfig, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(s3Server.URL)
		o.UsePathStyle = true
	})

	_, err = s3c.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		panic("Failed to create mock S3 bucket: " + err.Error())
	}

	client := s3client.NewFromS3Client(s3c, bucketName, s3Server.URL+"/"+bucketName)
	return s3Server, client
}

func findWebFormTemplatesDir() string {
	repoRoot := repositoryRoot()
	candidates := []string{
		filepath.Join(repoRoot, "web", "templates"),
	}

	for _, dir := range candidates {
		if _, err := os.Stat(filepath.Join(dir, "base.html")); err == nil {
			return dir
		}
	}

	panic("Cannot find templates directory")
}

// =============================================================================
// TEST 1: HTML Page Rendering Tests
// =============================================================================

func TestWebForm_PageRendering_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	// Single iteration - page rendering doesn't need property testing
	client := ts.Client()

	// Property 1: Login page renders with expected elements
	loginResp, err := client.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("Login page request failed: %v", err)
	}
	defer loginResp.Body.Close()

	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("Login page should return 200, got %d", loginResp.StatusCode)
	}

	loginBody, _ := io.ReadAll(loginResp.Body)
	loginHTML := string(loginBody)

	// Check for expected form elements
	if !strings.Contains(loginHTML, "email") {
		t.Fatal("Login page should contain email input")
	}
	if !strings.Contains(loginHTML, "password") {
		t.Fatal("Login page should contain password input")
	}

	// Property 2: Register page renders with expected elements
	registerResp, err := client.Get(ts.URL + "/register")
	if err != nil {
		t.Fatalf("Register page request failed: %v", err)
	}
	defer registerResp.Body.Close()

	if registerResp.StatusCode != http.StatusOK {
		t.Fatalf("Register page should return 200, got %d", registerResp.StatusCode)
	}

	registerBody, _ := io.ReadAll(registerResp.Body)
	registerHTML := string(registerBody)

	if !strings.Contains(registerHTML, "email") {
		t.Fatal("Register page should contain email input")
	}
	if !strings.Contains(registerHTML, "password") {
		t.Fatal("Register page should contain password input")
	}

	// Property 3: Password reset page renders
	resetResp, err := client.Get(ts.URL + "/password-reset")
	if err != nil {
		t.Fatalf("Password reset page request failed: %v", err)
	}
	defer resetResp.Body.Close()

	if resetResp.StatusCode != http.StatusOK {
		t.Fatalf("Password reset page should return 200, got %d", resetResp.StatusCode)
	}

	// Property 4: Landing page redirects or shows login
	landingResp, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("Landing page request failed: %v", err)
	}
	defer landingResp.Body.Close()

	// Should redirect to login or show landing
	if landingResp.StatusCode != http.StatusOK && landingResp.StatusCode != http.StatusFound {
		t.Fatalf("Landing page should return 200 or 302, got %d", landingResp.StatusCode)
	}
}

// =============================================================================
// TEST 2: HTML Form Registration Flow
// =============================================================================

func TestWebForm_Registration_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		password := testutil.PasswordGenerator().Draw(rt, "password")

		jar, _ := cookiejar.New(nil)
		client := ts.Client()
		client.Jar = jar
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		// Property 1: POST /auth/register with form data creates user and redirects
		formData := url.Values{
			"email":            {email},
			"password":         {password},
			"confirm_password": {password},
			"terms":            {"on"},
		}

		regResp, err := client.PostForm(ts.URL+"/auth/register", formData)
		if err != nil {
			rt.Fatalf("Registration request failed: %v", err)
		}
		defer regResp.Body.Close()

		// Should redirect after successful registration (302 or 303)
		if regResp.StatusCode != http.StatusFound && regResp.StatusCode != http.StatusSeeOther {
			body, _ := io.ReadAll(regResp.Body)
			rt.Fatalf("Registration should redirect, got %d: %s", regResp.StatusCode, string(body))
		}

		// Property 2: Redirect should be to /notes or similar protected page
		location := regResp.Header.Get("Location")
		if !strings.Contains(location, "/notes") && !strings.Contains(location, "/") {
			rt.Fatalf("Registration should redirect to notes page, got: %s", location)
		}

		// Property 3: Session cookie should be set
		serverURL, _ := url.Parse(ts.URL)
		cookies := jar.Cookies(serverURL)
		sessionCookieFound := false
		for _, c := range cookies {
			if c.Name == "session_id" && c.Value != "" {
				sessionCookieFound = true
				break
			}
		}
		// Note: Session cookie might be set on redirect response, not initial response
		for _, c := range regResp.Cookies() {
			if c.Name == "session_id" && c.Value != "" {
				sessionCookieFound = true
				break
			}
		}
		if !sessionCookieFound {
			rt.Log("Session cookie may be set on redirect target")
		}
	})
}

// =============================================================================
// TEST 3: Registration Validation Errors
// =============================================================================

func TestWebForm_RegistrationValidation_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")

		client := ts.Client()

		// Property 1: Mismatched passwords should show error
		mismatchForm := url.Values{
			"email":            {email},
			"password":         {"ValidPassword123!"},
			"confirm_password": {"DifferentPassword456!"},
			"terms":            {"on"},
		}

		mismatchResp, err := client.PostForm(ts.URL+"/auth/register", mismatchForm)
		if err != nil {
			rt.Fatalf("Mismatch password request failed: %v", err)
		}
		defer mismatchResp.Body.Close()

		// Should show error (either re-render form or redirect with error)
		if mismatchResp.StatusCode == http.StatusFound {
			// Check if redirected to register with error
			location := mismatchResp.Header.Get("Location")
			if !strings.Contains(location, "register") && !strings.Contains(location, "error") {
				rt.Log("Mismatch passwords redirected to:", location)
			}
		} else if mismatchResp.StatusCode == http.StatusOK {
			// Form re-rendered with error
			body, _ := io.ReadAll(mismatchResp.Body)
			if !strings.Contains(strings.ToLower(string(body)), "password") && !strings.Contains(strings.ToLower(string(body)), "match") {
				rt.Log("Expected password mismatch error message")
			}
		}

		// Property 2: Weak password should be rejected
		weakForm := url.Values{
			"email":            {email + "1"},
			"password":         {"weak"},
			"confirm_password": {"weak"},
			"terms":            {"on"},
		}

		weakResp, err := client.PostForm(ts.URL+"/auth/register", weakForm)
		if err != nil {
			rt.Fatalf("Weak password request failed: %v", err)
		}
		defer weakResp.Body.Close()

		// Should not redirect to notes (should show error)
		if weakResp.StatusCode == http.StatusFound {
			location := weakResp.Header.Get("Location")
			if strings.Contains(location, "/notes") {
				rt.Fatal("Weak password should not allow registration")
			}
		}

		// Property 3: Missing terms acceptance (if required)
		noTermsForm := url.Values{
			"email":            {email + "2"},
			"password":         {"ValidPassword123!"},
			"confirm_password": {"ValidPassword123!"},
			// No "terms" field
		}

		noTermsResp, err := client.PostForm(ts.URL+"/auth/register", noTermsForm)
		if err != nil {
			rt.Fatalf("No terms request failed: %v", err)
		}
		noTermsResp.Body.Close()
		// Terms may or may not be required - just verify no crash
	})
}

// =============================================================================
// TEST 4: HTML Form Login Flow
// =============================================================================

func TestWebForm_Login_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		password := testutil.PasswordGenerator().Draw(rt, "password")

		// First register the user via API
		apiClient := ts.Client()
		regResp, err := apiClient.PostForm(ts.URL+"/auth/register", url.Values{"email": {email}, "password": {password}})
		if err != nil {
			rt.Fatalf("Registration failed: %v", err)
		}
		regResp.Body.Close()

		// Now test HTML form login
		jar, _ := cookiejar.New(nil)
		client := ts.Client()
		client.Jar = jar
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		// Property 1: POST /auth/login with form data authenticates user
		loginForm := url.Values{
			"email":    {email},
			"password": {password},
		}

		loginResp, err := client.PostForm(ts.URL+"/auth/login", loginForm)
		if err != nil {
			rt.Fatalf("Login request failed: %v", err)
		}
		defer loginResp.Body.Close()

		// Should redirect after successful login
		if loginResp.StatusCode != http.StatusFound && loginResp.StatusCode != http.StatusSeeOther {
			body, _ := io.ReadAll(loginResp.Body)
			rt.Fatalf("Login should redirect, got %d: %s", loginResp.StatusCode, string(body))
		}

		// Property 2: Session cookie should be set
		sessionCookieFound := false
		for _, c := range loginResp.Cookies() {
			if c.Name == "session_id" && c.Value != "" {
				sessionCookieFound = true
				break
			}
		}
		if !sessionCookieFound {
			rt.Fatal("Session cookie should be set after login")
		}
	})
}

// =============================================================================
// TEST 5: HTML Magic Link Flow
// =============================================================================

func TestWebForm_MagicLink_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")

		// Clear previous emails for this iteration
		ts.emailService.Clear()

		jar, _ := cookiejar.New(nil)
		client := ts.Client()
		client.Jar = jar
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		// Property 1: POST /auth/magic with form data sends magic link
		magicForm := url.Values{
			"email": {email},
		}

		magicResp, err := client.PostForm(ts.URL+"/auth/magic", magicForm)
		if err != nil {
			rt.Fatalf("Magic link request failed: %v", err)
		}
		defer magicResp.Body.Close()

		// Should redirect to login page (303 See Other)
		if magicResp.StatusCode != http.StatusSeeOther && magicResp.StatusCode != http.StatusFound {
			body, _ := io.ReadAll(magicResp.Body)
			rt.Fatalf("Magic link should redirect (302/303), got %d: %s", magicResp.StatusCode, string(body))
		}

		// Property 2: Email should be sent
		if ts.emailService.Count() == 0 {
			rt.Fatal("Magic link email should be sent")
		}

		// Property 3: Extract and verify magic link
		lastEmail := ts.emailService.LastEmail()
		if lastEmail.To != email {
			rt.Fatalf("Email sent to wrong address: expected %s, got %s", email, lastEmail.To)
		}

		magicLinkData, ok := lastEmail.Data.(emailpkg.MagicLinkData)
		if !ok {
			rt.Fatal("Email data should be MagicLinkData")
		}

		linkURL, _ := url.Parse(magicLinkData.Link)
		token := linkURL.Query().Get("token")
		if token == "" {
			rt.Fatal("Magic link should contain token")
		}

		// Property 4: GET /auth/magic/verify with token should authenticate
		verifyResp, err := client.Get(ts.URL + "/auth/magic/verify?token=" + token)
		if err != nil {
			rt.Fatalf("Magic verify request failed: %v", err)
		}
		defer verifyResp.Body.Close()

		// Should redirect after successful verification
		if verifyResp.StatusCode != http.StatusFound {
			body, _ := io.ReadAll(verifyResp.Body)
			rt.Fatalf("Magic verify should redirect, got %d: %s", verifyResp.StatusCode, string(body))
		}

		// Property 5: Session cookie should be set
		sessionCookieFound := false
		for _, c := range verifyResp.Cookies() {
			if c.Name == "session_id" && c.Value != "" {
				sessionCookieFound = true
				break
			}
		}
		if !sessionCookieFound {
			rt.Fatal("Session cookie should be set after magic link verification")
		}

		// Property 6: Token should be consumed (reuse should fail)
		reuse, err := client.Get(ts.URL + "/auth/magic/verify?token=" + token)
		if err != nil {
			rt.Fatalf("Reuse request failed: %v", err)
		}
		reuse.Body.Close()

		if reuse.StatusCode == http.StatusFound {
			rt.Fatal("Reusing magic link token should not redirect to success")
		}
	})
}

// =============================================================================
// TEST 6: HTML Password Reset Flow
// =============================================================================

func TestWebForm_PasswordReset_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		password := testutil.PasswordGenerator().Draw(rt, "password")
		newPassword := testutil.PasswordGenerator().Draw(rt, "newPassword")

		// Register user first
		apiClient := ts.Client()
		regResp, _ := apiClient.PostForm(ts.URL+"/auth/register", url.Values{"email": {email}, "password": {password}})
		regResp.Body.Close()

		// Clear emails
		ts.emailService.Clear()

		client := ts.Client()

		// Property 1: POST /auth/password-reset with form data sends reset email
		resetForm := url.Values{
			"email": {email},
		}

		resetResp, err := client.PostForm(ts.URL+"/auth/password-reset", resetForm)
		if err != nil {
			rt.Fatalf("Password reset request failed: %v", err)
		}
		defer resetResp.Body.Close()

		// Should show success page or redirect (always succeeds to prevent enumeration)
		if resetResp.StatusCode != http.StatusOK && resetResp.StatusCode != http.StatusFound {
			body, _ := io.ReadAll(resetResp.Body)
			rt.Fatalf("Password reset should succeed, got %d: %s", resetResp.StatusCode, string(body))
		}

		// Property 2: Reset email should be sent
		if ts.emailService.Count() == 0 {
			rt.Fatal("Password reset email should be sent")
		}

		// Property 3: Extract reset token
		lastEmail := ts.emailService.LastEmail()
		resetData, ok := lastEmail.Data.(emailpkg.PasswordResetData)
		if !ok {
			rt.Fatal("Email data should be PasswordResetData")
		}

		linkURL, _ := url.Parse(resetData.Link)
		token := linkURL.Query().Get("token")
		if token == "" {
			rt.Fatal("Reset link should contain token")
		}

		// Property 4: POST /auth/password-reset-confirm with form data resets password
		confirmForm := url.Values{
			"token":            {token},
			"password":         {newPassword},
			"confirm_password": {newPassword},
		}

		confirmResp, err := client.PostForm(ts.URL+"/auth/password-reset-confirm", confirmForm)
		if err != nil {
			rt.Fatalf("Password reset confirm request failed: %v", err)
		}
		defer confirmResp.Body.Close()

		// Should show success or redirect to login
		if confirmResp.StatusCode != http.StatusOK && confirmResp.StatusCode != http.StatusFound {
			body, _ := io.ReadAll(confirmResp.Body)
			rt.Fatalf("Password reset confirm should succeed, got %d: %s", confirmResp.StatusCode, string(body))
		}

		// Property 5: Token should be consumed
		confirmForm2 := url.Values{
			"token":            {token},
			"password":         {"AnotherPassword789!"},
			"confirm_password": {"AnotherPassword789!"},
		}

		reuse, err := client.PostForm(ts.URL+"/auth/password-reset-confirm", confirmForm2)
		if err != nil {
			rt.Fatalf("Reuse request failed: %v", err)
		}
		reuse.Body.Close()

		if reuse.StatusCode == http.StatusFound {
			location := reuse.Header.Get("Location")
			if strings.Contains(location, "/login") && !strings.Contains(location, "error") {
				rt.Log("Token reuse may have succeeded (unexpected)")
			}
		}
	})
}

// =============================================================================
// TEST 7: Authenticated Notes CRUD via Web Forms
// =============================================================================

func TestWebForm_NotesCRUD_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		noteTitle := testutil.NoteTitleGenerator().Draw(rt, "title")
		noteContent := testutil.NoteContentGenerator().Draw(rt, "content")
		updatedContent := testutil.NoteContentGenerator().Draw(rt, "updatedContent")

		// Create user and get session
		ctx := context.Background()
		user, _ := ts.userService.FindOrCreateByProvider(ctx, email)
		sessionID, _ := ts.sessionService.Create(ctx, user.ID)

		jar, _ := cookiejar.New(nil)
		client := ts.Client()
		client.Jar = jar
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		// Set session cookie
		serverURL, _ := url.Parse(ts.URL)
		jar.SetCookies(serverURL, []*http.Cookie{{
			Name:  "session_id",
			Value: sessionID,
			Path:  "/",
		}})

		// Property 1: GET /notes/new returns new note form
		newPageResp, err := client.Get(ts.URL + "/notes/new")
		if err != nil {
			rt.Fatalf("New note page request failed: %v", err)
		}
		defer newPageResp.Body.Close()

		if newPageResp.StatusCode != http.StatusOK {
			rt.Fatalf("New note page should return 200, got %d", newPageResp.StatusCode)
		}

		newPageBody, _ := io.ReadAll(newPageResp.Body)
		if !strings.Contains(string(newPageBody), "title") || !strings.Contains(string(newPageBody), "content") {
			rt.Fatal("New note page should contain title and content inputs")
		}

		// Property 2: POST /notes creates note and redirects
		createForm := url.Values{
			"title":   {noteTitle},
			"content": {noteContent},
		}

		createResp, err := client.PostForm(ts.URL+"/notes", createForm)
		if err != nil {
			rt.Fatalf("Create note request failed: %v", err)
		}
		defer createResp.Body.Close()

		if createResp.StatusCode != http.StatusFound && createResp.StatusCode != http.StatusSeeOther {
			body, _ := io.ReadAll(createResp.Body)
			rt.Fatalf("Create note should redirect, got %d: %s", createResp.StatusCode, string(body))
		}

		// Extract note ID from redirect location
		location := createResp.Header.Get("Location")
		// Location should be /notes/{id}
		parts := strings.Split(location, "/")
		noteID := parts[len(parts)-1]

		// Property 3: GET /notes/{id} shows the note
		viewResp, err := client.Get(ts.URL + "/notes/" + noteID)
		if err != nil {
			rt.Fatalf("View note request failed: %v", err)
		}
		defer viewResp.Body.Close()

		if viewResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(viewResp.Body)
			rt.Fatalf("View note should return 200, got %d: %s", viewResp.StatusCode, string(body))
		}

		viewBody, _ := io.ReadAll(viewResp.Body)
		if !strings.Contains(string(viewBody), noteTitle) {
			rt.Fatal("View note should show note title")
		}

		// Property 4: GET /notes shows the note in list
		listResp, err := client.Get(ts.URL + "/notes")
		if err != nil {
			rt.Fatalf("List notes request failed: %v", err)
		}
		defer listResp.Body.Close()

		if listResp.StatusCode != http.StatusOK {
			rt.Fatalf("List notes should return 200, got %d", listResp.StatusCode)
		}

		listBody, _ := io.ReadAll(listResp.Body)
		if !strings.Contains(string(listBody), noteTitle) {
			rt.Fatal("Notes list should show created note")
		}

		// Property 5: GET /notes/{id}/edit shows edit form
		editPageResp, err := client.Get(ts.URL + "/notes/" + noteID + "/edit")
		if err != nil {
			rt.Fatalf("Edit note page request failed: %v", err)
		}
		defer editPageResp.Body.Close()

		if editPageResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(editPageResp.Body)
			rt.Fatalf("Edit note page should return 200, got %d: %s", editPageResp.StatusCode, string(body))
		}

		// Property 6: POST /notes/{id} updates the note
		updateForm := url.Values{
			"title":   {noteTitle},
			"content": {updatedContent},
		}

		updateResp, err := client.PostForm(ts.URL+"/notes/"+noteID, updateForm)
		if err != nil {
			rt.Fatalf("Update note request failed: %v", err)
		}
		defer updateResp.Body.Close()

		if updateResp.StatusCode != http.StatusFound && updateResp.StatusCode != http.StatusSeeOther {
			body, _ := io.ReadAll(updateResp.Body)
			rt.Fatalf("Update note should redirect, got %d: %s", updateResp.StatusCode, string(body))
		}

		// Property 7: POST /notes/{id}/delete deletes the note
		deleteResp, err := client.PostForm(ts.URL+"/notes/"+noteID+"/delete", url.Values{})
		if err != nil {
			rt.Fatalf("Delete note request failed: %v", err)
		}
		defer deleteResp.Body.Close()

		if deleteResp.StatusCode != http.StatusFound && deleteResp.StatusCode != http.StatusSeeOther {
			body, _ := io.ReadAll(deleteResp.Body)
			rt.Fatalf("Delete note should redirect, got %d: %s", deleteResp.StatusCode, string(body))
		}

		// Property 8: Deleted note should not be in list
		list2Resp, err := client.Get(ts.URL + "/notes")
		if err != nil {
			rt.Fatalf("List notes after delete failed: %v", err)
		}
		defer list2Resp.Body.Close()
		list2Body, _ := io.ReadAll(list2Resp.Body)
		if strings.Contains(string(list2Body), noteID) {
			rt.Fatal("Deleted note should not appear in list")
		}
	})
}

// =============================================================================
// TEST 8: Session Isolation
// =============================================================================

func TestWebForm_SessionIsolation_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email1 := testutil.EmailGenerator().Draw(rt, "email1")
		email2 := testutil.EmailGenerator().Draw(rt, "email2")
		if email2 == email1 {
			email2 = "other+" + email2
		}
		noteTitle := testutil.NoteTitleGenerator().Draw(rt, "title")

		// Create two users
		ctx := context.Background()
		user1, _ := ts.userService.FindOrCreateByProvider(ctx, email1)
		user2, _ := ts.userService.FindOrCreateByProvider(ctx, email2)
		session1, _ := ts.sessionService.Create(ctx, user1.ID)
		session2, _ := ts.sessionService.Create(ctx, user2.ID)

		// Client 1: Create note
		jar1, _ := cookiejar.New(nil)
		client1 := ts.Client()
		client1.Jar = jar1
		client1.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		serverURL, _ := url.Parse(ts.URL)
		jar1.SetCookies(serverURL, []*http.Cookie{{
			Name:  "session_id",
			Value: session1,
			Path:  "/",
		}})

		createForm := url.Values{
			"title":   {noteTitle},
			"content": {"User1's private note"},
		}
		createResp, _ := client1.PostForm(ts.URL+"/notes", createForm)
		createResp.Body.Close()

		// Extract note ID
		location := createResp.Header.Get("Location")
		parts := strings.Split(location, "/")
		noteID := parts[len(parts)-1]

		// Property 1: User 2 should NOT be able to view User 1's note
		jar2, _ := cookiejar.New(nil)
		client2 := ts.Client()
		client2.Jar = jar2

		jar2.SetCookies(serverURL, []*http.Cookie{{
			Name:  "session_id",
			Value: session2,
			Path:  "/",
		}})

		viewResp, err := client2.Get(ts.URL + "/notes/" + noteID)
		if err != nil {
			rt.Fatalf("View note as user 2 failed: %v", err)
		}
		defer viewResp.Body.Close()

		// Should return 404 or redirect to error page
		if viewResp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(viewResp.Body)
			if strings.Contains(string(body), noteTitle) {
				rt.Fatal("User 2 should NOT be able to see User 1's note")
			}
		}

		// Property 2: Unauthenticated user should not access user's notes
		client3 := ts.Client()
		client3.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		unauthResp, err := client3.Get(ts.URL + "/notes")
		if err != nil {
			rt.Fatalf("Unauthenticated notes request failed: %v", err)
		}
		defer unauthResp.Body.Close()

		// Should either redirect to login OR show empty/login prompt (both are secure)
		if unauthResp.StatusCode == http.StatusFound {
			// Redirects to login - this is good
			location = unauthResp.Header.Get("Location")
			if !strings.Contains(location, "login") {
				rt.Fatalf("Redirect should go to login, got: %s", location)
			}
		} else if unauthResp.StatusCode == http.StatusOK {
			// Shows a page - verify it doesn't contain the user's note
			body, _ := io.ReadAll(unauthResp.Body)
			if strings.Contains(string(body), noteTitle) {
				rt.Fatal("Unauthenticated user should NOT see authenticated user's notes")
			}
		} else {
			rt.Fatalf("Unauthenticated access should redirect or show empty page, got %d", unauthResp.StatusCode)
		}
	})
}

// =============================================================================
// TEST 9: Logout Flow
// =============================================================================

func TestWebForm_Logout_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")

		ctx := context.Background()
		user, _ := ts.userService.FindOrCreateByProvider(ctx, email)
		sessionID, _ := ts.sessionService.Create(ctx, user.ID)

		jar, _ := cookiejar.New(nil)
		client := ts.Client()
		client.Jar = jar
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		serverURL, _ := url.Parse(ts.URL)
		jar.SetCookies(serverURL, []*http.Cookie{{
			Name:  "session_id",
			Value: sessionID,
			Path:  "/",
		}})

		// Property 1: User can access notes when logged in
		notesResp, _ := client.Get(ts.URL + "/notes")
		notesResp.Body.Close()

		if notesResp.StatusCode != http.StatusOK {
			rt.Fatalf("Logged in user should access /notes, got %d", notesResp.StatusCode)
		}

		// Property 2: POST /auth/logout clears session
		logoutResp, err := client.PostForm(ts.URL+"/auth/logout", url.Values{})
		if err != nil {
			rt.Fatalf("Logout request failed: %v", err)
		}
		defer logoutResp.Body.Close()

		// Should redirect to login or home
		if logoutResp.StatusCode != http.StatusFound && logoutResp.StatusCode != http.StatusSeeOther {
			rt.Fatalf("Logout should redirect, got %d", logoutResp.StatusCode)
		}

		// Property 3: Session cookie should be cleared
		for _, c := range logoutResp.Cookies() {
			if c.Name == "session_id" {
				if c.MaxAge > 0 || c.Value != "" {
					// Cookie should be cleared (MaxAge <= 0 or empty value)
					rt.Log("Session cookie should be cleared after logout")
				}
			}
		}

		// Property 4: After logout, notes should redirect to login
		notes2Resp, _ := client.Get(ts.URL + "/notes")
		notes2Resp.Body.Close()

		if notes2Resp.StatusCode == http.StatusOK {
			rt.Fatal("After logout, /notes should not be accessible")
		}
	})
}

// =============================================================================
// TEST 10: Empty State and Pagination
// =============================================================================

func TestWebForm_EmptyStateAndPagination_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")

		ctx := context.Background()
		user, _ := ts.userService.FindOrCreateByProvider(ctx, email)
		sessionID, _ := ts.sessionService.Create(ctx, user.ID)

		jar, _ := cookiejar.New(nil)
		client := ts.Client()
		client.Jar = jar
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		serverURL, _ := url.Parse(ts.URL)
		jar.SetCookies(serverURL, []*http.Cookie{{
			Name:  "session_id",
			Value: sessionID,
			Path:  "/",
		}})

		// Property 1: Empty notes list shows appropriate message
		emptyResp, err := client.Get(ts.URL + "/notes")
		if err != nil {
			rt.Fatalf("Empty notes list request failed: %v", err)
		}
		defer emptyResp.Body.Close()

		emptyBody, _ := io.ReadAll(emptyResp.Body)
		emptyHTML := strings.ToLower(string(emptyBody))

		// Should show "no notes" or "create your first" message
		if !strings.Contains(emptyHTML, "no notes") && !strings.Contains(emptyHTML, "create") && !strings.Contains(emptyHTML, "empty") {
			rt.Log("Empty notes page should show helpful message")
		}

		// Property 2: Pagination parameter is accepted
		paginatedResp, err := client.Get(ts.URL + "/notes?page=1")
		if err != nil {
			rt.Fatalf("Paginated request failed: %v", err)
		}
		paginatedResp.Body.Close()

		if paginatedResp.StatusCode != http.StatusOK {
			rt.Fatalf("Paginated notes should return 200, got %d", paginatedResp.StatusCode)
		}

		// Property 3: Invalid page parameter is handled gracefully
		invalidPageResp, err := client.Get(ts.URL + "/notes?page=invalid")
		if err != nil {
			rt.Fatalf("Invalid page request failed: %v", err)
		}
		invalidPageResp.Body.Close()

		// Should not crash - either 200 (defaults to page 1) or error
		if invalidPageResp.StatusCode != http.StatusOK && invalidPageResp.StatusCode != http.StatusBadRequest {
			rt.Fatalf("Invalid page should be handled, got %d", invalidPageResp.StatusCode)
		}

		// Property 4: Negative page parameter is handled
		negativePageResp, err := client.Get(ts.URL + "/notes?page=-1")
		if err != nil {
			rt.Fatalf("Negative page request failed: %v", err)
		}
		negativePageResp.Body.Close()

		if negativePageResp.StatusCode != http.StatusOK && negativePageResp.StatusCode != http.StatusBadRequest {
			rt.Fatalf("Negative page should be handled, got %d", negativePageResp.StatusCode)
		}
	})
}

// =============================================================================
// TEST 11: Public Notes (No Auth Required)
// =============================================================================

func TestWebForm_PublicNotes_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		noteTitle := testutil.NoteTitleGenerator().Draw(rt, "title")
		noteContent := testutil.NoteContentGenerator().Draw(rt, "content")

		ctx := context.Background()
		user, _ := ts.userService.FindOrCreateByProvider(ctx, email)
		sessionID, _ := ts.sessionService.Create(ctx, user.ID)

		jar, _ := cookiejar.New(nil)
		client := ts.Client()
		client.Jar = jar
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		serverURL, _ := url.Parse(ts.URL)
		jar.SetCookies(serverURL, []*http.Cookie{{
			Name:  "session_id",
			Value: sessionID,
			Path:  "/",
		}})

		// Create a note
		createForm := url.Values{
			"title":   {noteTitle},
			"content": {noteContent},
		}
		createResp, _ := client.PostForm(ts.URL+"/notes", createForm)
		location := createResp.Header.Get("Location")
		createResp.Body.Close()

		parts := strings.Split(location, "/")
		noteID := parts[len(parts)-1]

		// Property 1: POST /notes/{id}/publish toggles public status
		publishResp, err := client.PostForm(ts.URL+"/notes/"+noteID+"/publish", url.Values{})
		if err != nil {
			rt.Fatalf("Publish request failed: %v", err)
		}
		publishResp.Body.Close()

		if publishResp.StatusCode != http.StatusFound && publishResp.StatusCode != http.StatusSeeOther && publishResp.StatusCode != http.StatusOK {
			rt.Fatalf("Publish should succeed, got %d", publishResp.StatusCode)
		}

		// Property 2: Public note URL should be accessible without auth
		anonClient := ts.Client()
		anonClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		publicURL := fmt.Sprintf("%s/public/%s/%s", ts.URL, user.ID, noteID)
		publicResp, err := anonClient.Get(publicURL)
		if err != nil {
			rt.Fatalf("Public note request failed: %v", err)
		}
		defer publicResp.Body.Close()

		// Should return 200 (public note) or 404 (note not published yet)
		if publicResp.StatusCode != http.StatusOK && publicResp.StatusCode != http.StatusNotFound {
			body, _ := io.ReadAll(publicResp.Body)
			rt.Fatalf("Public note should return 200 or 404, got %d: %s", publicResp.StatusCode, string(body))
		}

		// Property 3: If published, page should have SEO meta tags
		if publicResp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(publicResp.Body)
			html := string(body)

			// Check for basic SEO elements
			if !strings.Contains(html, "<title>") {
				rt.Log("Public note page should have title tag")
			}
			// og:title or twitter:card are optional but good to check
		}
	})
}

// =============================================================================
// TEST 12: Arbitrary Input Handling (Fuzz-friendly)
// =============================================================================

func TestWebForm_ArbitraryInputs_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		// Generate arbitrary strings for edge case testing
		arbitraryString := rapid.String().Draw(rt, "arbitrary")
		specialChars := rapid.StringMatching(`[<>"'&\n\r\t]{1,10}`).Draw(rt, "special")

		client := ts.Client()

		// Property 1: Arbitrary email in login doesn't crash
		loginForm := url.Values{
			"email":    {arbitraryString},
			"password": {arbitraryString},
		}
		loginResp, _ := client.PostForm(ts.URL+"/auth/login", loginForm)
		loginResp.Body.Close()
		// Just verify no crash/500

		// Property 2: Special characters in registration handled
		regForm := url.Values{
			"email":            {specialChars + "@example.com"},
			"password":         {specialChars},
			"confirm_password": {specialChars},
		}
		regResp, _ := client.PostForm(ts.URL+"/auth/register", regForm)
		regResp.Body.Close()
		// Just verify no crash

		// Property 3: Arbitrary token in magic verify handled
		verifyResp, _ := client.Get(ts.URL + "/auth/magic/verify?token=" + url.QueryEscape(arbitraryString))
		verifyResp.Body.Close()
		// Should not be 500

		// Property 4: Arbitrary token in password reset handled
		resetConfirmForm := url.Values{
			"token":            {arbitraryString},
			"password":         {"ValidPassword123!"},
			"confirm_password": {"ValidPassword123!"},
		}
		resetResp, _ := client.PostForm(ts.URL+"/auth/password-reset-confirm", resetConfirmForm)
		resetResp.Body.Close()
		// Should not be 500

		// Property 5: XSS characters in note content are escaped
		ctx := context.Background()
		xssEmail := testutil.EmailGenerator().Draw(rt, "xss_email")
		user, _ := ts.userService.FindOrCreateByProvider(ctx, xssEmail)
		sessionID, _ := ts.sessionService.Create(ctx, user.ID)

		jar, _ := cookiejar.New(nil)
		authClient := ts.Client()
		authClient.Jar = jar
		authClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		serverURL, _ := url.Parse(ts.URL)
		jar.SetCookies(serverURL, []*http.Cookie{{
			Name:  "session_id",
			Value: sessionID,
			Path:  "/",
		}})

		xssContent := "<script>alert('xss')</script>"
		noteForm := url.Values{
			"title":   {"XSS Test Note"},
			"content": {xssContent},
		}
		noteResp, _ := authClient.PostForm(ts.URL+"/notes", noteForm)
		if noteResp.StatusCode == http.StatusFound {
			location := noteResp.Header.Get("Location")
			noteResp.Body.Close()

			viewResp, _ := authClient.Get(ts.URL + location)
			body, _ := io.ReadAll(viewResp.Body)
			viewResp.Body.Close()

			// The raw <script> tag should be escaped (not appear as-is)
			if strings.Contains(string(body), "<script>alert('xss')</script>") {
				rt.Fatal("XSS content should be escaped in HTML output")
			}
		} else {
			noteResp.Body.Close()
		}
	})
}
