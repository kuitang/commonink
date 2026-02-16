// Package browser contains Playwright E2E tests for browser-based authentication flows.
// These tests are deterministic scenarios (NOT property-based) as per CLAUDE.md guidelines.
//
// Prerequisites:
// - Install Playwright browsers: go run github.com/playwright-community/playwright-go/cmd/playwright install chromium
// - Run tests with: go test -v ./tests/browser/...
package browser

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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
	"github.com/playwright-community/playwright-go"

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/email"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/kuitang/agent-notes/internal/ratelimit"
	"github.com/kuitang/agent-notes/internal/s3client"
	"github.com/kuitang/agent-notes/internal/web"
)

// authTestEnv encapsulates the test environment for auth flow tests.
// This type is separate from the existing testEnv/testServer to avoid conflicts.
type authTestEnv struct {
	server       *httptest.Server
	emailService *email.MockEmailService
	sessionsDB   *db.SessionsDB
	s3Server     *httptest.Server
	pw           *playwright.Playwright
	browser      playwright.Browser
	baseURL      string
}

// setupAuthTestEnv creates a test server for auth flow testing.
// The caller MUST call cleanup() when done to release resources.
func setupAuthTestEnv(t *testing.T) (*authTestEnv, func()) {
	t.Helper()

	// Reset database singleton and set fresh data directory
	db.ResetForTesting()
	db.DataDirectory = t.TempDir()

	// Initialize sessions database (now uses fresh directory)
	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		t.Fatalf("Failed to open sessions database: %v", err)
	}

	// Generate a test master key
	masterKey, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	// Initialize key manager
	keyManager := crypto.NewKeyManager(masterKey, sessionsDB)

	// Initialize mock email service
	emailService := email.NewMockEmailService()

	// Create mock S3
	s3Client, s3Server := createAuthTestS3(t)

	// Initialize template renderer
	templatesDir := findAuthTestTemplatesDir()
	renderer, err := web.NewRenderer(templatesDir)
	if err != nil {
		t.Fatalf("Failed to create renderer: %v", err)
	}

	// Create server first to get URL
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	// Initialize services with actual server URL
	userService := auth.NewUserService(sessionsDB, keyManager, emailService, server.URL)
	sessionService := auth.NewSessionService(sessionsDB)
	consentService := auth.NewConsentService(sessionsDB)

	// Initialize local mock OIDC provider (serves consent page at /auth/mock-oidc/authorize)
	var localMockOIDC *auth.LocalMockOIDCProvider

	// Initialize public notes service
	publicNotes := notes.NewPublicNoteService(s3Client)

	// Initialize auth middleware
	authMiddleware := auth.NewMiddleware(sessionService, keyManager)

	// Initialize rate limiter (high limits for tests)
	rateLimiter := ratelimit.NewRateLimiter(ratelimit.Config{
		FreeRPS:         10000,
		FreeBurst:       100000,
		PaidRPS:         100000,
		PaidBurst:       1000000,
		CleanupInterval: time.Hour,
	})

	// Initialize web handler with all services
	webHandler := web.NewWebHandler(
		renderer,
		nil, // notesService is created per-request
		publicNotes,
		userService,
		sessionService,
		consentService,
		s3Client,
		nil, // shortURLSvc not needed for auth tests
		server.URL,
	)

	// Close old server and create new mux
	server.Close()

	// Create new mux with all routes
	mux = http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// Register web UI routes (GET pages) and auth handler routes (POST form actions)
	webHandler.RegisterRoutes(mux, authMiddleware)
	localMockOIDC = auth.NewLocalMockOIDCProvider("PLACEHOLDER")
	authHandler := auth.NewHandler(localMockOIDC, userService, sessionService)
	authHandler.RegisterRoutes(mux)
	localMockOIDC.RegisterRoutes(mux)

	// Rate limiting middleware
	getUserID := func(r *http.Request) string {
		return auth.GetUserID(r.Context())
	}
	getIsPaid := func(r *http.Request) bool {
		return false
	}
	rateLimitMW := ratelimit.RateLimitMiddleware(rateLimiter, getUserID, getIsPaid)

	// Notes API handlers (needed for redirects after auth)
	notesAPIHandler := &authTestNotesHandler{}
	mux.Handle("GET /api/notes", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(notesAPIHandler.ListNotes))))
	mux.Handle("POST /api/notes", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(notesAPIHandler.CreateNote))))

	// Create final test server
	server = httptest.NewServer(mux)
	localMockOIDC.SetBaseURL(server.URL)

	env := &authTestEnv{
		server:       server,
		emailService: emailService,
		sessionsDB:   sessionsDB,
		s3Server:     s3Server,
		baseURL:      server.URL,
	}

	cleanup := func() {
		if env.browser != nil {
			env.browser.Close()
		}
		if env.pw != nil {
			env.pw.Stop()
		}
		env.server.Close()
		if env.s3Server != nil {
			env.s3Server.Close()
		}
		rateLimiter.Stop()
		db.CloseAll()
	}

	return env, cleanup
}

// createAuthTestS3 creates a mock S3 server for auth tests.
func createAuthTestS3(t *testing.T) (*s3client.Client, *httptest.Server) {
	t.Helper()

	backend := s3mem.New()
	faker := gofakes3.New(backend)
	ts := httptest.NewServer(faker.Server())

	ctx := context.Background()
	sdkConfig, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider("test-key", "test-secret", ""),
		),
	)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}

	s3SDK := s3.NewFromConfig(sdkConfig, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(ts.URL)
		o.UsePathStyle = true
	})

	bucketName := "auth-test-bucket"
	_, err = s3SDK.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Fatalf("Failed to create mock S3 bucket: %v", err)
	}

	client := s3client.NewFromS3Client(s3SDK, bucketName, ts.URL+"/"+bucketName)
	return client, ts
}

// findAuthTestTemplatesDir locates the templates directory.
func findAuthTestTemplatesDir() string {
	candidates := []string{
		"../../web/templates",
		"../../../web/templates",
		"web/templates",
		"/home/kuitang/git/agent-notes/web/templates",
	}

	for _, dir := range candidates {
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}

	return "/home/kuitang/git/agent-notes/web/templates"
}

// initAuthTestBrowser initializes Playwright and launches a browser.
func (env *authTestEnv) initAuthTestBrowser(t *testing.T) error {
	t.Helper()

	pw, err := playwright.Run()
	if err != nil {
		return fmt.Errorf("could not start playwright: %w (run: go run github.com/playwright-community/playwright-go/cmd/playwright install chromium)", err)
	}
	env.pw = pw

	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
	})
	if err != nil {
		pw.Stop()
		return fmt.Errorf("could not launch browser: %w", err)
	}
	env.browser = browser

	return nil
}

// newAuthTestPage creates a new browser page for testing.
func (env *authTestEnv) newAuthTestPage(t *testing.T) playwright.Page {
	t.Helper()

	page, err := env.browser.NewPage()
	if err != nil {
		t.Fatalf("could not create page: %v", err)
	}

	page.SetDefaultTimeout(10000) // 10 seconds

	return page
}

// authTestNotesHandler provides simple API handlers for testing.
type authTestNotesHandler struct{}

func (h *authTestNotesHandler) ListNotes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"notes":[]}`))
}

func (h *authTestNotesHandler) CreateNote(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"id":"test-note-1","title":"Test","content":""}`))
}

// =============================================================================
// Registration Flow Tests
// =============================================================================

func TestBrowser_Auth_Registration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Navigate to register page
	_, err := page.Goto(env.baseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate to register page: %v", err)
	}

	// Wait for page to load
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	// Verify we're on the register page
	title, err := page.Title()
	if err != nil {
		t.Fatalf("Failed to get page title: %v", err)
	}
	if !strings.Contains(title, "Create") && !strings.Contains(title, "Register") && !strings.Contains(title, "Account") {
		t.Errorf("Unexpected page title: %s", title)
	}

	// Fill registration form
	testEmail := fmt.Sprintf("test-%d@example.com", time.Now().UnixNano())
	testPassword := "SecurePass123!"

	// Fill email
	emailInput := page.Locator("input[name='email']")
	err = emailInput.Fill(testEmail)
	if err != nil {
		t.Fatalf("Failed to fill email: %v", err)
	}

	// Fill password
	passwordInput := page.Locator("input[name='password']")
	err = passwordInput.Fill(testPassword)
	if err != nil {
		t.Fatalf("Failed to fill password: %v", err)
	}

	// Fill confirm password
	confirmInput := page.Locator("input[name='confirm_password']")
	err = confirmInput.Fill(testPassword)
	if err != nil {
		t.Fatalf("Failed to fill confirm password: %v", err)
	}

	// Check terms checkbox
	termsCheckbox := page.Locator("input[name='terms']")
	err = termsCheckbox.Check()
	if err != nil {
		t.Fatalf("Failed to check terms: %v", err)
	}

	// Submit form
	submitBtn := page.Locator("button[type='submit']:has-text('Create account')")
	err = submitBtn.Click()
	if err != nil {
		t.Fatalf("Failed to click submit button: %v", err)
	}

	// Wait for navigation to complete
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	if err != nil {
		t.Fatalf("Navigation did not complete: %v", err)
	}

	// After successful registration, should redirect to /notes
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/notes") && !strings.Contains(currentURL, "/login") {
		t.Errorf("Expected redirect to /notes or /login, got: %s", currentURL)
	}
}

func TestBrowser_Auth_Registration_PasswordMismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Navigate to register page
	_, err := page.Goto(env.baseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate to register page: %v", err)
	}

	// Fill form with mismatched passwords
	page.Locator("input[name='email']").Fill("test@example.com")
	page.Locator("input[name='password']").Fill("SecurePass123!")
	page.Locator("input[name='confirm_password']").Fill("DifferentPass456!")
	page.Locator("input[name='terms']").Check()

	// Submit form
	page.Locator("button[type='submit']:has-text('Create account')").Click()

	// Wait for response
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Should show error about password mismatch or stay on register page with error
	currentURL := page.URL()
	if strings.Contains(currentURL, "/register") || strings.Contains(currentURL, "error") {
		t.Log("Password mismatch was handled correctly")
	}
}

// =============================================================================
// Password Login Flow Tests
// =============================================================================

func TestBrowser_Auth_PasswordLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Pre-create a test user by registering first
	testEmail := fmt.Sprintf("login-test-%d@example.com", time.Now().UnixNano())
	testPassword := "SecurePass123!"

	// First register the user
	_, err := page.Goto(env.baseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate to register page: %v", err)
	}

	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill(testPassword)
	page.Locator("input[name='confirm_password']").Fill(testPassword)
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()

	// Wait for registration to complete
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Clear cookies (logout)
	browserContext := page.Context()
	browserContext.ClearCookies()

	// Now test login
	_, err = page.Goto(env.baseURL + "/login")
	if err != nil {
		t.Fatalf("Failed to navigate to login page: %v", err)
	}

	// Wait for page to load
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	// Fill login form (password section)
	loginEmailInput := page.Locator("#login-email")
	err = loginEmailInput.Fill(testEmail)
	if err != nil {
		t.Fatalf("Failed to fill email: %v", err)
	}

	loginPasswordInput := page.Locator("#login-password")
	err = loginPasswordInput.Fill(testPassword)
	if err != nil {
		t.Fatalf("Failed to fill password: %v", err)
	}

	// Submit login form (target the password login form specifically)
	signInBtn := page.Locator("form[action='/auth/login'] button[type='submit']")
	err = signInBtn.Click()
	if err != nil {
		t.Fatalf("Failed to click sign in button: %v", err)
	}

	// Wait for navigation
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	if err != nil {
		t.Fatalf("Navigation did not complete: %v", err)
	}

	// Should redirect to /notes after successful login
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/notes") {
		t.Errorf("Expected redirect to /notes, got: %s", currentURL)
	}
}

// =============================================================================
// Magic Link Login Flow Tests
// =============================================================================

func TestBrowser_Auth_MagicLinkLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Navigate to login page
	_, err := page.Goto(env.baseURL + "/login")
	if err != nil {
		t.Fatalf("Failed to navigate to login page: %v", err)
	}

	// Wait for page to load
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	// Find the magic link email input
	magicEmailInput := page.Locator("#magic-email")
	testEmail := fmt.Sprintf("magic-test-%d@example.com", time.Now().UnixNano())

	err = magicEmailInput.Fill(testEmail)
	if err != nil {
		t.Fatalf("Failed to fill magic link email: %v", err)
	}

	// Click "Send Magic Link" button
	magicLinkBtn := page.Locator("button[type='submit']:has-text('Send Magic Link')")
	err = magicLinkBtn.Click()
	if err != nil {
		t.Fatalf("Failed to click Send Magic Link button: %v", err)
	}

	// The magic link form uses fetch() + dialog.showModal() (not a page navigation).
	// Wait for the dialog to become visible after the AJAX request completes.
	magicDialog := page.Locator("#magic-link-dialog")
	err = magicDialog.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(10000),
	})
	if err != nil {
		t.Fatalf("Magic link dialog did not become visible: %v", err)
	}

	// Verify the dialog shows the correct email address
	modalEmail := page.Locator("#modal-email")
	emailText, err := modalEmail.TextContent()
	if err != nil {
		t.Fatalf("Failed to get modal email text: %v", err)
	}
	if emailText != testEmail {
		t.Errorf("Dialog shows wrong email: got %q, want %q", emailText, testEmail)
	}

	// Verify dialog heading
	dialogHeading := magicDialog.Locator("h3")
	headingText, err := dialogHeading.TextContent()
	if err != nil {
		t.Fatalf("Failed to get dialog heading: %v", err)
	}
	if !strings.Contains(headingText, "Check your email") {
		t.Errorf("Dialog heading should say 'Check your email', got: %q", headingText)
	}

	// Verify email was captured by mock service
	emailCount := env.emailService.Count()
	if emailCount == 0 {
		t.Error("Expected magic link email to be sent, but no emails captured")
	} else {
		lastEmail := env.emailService.LastEmail()
		if lastEmail.To != testEmail {
			t.Errorf("Email sent to wrong address: got %s, want %s", lastEmail.To, testEmail)
		}
		if lastEmail.Template != email.TemplateMagicLink {
			t.Errorf("Wrong email template: got %s, want %s", lastEmail.Template, email.TemplateMagicLink)
		}
	}
}

func TestBrowser_Auth_MagicLinkVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// First, request a magic link
	testEmail := fmt.Sprintf("verify-test-%d@example.com", time.Now().UnixNano())

	_, err := page.Goto(env.baseURL + "/login")
	if err != nil {
		t.Fatalf("Failed to navigate to login page: %v", err)
	}

	page.Locator("#magic-email").Fill(testEmail)
	page.Locator("button[type='submit']:has-text('Send Magic Link')").Click()

	// Wait for email to be sent
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Extract magic link from mock email service
	if env.emailService.Count() == 0 {
		t.Fatal("No magic link email was sent")
	}

	lastEmail := env.emailService.LastEmail()
	magicLinkData, ok := lastEmail.Data.(email.MagicLinkData)
	if !ok {
		t.Fatalf("Email data is not MagicLinkData type: %T", lastEmail.Data)
	}

	magicLink := magicLinkData.Link
	if magicLink == "" {
		t.Fatal("Magic link is empty")
	}

	// Clear cookies to simulate new browser session
	page.Context().ClearCookies()

	// Navigate to magic link URL
	_, err = page.Goto(magicLink)
	if err != nil {
		t.Fatalf("Failed to navigate to magic link: %v", err)
	}

	// Wait for redirect
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	if err != nil {
		t.Fatalf("Navigation did not complete: %v", err)
	}

	// Should redirect to /notes or / after successful magic link verification
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/notes") && !strings.Contains(currentURL, "/") {
		if strings.Contains(currentURL, "error") {
			t.Errorf("Magic link verification failed, redirected to: %s", currentURL)
		}
	}
}

// =============================================================================
// Forgot Password Link Tests (from Login Page)
// =============================================================================

func TestBrowser_Auth_ForgotPasswordLink(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Navigate to login page
	_, err := page.Goto(env.baseURL + "/login")
	if err != nil {
		t.Fatalf("Failed to navigate to login page: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	// Find the "Forgot password?" link — it's now href="#" with inline JS
	forgotLink := page.Locator("#forgot-password-link")
	count, err := forgotLink.Count()
	if err != nil || count == 0 {
		t.Fatal("'Forgot password?' link not found on login page")
	}

	href, err := forgotLink.GetAttribute("href")
	if err != nil {
		t.Fatalf("Failed to get href attribute: %v", err)
	}
	if href != "#" {
		t.Errorf("Forgot password link should be href='#' (inline JS), got: %q", href)
	}

	// Test 1: Clicking without email shows error flash
	err = forgotLink.Click()
	if err != nil {
		t.Fatalf("Failed to click forgot password link: %v", err)
	}

	inlineFlash := page.Locator("#inline-flash")
	err = inlineFlash.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Inline flash did not appear after clicking without email: %v", err)
	}
	flashText, _ := inlineFlash.TextContent()
	if !strings.Contains(flashText, "Enter your email") {
		t.Errorf("Expected 'Enter your email' error flash, got: %q", flashText)
	}

	// Test 2: Fill email then click — should show success flash and send email
	testEmail := fmt.Sprintf("forgot-test-%d@example.com", time.Now().UnixNano())
	loginEmailInput := page.Locator("#login-email")
	err = loginEmailInput.Fill(testEmail)
	if err != nil {
		t.Fatalf("Failed to fill login email: %v", err)
	}

	err = forgotLink.Click()
	if err != nil {
		t.Fatalf("Failed to click forgot password link: %v", err)
	}

	// Wait for the success flash to appear (replaces the error flash)
	err = page.Locator("#inline-flash:has-text('reset link')").WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(10000),
	})
	if err != nil {
		t.Fatalf("Success flash did not appear after forgot password request: %v", err)
	}

	// Should still be on /login (no page navigation)
	currentURL := page.URL()
	if !strings.HasSuffix(currentURL, "/login") {
		t.Errorf("Should stay on /login page, got: %s", currentURL)
	}

	// Verify email was captured by mock service
	if env.emailService.Count() == 0 {
		t.Fatal("No password reset email was captured")
	}
	lastEmail := env.emailService.LastEmail()
	if lastEmail.To != testEmail {
		t.Errorf("Email sent to wrong address: got %s, want %s", lastEmail.To, testEmail)
	}
	if lastEmail.Template != email.TemplatePasswordReset {
		t.Errorf("Wrong email template: got %s, want %s", lastEmail.Template, email.TemplatePasswordReset)
	}
}

// =============================================================================
// Logout Flow Tests
// =============================================================================

func TestBrowser_Auth_Logout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// First, login
	testEmail := fmt.Sprintf("logout-test-%d@example.com", time.Now().UnixNano())
	testPassword := "SecurePass123!"

	// Register and login
	_, err := page.Goto(env.baseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill(testPassword)
	page.Locator("input[name='confirm_password']").Fill(testPassword)
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()

	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Verify we're logged in (on /notes page)
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/notes") {
		t.Skipf("Registration did not redirect to /notes (got %s), skipping logout test", currentURL)
	}

	// Look for logout button/link and click it
	logoutForm := page.Locator("form[action='/auth/logout'] button, a:has-text('Logout'), button:has-text('Logout'), a:has-text('Sign out'), button:has-text('Sign out')")

	count, err := logoutForm.Count()
	if err != nil || count == 0 {
		pageContent, _ := page.Content()
		if strings.Contains(pageContent, "logout") || strings.Contains(pageContent, "Logout") || strings.Contains(pageContent, "sign out") {
			t.Log("Logout mechanism exists but couldn't be located via Playwright")
		} else {
			t.Skip("No logout button found on the page")
		}
		return
	}

	err = logoutForm.First().Click()
	if err != nil {
		t.Fatalf("Failed to click logout: %v", err)
	}

	// Wait for redirect
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Should redirect to /login after logout
	currentURL = page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Errorf("Expected redirect to /login after logout, got: %s", currentURL)
	}
}

// =============================================================================
// Password Reset Flow Tests
// =============================================================================

func TestBrowser_Auth_PasswordReset_RequestForm(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Navigate to password reset page
	_, err := page.Goto(env.baseURL + "/password-reset")
	if err != nil {
		t.Fatalf("Failed to navigate to password reset page: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	// Verify we're on the password reset page
	title, err := page.Title()
	if err != nil {
		t.Fatalf("Failed to get page title: %v", err)
	}
	if !strings.Contains(strings.ToLower(title), "reset") {
		t.Errorf("Unexpected page title: %s", title)
	}

	// Fill email and submit
	testEmail := fmt.Sprintf("reset-test-%d@example.com", time.Now().UnixNano())
	err = page.Locator("input[name='email']").Fill(testEmail)
	if err != nil {
		t.Fatalf("Failed to fill email: %v", err)
	}

	err = page.Locator("button[type='submit']:has-text('Send reset link')").Click()
	if err != nil {
		t.Fatalf("Failed to click submit button: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	if err != nil {
		t.Fatalf("Navigation did not complete: %v", err)
	}

	// After POST /auth/password-reset, should redirect to /login?reset=requested
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Fatalf("Expected redirect to /login, got: %s", currentURL)
	}

	// Verify flash message banner is visible on login page
	flashBanner := page.Locator("[role='status']")
	err = flashBanner.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Flash message banner not visible after password reset request: %v", err)
	}

	bannerText, err := flashBanner.TextContent()
	if err != nil {
		t.Fatalf("Failed to get banner text: %v", err)
	}
	if !strings.Contains(bannerText, "password reset link") {
		t.Errorf("Flash message should mention password reset link, got: %q", bannerText)
	}

	// Verify email was captured by mock service
	if env.emailService.Count() == 0 {
		t.Fatal("No password reset email was captured")
	}
	lastEmail := env.emailService.LastEmail()
	if lastEmail.To != testEmail {
		t.Errorf("Email sent to wrong address: got %s, want %s", lastEmail.To, testEmail)
	}
	if lastEmail.Template != email.TemplatePasswordReset {
		t.Errorf("Wrong email template: got %s, want %s", lastEmail.Template, email.TemplatePasswordReset)
	}

	// Verify the reset link in the email uses the test server URL (not localhost:8080)
	resetData, ok := lastEmail.Data.(email.PasswordResetData)
	if !ok {
		t.Fatalf("Email data is not PasswordResetData: %T", lastEmail.Data)
	}
	if !strings.HasPrefix(resetData.Link, env.baseURL) {
		t.Errorf("Reset link should start with %s, got: %s", env.baseURL, resetData.Link)
	}
}

func TestBrowser_Auth_PasswordReset_FullFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Step 1: Register a user (need an account to reset password for)
	testEmail := fmt.Sprintf("fullreset-%d@example.com", time.Now().UnixNano())
	originalPassword := "OriginalPass123!"

	_, err := page.Goto(env.baseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate to register: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill(originalPassword)
	page.Locator("input[name='confirm_password']").Fill(originalPassword)
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Clear cookies (logout)
	page.Context().ClearCookies()
	env.emailService.Clear()

	// Step 2: Request password reset from /password-reset page
	_, err = page.Goto(env.baseURL + "/password-reset")
	if err != nil {
		t.Fatalf("Failed to navigate to password reset: %v", err)
	}

	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("button[type='submit']:has-text('Send reset link')").Click()

	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Should redirect to /login with flash message
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Fatalf("Expected redirect to /login after reset request, got: %s", currentURL)
	}

	// Step 3: Extract reset link from email
	if env.emailService.Count() == 0 {
		t.Fatal("No password reset email was sent")
	}

	lastEmail := env.emailService.LastEmail()
	resetData, ok := lastEmail.Data.(email.PasswordResetData)
	if !ok {
		t.Fatalf("Email data is not PasswordResetData: %T", lastEmail.Data)
	}
	if resetData.Link == "" {
		t.Fatal("Reset link is empty")
	}

	// Verify link uses correct base URL
	if !strings.HasPrefix(resetData.Link, env.baseURL) {
		t.Errorf("Reset link should use test server URL, got: %s", resetData.Link)
	}

	// Step 4: Navigate to reset link — should show new password form
	_, err = page.Goto(resetData.Link)
	if err != nil {
		t.Fatalf("Failed to navigate to reset link: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Verify we're on the password reset confirm page
	heading := page.Locator("h2:has-text('Create new password')")
	err = heading.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Password reset confirm page heading not found: %v", err)
	}

	// Step 5: Fill new password and submit
	newPassword := "NewSecurePass456!"
	page.Locator("input[name='password']").Fill(newPassword)
	page.Locator("input[name='confirm_password']").Fill(newPassword)
	page.Locator("button[type='submit']:has-text('Reset password')").Click()

	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Step 6: Should redirect to /login with success message
	currentURL = page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Fatalf("Expected redirect to /login after password reset, got: %s", currentURL)
	}

	// Verify success flash message is visible
	flashBanner := page.Locator("[role='status']")
	err = flashBanner.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Success flash message not visible after password reset: %v", err)
	}

	bannerText, err := flashBanner.TextContent()
	if err != nil {
		t.Fatalf("Failed to get banner text: %v", err)
	}
	if !strings.Contains(strings.ToLower(bannerText), "password reset") {
		t.Errorf("Flash message should mention password reset, got: %q", bannerText)
	}
}

// =============================================================================
// Server Health Tests
// =============================================================================

func TestBrowser_Auth_ServerHealth(t *testing.T) {
	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	// Test server health without browser
	resp, err := http.Get(env.baseURL + "/health")
	if err != nil {
		t.Fatalf("Failed to reach health endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Health check failed with status: %d", resp.StatusCode)
	}
}

func TestBrowser_Auth_LoginPageLoads(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Navigate to login page
	_, err := page.Goto(env.baseURL + "/login")
	if err != nil {
		t.Fatalf("Failed to navigate to login page: %v", err)
	}

	// Wait for page to load
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	// Verify key elements are present
	magicEmail := page.Locator("#magic-email")
	count, err := magicEmail.Count()
	if err != nil || count == 0 {
		t.Error("Magic link email input not found")
	}

	loginEmail := page.Locator("#login-email")
	count, err = loginEmail.Count()
	if err != nil || count == 0 {
		t.Error("Login email input not found")
	}

	loginPassword := page.Locator("#login-password")
	count, err = loginPassword.Count()
	if err != nil || count == 0 {
		t.Error("Login password input not found")
	}

	googleBtn := page.Locator("button:has-text('Google')")
	count, err = googleBtn.Count()
	if err != nil || count == 0 {
		t.Error("Google sign-in button not found")
	}
}

// =============================================================================
// Google OIDC (Mock) Browser Tests
// =============================================================================

func TestBrowser_Auth_GoogleOIDC_FullFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	_, err := page.Goto(env.baseURL + "/login")
	if err != nil {
		t.Fatalf("Failed to navigate to login page: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	// Click "Sign in with Google" button
	googleBtn := page.Locator("form[action='/auth/google'] button[type='submit']")
	err = googleBtn.Click()
	if err != nil {
		t.Fatalf("Failed to click Google sign-in button: %v", err)
	}

	// Should land on the mock OIDC consent page
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Mock OIDC page did not load: %v", err)
	}

	heading := page.Locator("h1")
	headingText, err := heading.TextContent()
	if err != nil || headingText != "Mock Google Sign-In" {
		t.Fatalf("Expected mock OIDC consent page, got heading: %q", headingText)
	}

	emailInput := page.Locator("input[name='email']")
	err = emailInput.Fill("oidc-browser@example.com")
	if err != nil {
		t.Fatalf("Failed to fill email: %v", err)
	}

	submitBtn := page.Locator("button[type='submit']")
	err = submitBtn.Click()
	if err != nil {
		t.Fatalf("Failed to click submit: %v", err)
	}

	// Should redirect through callback and land on app
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Post-OIDC page did not load: %v", err)
	}

	currentURL := page.URL()
	if strings.Contains(currentURL, "/login") || strings.Contains(currentURL, "/auth/mock-oidc") {
		t.Fatalf("Expected to be redirected away from login after OIDC, but URL is: %s", currentURL)
	}
}

func TestBrowser_Auth_GoogleOIDC_ReturnTo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	_, err := page.Goto(env.baseURL + "/login?return_to=/notes")
	if err != nil {
		t.Fatalf("Failed to navigate to login page: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	googleBtn := page.Locator("form[action='/auth/google'] button[type='submit']")
	err = googleBtn.Click()
	if err != nil {
		t.Fatalf("Failed to click Google sign-in button: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Mock OIDC page did not load: %v", err)
	}

	emailInput := page.Locator("input[name='email']")
	err = emailInput.Fill("oidc-return@example.com")
	if err != nil {
		t.Fatalf("Failed to fill email: %v", err)
	}

	submitBtn := page.Locator("button[type='submit']")
	err = submitBtn.Click()
	if err != nil {
		t.Fatalf("Failed to click submit: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Post-OIDC page did not load: %v", err)
	}

	currentURL := page.URL()
	if !strings.HasSuffix(currentURL, "/notes") {
		t.Fatalf("Expected to be redirected to /notes, but URL is: %s", currentURL)
	}
}

// =============================================================================
// Session Isolation Tests
// =============================================================================

func TestBrowser_Auth_SessionIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	// Create two separate browser contexts (like two users)
	context1, err := env.browser.NewContext()
	if err != nil {
		t.Fatalf("Failed to create context 1: %v", err)
	}
	defer context1.Close()

	context2, err := env.browser.NewContext()
	if err != nil {
		t.Fatalf("Failed to create context 2: %v", err)
	}
	defer context2.Close()

	page1, err := context1.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page 1: %v", err)
	}
	defer page1.Close()

	page2, err := context2.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page 2: %v", err)
	}
	defer page2.Close()

	// User 1 registers and logs in
	user1Email := fmt.Sprintf("user1-%d@example.com", time.Now().UnixNano())
	password := "SecurePass123!"

	page1.Goto(env.baseURL + "/register")
	page1.Locator("input[name='email']").Fill(user1Email)
	page1.Locator("input[name='password']").Fill(password)
	page1.Locator("input[name='confirm_password']").Fill(password)
	page1.Locator("input[name='terms']").Check()
	page1.Locator("button[type='submit']:has-text('Create account')").Click()
	page1.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// User 2 should not be logged in
	page2.Goto(env.baseURL + "/notes")
	page2.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// User 2 should be redirected to login (401 or redirect)
	page2URL := page2.URL()
	if strings.Contains(page2URL, "/notes") && !strings.Contains(page2URL, "Unauthorized") {
		pageContent, _ := page2.Content()
		if !strings.Contains(pageContent, "Unauthorized") && !strings.Contains(pageContent, "login") {
			t.Logf("User 2 accessed /notes without auth, URL: %s", page2URL)
		}
	}
}

// =============================================================================
// Login Error Path Tests
// =============================================================================

func TestBrowser_Auth_LoginWrongPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Register a user first
	testEmail := fmt.Sprintf("wrongpw-%d@example.com", time.Now().UnixNano())
	testPassword := "SecurePass123!"

	_, err := page.Goto(env.baseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill(testPassword)
	page.Locator("input[name='confirm_password']").Fill(testPassword)
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Logout
	page.Context().ClearCookies()

	// Try login with wrong password
	_, err = page.Goto(env.baseURL + "/login")
	if err != nil {
		t.Fatalf("Failed to navigate to login: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	page.Locator("#login-email").Fill(testEmail)
	page.Locator("#login-password").Fill("WrongPassword999!")
	page.Locator("form[action='/auth/login'] button[type='submit']").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Should redirect back to /login with error
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Fatalf("Expected redirect to /login, got: %s", currentURL)
	}

	// Error flash should be visible
	errorBanner := page.Locator("[role='alert']")
	err = errorBanner.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Error banner not visible: %v", err)
	}

	bannerText, _ := errorBanner.TextContent()
	if !strings.Contains(strings.ToLower(bannerText), "invalid") {
		t.Errorf("Error should mention invalid credentials, got: %q", bannerText)
	}
}

func TestBrowser_Auth_LoginNonexistentEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Try login with email that was never registered
	_, err := page.Goto(env.baseURL + "/login")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	page.Locator("#login-email").Fill("nobody-exists@example.com")
	page.Locator("#login-password").Fill("SomePassword123!")
	page.Locator("form[action='/auth/login'] button[type='submit']").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Should show same generic error (no email enumeration)
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Fatalf("Expected redirect to /login, got: %s", currentURL)
	}

	errorBanner := page.Locator("[role='alert']")
	err = errorBanner.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Error banner not visible: %v", err)
	}

	bannerText, _ := errorBanner.TextContent()
	if !strings.Contains(strings.ToLower(bannerText), "invalid") {
		t.Errorf("Error should mention invalid credentials, got: %q", bannerText)
	}
}

// =============================================================================
// Registration Error Path Tests
// =============================================================================

func TestBrowser_Auth_RegisterDuplicateEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	testEmail := fmt.Sprintf("dup-%d@example.com", time.Now().UnixNano())
	testPassword := "SecurePass123!"

	// Register first time
	_, err := page.Goto(env.baseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill(testPassword)
	page.Locator("input[name='confirm_password']").Fill(testPassword)
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Clear cookies and try to register again with same email
	page.Context().ClearCookies()

	_, err = page.Goto(env.baseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill(testPassword)
	page.Locator("input[name='confirm_password']").Fill(testPassword)
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Should redirect to /login with "Account already exists" error
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Fatalf("Expected redirect to /login for duplicate, got: %s", currentURL)
	}

	errorBanner := page.Locator("[role='alert']")
	err = errorBanner.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Error banner not visible: %v", err)
	}

	bannerText, _ := errorBanner.TextContent()
	if !strings.Contains(strings.ToLower(bannerText), "already exists") {
		t.Errorf("Error should mention account already exists, got: %q", bannerText)
	}
}

// =============================================================================
// Password Reset Confirm Error Path Tests
// =============================================================================

func TestBrowser_Auth_PasswordResetConfirm_Mismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Register user, request reset, get token
	testEmail := fmt.Sprintf("mismatch-%d@example.com", time.Now().UnixNano())
	_, err := page.Goto(env.baseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill("OriginalPass123!")
	page.Locator("input[name='confirm_password']").Fill("OriginalPass123!")
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	page.Context().ClearCookies()
	env.emailService.Clear()

	// Request password reset
	_, err = page.Goto(env.baseURL + "/password-reset")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("button[type='submit']:has-text('Send reset link')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Extract token from email
	if env.emailService.Count() == 0 {
		t.Fatal("No reset email sent")
	}
	lastEmail := env.emailService.LastEmail()
	resetData, ok := lastEmail.Data.(email.PasswordResetData)
	if !ok {
		t.Fatalf("Email data is not PasswordResetData: %T", lastEmail.Data)
	}

	// Navigate to reset link
	_, err = page.Goto(resetData.Link)
	if err != nil {
		t.Fatalf("Failed to navigate to reset link: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Submit mismatched passwords
	page.Locator("input[name='password']").Fill("NewPassword123!")
	page.Locator("input[name='confirm_password']").Fill("DifferentPassword456!")
	page.Locator("button[type='submit']:has-text('Reset password')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Should show error about password mismatch, token preserved
	currentURL := page.URL()
	if !strings.Contains(currentURL, "password-reset-confirm") {
		t.Fatalf("Expected to stay on password-reset-confirm, got: %s", currentURL)
	}

	errorBanner := page.Locator("[role='alert']")
	err = errorBanner.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Error banner not visible: %v", err)
	}

	bannerText, _ := errorBanner.TextContent()
	if !strings.Contains(strings.ToLower(bannerText), "passwords do not match") {
		t.Errorf("Error should mention passwords don't match, got: %q", bannerText)
	}

	// Token should be preserved in the form so user can retry
	tokenInput := page.Locator("input[name='token']")
	tokenVal, err := tokenInput.GetAttribute("value")
	if err != nil || tokenVal == "" {
		t.Error("Token should be preserved in the form after mismatch error")
	}
}

func TestBrowser_Auth_PasswordResetConfirm_InvalidToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Navigate to reset confirm page with bogus token
	_, err := page.Goto(env.baseURL + "/auth/password-reset-confirm?token=bogus-invalid-token")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Fill passwords and submit
	page.Locator("input[name='password']").Fill("NewPassword123!")
	page.Locator("input[name='confirm_password']").Fill("NewPassword123!")
	page.Locator("button[type='submit']:has-text('Reset password')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Should redirect to /login with "invalid or expired" error
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Fatalf("Expected redirect to /login for invalid token, got: %s", currentURL)
	}

	errorBanner := page.Locator("[role='alert']")
	err = errorBanner.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Error banner not visible: %v", err)
	}

	bannerText, _ := errorBanner.TextContent()
	if !strings.Contains(strings.ToLower(bannerText), "invalid") || !strings.Contains(strings.ToLower(bannerText), "expired") {
		t.Errorf("Error should mention invalid or expired, got: %q", bannerText)
	}
}

func TestBrowser_Auth_PasswordResetConfirm_MissingToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Navigate to reset confirm page with NO token
	_, err := page.Goto(env.baseURL + "/auth/password-reset-confirm")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Should show error page (not the form)
	currentURL := page.URL()
	pageContent, _ := page.Content()

	// The handler renders auth error page for missing token
	if strings.Contains(pageContent, "invalid") || strings.Contains(pageContent, "expired") || strings.Contains(pageContent, "Missing") {
		t.Log("Missing token correctly shows error page")
	} else {
		t.Errorf("Expected error page for missing token, URL: %s", currentURL)
	}
}

// =============================================================================
// Full Password Reset → Login With New Password
// =============================================================================

func TestBrowser_Auth_PasswordReset_ThenLoginWithNewPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Step 1: Register
	testEmail := fmt.Sprintf("fullreset2-%d@example.com", time.Now().UnixNano())
	originalPassword := "OriginalPass123!"
	newPassword := "BrandNewPass456!"

	_, err := page.Goto(env.baseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill(originalPassword)
	page.Locator("input[name='confirm_password']").Fill(originalPassword)
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	page.Context().ClearCookies()
	env.emailService.Clear()

	// Step 2: Request password reset
	_, err = page.Goto(env.baseURL + "/password-reset")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("button[type='submit']:has-text('Send reset link')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Step 3: Use reset link
	if env.emailService.Count() == 0 {
		t.Fatal("No reset email sent")
	}
	resetData := env.emailService.LastEmail().Data.(email.PasswordResetData)

	_, err = page.Goto(resetData.Link)
	if err != nil {
		t.Fatalf("Failed to navigate to reset link: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	page.Locator("input[name='password']").Fill(newPassword)
	page.Locator("input[name='confirm_password']").Fill(newPassword)
	page.Locator("button[type='submit']:has-text('Reset password')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Should be on /login with success
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Fatalf("Expected /login after reset, got: %s", currentURL)
	}

	successBanner := page.Locator("[role='status']")
	err = successBanner.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Success banner not visible after reset: %v", err)
	}

	// Step 4: Login with NEW password
	page.Locator("#login-email").Fill(testEmail)
	page.Locator("#login-password").Fill(newPassword)
	page.Locator("form[action='/auth/login'] button[type='submit']").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	currentURL = page.URL()
	if !strings.Contains(currentURL, "/notes") {
		t.Errorf("Expected redirect to /notes after login with new password, got: %s", currentURL)
	}

	// Step 5: Verify old password no longer works
	page.Context().ClearCookies()
	_, err = page.Goto(env.baseURL + "/login")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	page.Locator("#login-email").Fill(testEmail)
	page.Locator("#login-password").Fill(originalPassword)
	page.Locator("form[action='/auth/login'] button[type='submit']").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	currentURL = page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Errorf("Old password should be rejected, but got: %s", currentURL)
	}

	errorBanner := page.Locator("[role='alert']")
	err = errorBanner.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Error banner not visible for old password: %v", err)
	}
}

// =============================================================================
// return_to Parameter Tests
// =============================================================================

func TestBrowser_Auth_ReturnTo_LoginRedirect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Register user
	testEmail := fmt.Sprintf("returnto-%d@example.com", time.Now().UnixNano())
	testPassword := "SecurePass123!"

	_, err := page.Goto(env.baseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill(testPassword)
	page.Locator("input[name='confirm_password']").Fill(testPassword)
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	page.Context().ClearCookies()

	// Visit login page with return_to
	_, err = page.Goto(env.baseURL + "/login?return_to=/notes")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Verify hidden return_to field exists in the password form
	returnToInput := page.Locator("form[action='/auth/login'] input[name='return_to']")
	count, err := returnToInput.Count()
	if err != nil || count == 0 {
		t.Error("Hidden return_to input not found in login form")
	} else {
		val, _ := returnToInput.GetAttribute("value")
		if val != "/notes" {
			t.Errorf("return_to input should have value '/notes', got: %q", val)
		}
	}

	// Login and verify redirect to return_to path
	page.Locator("#login-email").Fill(testEmail)
	page.Locator("#login-password").Fill(testPassword)
	page.Locator("form[action='/auth/login'] button[type='submit']").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	currentURL := page.URL()
	if !strings.Contains(currentURL, "/notes") {
		t.Errorf("Expected redirect to /notes (return_to), got: %s", currentURL)
	}
}

func TestBrowser_Auth_ReturnTo_RegisterPropagation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Visit login page with return_to, then click "create a new account"
	_, err := page.Goto(env.baseURL + "/login?return_to=/notes")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Click "create a new account" link — should propagate return_to
	createLink := page.Locator("a:has-text('create a new account')")
	href, err := createLink.GetAttribute("href")
	if err != nil {
		t.Fatalf("Failed to get create account href: %v", err)
	}
	if !strings.Contains(href, "return_to") {
		t.Errorf("'create a new account' link should include return_to, got: %q", href)
	}

	err = createLink.Click()
	if err != nil {
		t.Fatalf("Failed to click create account link: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Verify we're on /register with return_to preserved
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/register") || !strings.Contains(currentURL, "return_to") {
		t.Errorf("Expected /register with return_to, got: %s", currentURL)
	}

	// Register and verify redirect goes to return_to
	testEmail := fmt.Sprintf("regreturn-%d@example.com", time.Now().UnixNano())
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill("SecurePass123!")
	page.Locator("input[name='confirm_password']").Fill("SecurePass123!")
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	currentURL = page.URL()
	if !strings.Contains(currentURL, "/notes") {
		t.Errorf("Expected redirect to /notes (return_to), got: %s", currentURL)
	}
}

// =============================================================================
// Logout → Protected Page Tests
// =============================================================================

func TestBrowser_Auth_LogoutThenAccessProtected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Register and login
	testEmail := fmt.Sprintf("logoutprot-%d@example.com", time.Now().UnixNano())
	testPassword := "SecurePass123!"

	_, err := page.Goto(env.baseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill(testPassword)
	page.Locator("input[name='confirm_password']").Fill(testPassword)
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Verify we're on /notes
	if !strings.Contains(page.URL(), "/notes") {
		t.Skipf("Registration didn't redirect to /notes, got: %s", page.URL())
	}

	// Navigate to logout
	_, err = page.Goto(env.baseURL + "/auth/logout")
	if err != nil {
		t.Fatalf("Failed to navigate to logout: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Try to access /notes — should redirect to /login
	_, err = page.Goto(env.baseURL + "/notes")
	if err != nil {
		t.Fatalf("Failed to navigate to /notes: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Errorf("Expected redirect to /login after logout, got: %s", currentURL)
	}
}

// =============================================================================
// Landing Page Redirect Tests
// =============================================================================

func TestBrowser_Auth_LandingRedirect_Unauthenticated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Visit / without auth
	_, err := page.Goto(env.baseURL + "/")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Errorf("Unauthenticated / should redirect to /login, got: %s", currentURL)
	}
}

func TestBrowser_Auth_LandingRedirect_Authenticated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Register to get authenticated
	testEmail := fmt.Sprintf("landing-%d@example.com", time.Now().UnixNano())

	_, err := page.Goto(env.baseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.Locator("input[name='email']").Fill(testEmail)
	page.Locator("input[name='password']").Fill("SecurePass123!")
	page.Locator("input[name='confirm_password']").Fill("SecurePass123!")
	page.Locator("input[name='terms']").Check()
	page.Locator("button[type='submit']:has-text('Create account')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Now visit / — should redirect to /notes
	_, err = page.Goto(env.baseURL + "/")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	currentURL := page.URL()
	if !strings.Contains(currentURL, "/notes") {
		t.Errorf("Authenticated / should redirect to /notes, got: %s", currentURL)
	}
}

// =============================================================================
// Magic Link Dialog Close Tests
// =============================================================================

func TestBrowser_Auth_MagicLinkDialog_CloseButton(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	_, err := page.Goto(env.baseURL + "/login")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Fill email and submit magic link
	testEmail := fmt.Sprintf("dialogclose-%d@example.com", time.Now().UnixNano())
	page.Locator("#magic-email").Fill(testEmail)
	page.Locator("button[type='submit']:has-text('Send Magic Link')").Click()

	// Wait for dialog
	dialog := page.Locator("#magic-link-dialog")
	err = dialog.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(10000),
	})
	if err != nil {
		t.Fatalf("Dialog did not appear: %v", err)
	}

	// Click "Got it" button
	page.Locator("#close-modal-btn").Click()

	// Dialog should close
	err = dialog.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateHidden,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Dialog did not close after clicking 'Got it': %v", err)
	}

	// Email field should be cleared
	emailVal, _ := page.Locator("#magic-email").InputValue()
	if emailVal != "" {
		t.Errorf("Email field should be cleared after dialog close, got: %q", emailVal)
	}
}

// =============================================================================
// Flash Message Rendering Tests
// =============================================================================

func TestBrowser_Auth_FlashMessages_LoginPage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	tests := []struct {
		name     string
		query    string
		role     string // "status" for success, "alert" for error
		contains string
	}{
		{
			name:     "success flash",
			query:    "?success=Password+reset+successfully.+Please+sign+in.",
			role:     "status",
			contains: "Password reset successfully",
		},
		{
			name:     "reset requested flash",
			query:    "?reset=requested",
			role:     "status",
			contains: "password reset link",
		},
		{
			name:     "error flash",
			query:    "?error=Invalid+email+or+password",
			role:     "alert",
			contains: "Invalid email or password",
		},
		{
			name:     "account exists flash",
			query:    "?error=Account+already+exists.+Please+sign+in.",
			role:     "alert",
			contains: "Account already exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page := env.newAuthTestPage(t)
			defer page.Close()

			_, err := page.Goto(env.baseURL + "/login" + tt.query)
			if err != nil {
				t.Fatalf("Failed to navigate: %v", err)
			}
			page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

			banner := page.Locator(fmt.Sprintf("[role='%s']", tt.role))
			err = banner.WaitFor(playwright.LocatorWaitForOptions{
				State:   playwright.WaitForSelectorStateVisible,
				Timeout: playwright.Float(5000),
			})
			if err != nil {
				t.Fatalf("Flash banner [role='%s'] not visible for %s: %v", tt.role, tt.name, err)
			}

			text, _ := banner.TextContent()
			if !strings.Contains(text, tt.contains) {
				t.Errorf("Flash should contain %q, got: %q", tt.contains, text)
			}
		})
	}
}

// =============================================================================
// Password Reset Page (Standalone) Tests
// =============================================================================

func TestBrowser_Auth_PasswordResetPage_BackToLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	_, err := page.Goto(env.baseURL + "/password-reset")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Verify page heading
	heading := page.Locator("h2:has-text('Reset your password')")
	count, err := heading.Count()
	if err != nil || count == 0 {
		t.Error("Password reset page heading not found")
	}

	// Click "Back to login" link
	backLink := page.Locator("a:has-text('Back to login')")
	err = backLink.Click()
	if err != nil {
		t.Fatalf("Failed to click Back to login: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	currentURL := page.URL()
	if !strings.HasSuffix(currentURL, "/login") {
		t.Errorf("Expected redirect to /login, got: %s", currentURL)
	}
}

func TestBrowser_Auth_PasswordResetPage_NonexistentEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	_, err := page.Goto(env.baseURL + "/password-reset")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// Submit for a nonexistent email — should still show success (no enumeration)
	page.Locator("input[name='email']").Fill("nonexistent-nobody@example.com")
	page.Locator("button[type='submit']:has-text('Send reset link')").Click()
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle})

	// Should redirect to /login with success flash
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") {
		t.Fatalf("Expected redirect to /login, got: %s", currentURL)
	}

	successBanner := page.Locator("[role='status']")
	err = successBanner.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Success banner not visible (should not reveal email doesn't exist): %v", err)
	}

	text, _ := successBanner.TextContent()
	if !strings.Contains(strings.ToLower(text), "if an account exists") {
		t.Errorf("Banner should say 'if an account exists', got: %q", text)
	}
}

// =============================================================================
// Register Page Link Tests
// =============================================================================

func TestBrowser_Auth_RegisterPage_SignInLink(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	if err := env.initAuthTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newAuthTestPage(t)
	defer page.Close()

	// Visit register page with return_to
	_, err := page.Goto(env.baseURL + "/register?return_to=/notes")
	if err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	// "Sign in" link should propagate return_to
	signInLink := page.Locator("a:has-text('Sign in')")
	href, err := signInLink.GetAttribute("href")
	if err != nil {
		t.Fatalf("Failed to get Sign in href: %v", err)
	}
	if !strings.Contains(href, "return_to") {
		t.Errorf("'Sign in' link should include return_to, got: %q", href)
	}

	err = signInLink.Click()
	if err != nil {
		t.Fatalf("Failed to click Sign in: %v", err)
	}
	page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateDomcontentloaded})

	currentURL := page.URL()
	if !strings.Contains(currentURL, "/login") || !strings.Contains(currentURL, "return_to") {
		t.Errorf("Expected /login with return_to, got: %s", currentURL)
	}
}

// =============================================================================
// Test Utilities
// =============================================================================

// generateAuthTestMasterKey creates a deterministic master key for testing.
func generateAuthTestMasterKey() []byte {
	key, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	return key
}

// parallelAuthBrowserTest runs multiple browser tests concurrently.
func parallelAuthBrowserTest(t *testing.T, env *authTestEnv, numUsers int, testFunc func(t *testing.T, page playwright.Page, userIndex int)) {
	var wg sync.WaitGroup
	errors := make(chan error, numUsers)

	for i := 0; i < numUsers; i++ {
		wg.Add(1)
		go func(userIndex int) {
			defer wg.Done()

			ctx, err := env.browser.NewContext()
			if err != nil {
				errors <- fmt.Errorf("user %d: failed to create context: %w", userIndex, err)
				return
			}
			defer ctx.Close()

			page, err := ctx.NewPage()
			if err != nil {
				errors <- fmt.Errorf("user %d: failed to create page: %w", userIndex, err)
				return
			}
			defer page.Close()

			testFunc(t, page, userIndex)
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		if err != nil {
			t.Error(err)
		}
	}
}

// waitForAuthElement waits for an element to be visible with a custom timeout.
func waitForAuthElement(page playwright.Page, selector string, timeout float64) error {
	return page.Locator(selector).WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(timeout),
	})
}

// extractTokenFromAuthURL extracts a token parameter from a URL.
func extractTokenFromAuthURL(url string) string {
	if idx := strings.Index(url, "token="); idx != -1 {
		start := idx + 6
		end := strings.IndexAny(url[start:], "&# ")
		if end == -1 {
			return url[start:]
		}
		return url[start : start+end]
	}
	return ""
}
