// Package browser contains Playwright E2E tests for static pages.
// These tests verify that privacy and terms links appear on all pages
// and that static pages load correctly.
package browser

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

// staticTestEnv encapsulates the test environment for static page tests.
type staticTestEnv struct {
	server   *httptest.Server
	s3Server *httptest.Server
	pw       *playwright.Playwright
	browser  playwright.Browser
	baseURL  string
}

// setupStaticTestEnv creates a test server for static page testing.
func setupStaticTestEnv(t *testing.T) (*staticTestEnv, func()) {
	t.Helper()

	// Reset database singleton and set fresh data directory
	db.ResetForTesting()
	db.DataDirectory = t.TempDir()

	// Initialize sessions database
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
	s3Client, s3Server := createStaticTestS3(t)

	// Initialize template renderer
	templatesDir := findStaticTestTemplatesDir()
	renderer, err := web.NewRenderer(templatesDir)
	if err != nil {
		t.Fatalf("Failed to create renderer: %v", err)
	}

	// Create server first to get URL
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	// Initialize services
	userService := auth.NewUserService(sessionsDB, emailService, server.URL)
	sessionService := auth.NewSessionService(sessionsDB)
	consentService := auth.NewConsentService(sessionsDB)
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

	// Initialize web handler (pass nil for shortURLSvc since it's not needed for static page tests)
	webHandler := web.NewWebHandler(
		renderer,
		nil,
		publicNotes,
		userService,
		sessionService,
		consentService,
		s3Client,
		nil, // shortURLSvc not needed for static page tests
		server.URL,
	)

	// Close old server and create new mux
	server.Close()
	mux = http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// Register routes
	webHandler.RegisterRoutes(mux, authMiddleware)

	// Initialize and register static page handler
	staticGenDir := findStaticGenDir()
	staticSrcDir := findStaticSrcDir()
	staticHandler := web.NewStaticHandler(renderer, staticGenDir, staticSrcDir)
	staticHandler.RegisterRoutes(mux)

	// Create final test server
	server = httptest.NewServer(mux)

	env := &staticTestEnv{
		server:   server,
		s3Server: s3Server,
		baseURL:  server.URL,
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

// createStaticTestS3 creates a mock S3 server.
func createStaticTestS3(t *testing.T) (*s3client.Client, *httptest.Server) {
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

	bucketName := "static-test-bucket"
	_, err = s3SDK.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Fatalf("Failed to create mock S3 bucket: %v", err)
	}

	client := s3client.NewFromS3Client(s3SDK, bucketName, ts.URL+"/"+bucketName)
	return client, ts
}

// findStaticTestTemplatesDir locates the templates directory.
func findStaticTestTemplatesDir() string {
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

// findStaticGenDir locates the generated static pages directory.
func findStaticGenDir() string {
	candidates := []string{
		"../../static/gen",
		"../../../static/gen",
		"static/gen",
		"/home/kuitang/git/agent-notes/static/gen",
	}

	for _, dir := range candidates {
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}

	return "/home/kuitang/git/agent-notes/static/gen"
}

// findStaticSrcDir locates the source markdown directory.
func findStaticSrcDir() string {
	candidates := []string{
		"../../static/src",
		"../../../static/src",
		"static/src",
		"/home/kuitang/git/agent-notes/static/src",
	}

	for _, dir := range candidates {
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}

	return "/home/kuitang/git/agent-notes/static/src"
}

// initStaticTestBrowser initializes Playwright.
func (env *staticTestEnv) initStaticTestBrowser(t *testing.T) error {
	t.Helper()

	pw, err := playwright.Run()
	if err != nil {
		return err
	}
	env.pw = pw

	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
	})
	if err != nil {
		pw.Stop()
		return err
	}
	env.browser = browser

	return nil
}

// newStaticTestPage creates a new browser page.
func (env *staticTestEnv) newStaticTestPage(t *testing.T) playwright.Page {
	t.Helper()

	page, err := env.browser.NewPage()
	if err != nil {
		t.Fatalf("could not create page: %v", err)
	}

	page.SetDefaultTimeout(10000)

	return page
}

// =============================================================================
// Footer Links Tests
// =============================================================================

// TestBrowser_Static_FooterLinksOnLoginPage verifies Privacy and Terms links appear on the login page.
func TestBrowser_Static_FooterLinksOnLoginPage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupStaticTestEnv(t)
	defer cleanup()

	if err := env.initStaticTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newStaticTestPage(t)
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

	// Check for Privacy link
	privacyLink := page.Locator("footer a[href='/privacy']")
	count, err := privacyLink.Count()
	if err != nil || count == 0 {
		t.Error("Privacy link not found in footer")
	}

	// Check for Terms link
	termsLink := page.Locator("footer a[href='/terms']")
	count, err = termsLink.Count()
	if err != nil || count == 0 {
		t.Error("Terms link not found in footer")
	}

	// Check for About link
	aboutLink := page.Locator("footer a[href='/about']")
	count, err = aboutLink.Count()
	if err != nil || count == 0 {
		t.Error("About link not found in footer")
	}

	// Check for API Docs link
	docsLink := page.Locator("footer a[href='/docs']")
	count, err = docsLink.Count()
	if err != nil || count == 0 {
		t.Error("API Docs link not found in footer")
	}
}

// TestBrowser_Static_FooterLinksOnRegisterPage verifies footer links appear on the register page.
func TestBrowser_Static_FooterLinksOnRegisterPage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupStaticTestEnv(t)
	defer cleanup()

	if err := env.initStaticTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newStaticTestPage(t)
	defer page.Close()

	// Navigate to register page
	_, err := page.Goto(env.baseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to navigate to register page: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	// Check for Privacy link
	privacyLink := page.Locator("footer a[href='/privacy']")
	count, err := privacyLink.Count()
	if err != nil || count == 0 {
		t.Error("Privacy link not found in footer on register page")
	}

	// Check for Terms link
	termsLink := page.Locator("footer a[href='/terms']")
	count, err = termsLink.Count()
	if err != nil || count == 0 {
		t.Error("Terms link not found in footer on register page")
	}
}

// =============================================================================
// Static Page Content Tests
// =============================================================================

// TestBrowser_Static_PrivacyPageLoads verifies the privacy policy page loads correctly.
func TestBrowser_Static_PrivacyPageLoads(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupStaticTestEnv(t)
	defer cleanup()

	if err := env.initStaticTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newStaticTestPage(t)
	defer page.Close()

	// Navigate to privacy page
	_, err := page.Goto(env.baseURL + "/privacy")
	if err != nil {
		t.Fatalf("Failed to navigate to privacy page: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	// Check page title
	title, err := page.Title()
	if err != nil {
		t.Fatalf("Failed to get page title: %v", err)
	}
	if !strings.Contains(strings.ToLower(title), "privacy") {
		t.Errorf("Expected 'Privacy' in page title, got: %s", title)
	}

	// Check for privacy-related content
	pageContent, err := page.Content()
	if err != nil {
		t.Fatalf("Failed to get page content: %v", err)
	}
	if !strings.Contains(strings.ToLower(pageContent), "privacy") {
		t.Error("Privacy page does not contain 'privacy' in content")
	}
}

// TestBrowser_Static_TermsPageLoads verifies the terms of service page loads correctly.
func TestBrowser_Static_TermsPageLoads(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupStaticTestEnv(t)
	defer cleanup()

	if err := env.initStaticTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newStaticTestPage(t)
	defer page.Close()

	// Navigate to terms page
	_, err := page.Goto(env.baseURL + "/terms")
	if err != nil {
		t.Fatalf("Failed to navigate to terms page: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	// Check page title
	title, err := page.Title()
	if err != nil {
		t.Fatalf("Failed to get page title: %v", err)
	}
	if !strings.Contains(strings.ToLower(title), "terms") {
		t.Errorf("Expected 'Terms' in page title, got: %s", title)
	}

	// Check for terms-related content
	pageContent, err := page.Content()
	if err != nil {
		t.Fatalf("Failed to get page content: %v", err)
	}
	if !strings.Contains(strings.ToLower(pageContent), "terms") {
		t.Error("Terms page does not contain 'terms' in content")
	}
}

// TestBrowser_Static_AboutPageLoads verifies the about page loads correctly.
func TestBrowser_Static_AboutPageLoads(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupStaticTestEnv(t)
	defer cleanup()

	if err := env.initStaticTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newStaticTestPage(t)
	defer page.Close()

	// Navigate to about page
	_, err := page.Goto(env.baseURL + "/about")
	if err != nil {
		t.Fatalf("Failed to navigate to about page: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	// Check page title
	title, err := page.Title()
	if err != nil {
		t.Fatalf("Failed to get page title: %v", err)
	}
	if !strings.Contains(strings.ToLower(title), "about") {
		t.Errorf("Expected 'About' in page title, got: %s", title)
	}

	// Check for about-related content (common.ink branding)
	pageContent, err := page.Content()
	if err != nil {
		t.Fatalf("Failed to get page content: %v", err)
	}
	if !strings.Contains(pageContent, "common.ink") {
		t.Error("About page does not contain 'common.ink' in content")
	}
}

// TestBrowser_Static_APIDocsPageLoads verifies the API documentation page loads correctly.
func TestBrowser_Static_APIDocsPageLoads(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupStaticTestEnv(t)
	defer cleanup()

	if err := env.initStaticTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newStaticTestPage(t)
	defer page.Close()

	// Navigate to API docs page
	_, err := page.Goto(env.baseURL + "/docs/api")
	if err != nil {
		t.Fatalf("Failed to navigate to API docs page: %v", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	// Check page title
	title, err := page.Title()
	if err != nil {
		t.Fatalf("Failed to get page title: %v", err)
	}
	if !strings.Contains(strings.ToLower(title), "api") && !strings.Contains(strings.ToLower(title), "documentation") {
		t.Errorf("Expected 'API' or 'Documentation' in page title, got: %s", title)
	}

	// Check for API-related content
	pageContent, err := page.Content()
	if err != nil {
		t.Fatalf("Failed to get page content: %v", err)
	}
	if !strings.Contains(strings.ToLower(pageContent), "api") {
		t.Error("API docs page does not contain 'api' in content")
	}
}

// =============================================================================
// Navigation Tests
// =============================================================================

// TestBrowser_Static_PrivacyLinkNavigates verifies clicking the Privacy link navigates correctly.
func TestBrowser_Static_PrivacyLinkNavigates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupStaticTestEnv(t)
	defer cleanup()

	if err := env.initStaticTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newStaticTestPage(t)
	defer page.Close()

	// Start from login page
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

	// Click Privacy link
	privacyLink := page.Locator("footer a[href='/privacy']")
	err = privacyLink.Click()
	if err != nil {
		t.Fatalf("Failed to click Privacy link: %v", err)
	}

	// Wait for navigation
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	if err != nil {
		t.Fatalf("Navigation did not complete: %v", err)
	}

	// Verify we're on the privacy page
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/privacy") {
		t.Errorf("Expected to be on /privacy, got: %s", currentURL)
	}
}

// =============================================================================
// No-Scroll Assertions (Desktop + Mobile)
// =============================================================================

// scrollDimensions holds the scroll measurement results from a page.
type scrollDimensions struct {
	HasVerticalScroll   bool    `json:"hasVerticalScroll"`
	HasHorizontalScroll bool    `json:"hasHorizontalScroll"`
	ScrollHeight        float64 `json:"scrollHeight"`
	InnerHeight         float64 `json:"innerHeight"`
	ScrollWidth         float64 `json:"scrollWidth"`
	InnerWidth          float64 `json:"innerWidth"`
}

// parseScrollDimensions converts the raw Evaluate result into scrollDimensions.
func parseScrollDimensions(raw interface{}) scrollDimensions {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return scrollDimensions{}
	}
	return scrollDimensions{
		HasVerticalScroll:   m["hasVerticalScroll"].(bool),
		HasHorizontalScroll: m["hasHorizontalScroll"].(bool),
		ScrollHeight:        m["scrollHeight"].(float64),
		InnerHeight:         m["innerHeight"].(float64),
		ScrollWidth:         m["scrollWidth"].(float64),
		InnerWidth:          m["innerWidth"].(float64),
	}
}

// assertNoScroll checks that the current page has no vertical or horizontal scrollbar
// and reports failures with detailed dimension info.
func assertNoScroll(t *testing.T, page playwright.Page, pagePath string, viewportLabel string) {
	t.Helper()

	raw, err := page.Evaluate(`() => ({
		hasVerticalScroll: document.documentElement.scrollHeight > window.innerHeight,
		hasHorizontalScroll: document.documentElement.scrollWidth > window.innerWidth,
		scrollHeight: document.documentElement.scrollHeight,
		innerHeight: window.innerHeight,
		scrollWidth: document.documentElement.scrollWidth,
		innerWidth: window.innerWidth,
	})`)
	if err != nil {
		t.Fatalf("[%s] %s: failed to evaluate scroll dimensions: %v", viewportLabel, pagePath, err)
	}

	dims := parseScrollDimensions(raw)

	if dims.HasVerticalScroll {
		t.Errorf("[%s] %s: unexpected vertical scroll (scrollHeight=%0.f > innerHeight=%0.f)",
			viewportLabel, pagePath, dims.ScrollHeight, dims.InnerHeight)
	}
	if dims.HasHorizontalScroll {
		t.Errorf("[%s] %s: unexpected horizontal scroll (scrollWidth=%0.f > innerWidth=%0.f)",
			viewportLabel, pagePath, dims.ScrollWidth, dims.InnerWidth)
	}
}

// TestBrowser_Static_NoScroll_Desktop verifies no scrolling on key pages at desktop viewport (1280x720).
func TestBrowser_Static_NoScroll_Desktop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupStaticTestEnv(t)
	defer cleanup()

	if err := env.initStaticTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newStaticTestPage(t)
	defer page.Close()

	// Set desktop viewport
	page.SetViewportSize(1280, 720)

	pages := []string{"/login", "/register", "/privacy", "/terms", "/about"}

	for _, pagePath := range pages {
		_, err := page.Goto(env.baseURL + pagePath)
		if err != nil {
			t.Fatalf("Failed to navigate to %s: %v", pagePath, err)
		}

		err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
			State: playwright.LoadStateNetworkidle,
		})
		if err != nil {
			t.Fatalf("%s did not finish loading: %v", pagePath, err)
		}

		assertNoScroll(t, page, pagePath, "desktop 1280x720")
	}
}

// TestBrowser_Static_NoScroll_Mobile verifies no scrolling on key pages at mobile viewport (375x667).
func TestBrowser_Static_NoScroll_Mobile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupStaticTestEnv(t)
	defer cleanup()

	if err := env.initStaticTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newStaticTestPage(t)
	defer page.Close()

	// Set mobile viewport
	page.SetViewportSize(375, 667)

	pages := []string{"/login", "/register", "/privacy", "/terms", "/about"}

	for _, pagePath := range pages {
		_, err := page.Goto(env.baseURL + pagePath)
		if err != nil {
			t.Fatalf("Failed to navigate to %s: %v", pagePath, err)
		}

		err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
			State: playwright.LoadStateNetworkidle,
		})
		if err != nil {
			t.Fatalf("%s did not finish loading: %v", pagePath, err)
		}

		assertNoScroll(t, page, pagePath, "mobile 375x667")
	}
}

// TestBrowser_Static_TermsLinkNavigates verifies clicking the Terms link navigates correctly.
func TestBrowser_Static_TermsLinkNavigates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env, cleanup := setupStaticTestEnv(t)
	defer cleanup()

	if err := env.initStaticTestBrowser(t); err != nil {
		t.Skip("Playwright not available:", err)
	}

	page := env.newStaticTestPage(t)
	defer page.Close()

	// Start from login page
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

	// Click Terms link
	termsLink := page.Locator("footer a[href='/terms']")
	err = termsLink.Click()
	if err != nil {
		t.Fatalf("Failed to click Terms link: %v", err)
	}

	// Wait for navigation
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	if err != nil {
		t.Fatalf("Navigation did not complete: %v", err)
	}

	// Verify we're on the terms page
	currentURL := page.URL()
	if !strings.Contains(currentURL, "/terms") {
		t.Errorf("Expected to be on /terms, got: %s", currentURL)
	}
}
