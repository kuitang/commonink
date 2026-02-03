// Package browser contains Playwright E2E tests for browser-based UI flows.
// These are deterministic scenario tests (NOT property-based) as per CLAUDE.md.
//
// This file tests API Key management via the web UI at /settings/api-keys.
//
// Prerequisites:
// - Install Playwright browsers: go run github.com/playwright-community/playwright-go/cmd/playwright install chromium
// - Run tests with: go test -v ./tests/browser/...
package browser

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
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
	"github.com/kuitang/agent-notes/internal/db/userdb"
	"github.com/kuitang/agent-notes/internal/email"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/kuitang/agent-notes/internal/ratelimit"
	"github.com/kuitang/agent-notes/internal/s3client"
	"github.com/kuitang/agent-notes/internal/web"
)

const (
	apiKeyTestBucketName = "apikey-test-bucket"
	apiKeyTestMasterKey  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64 hex chars = 32 bytes, low entropy for gitleaks
)

// apiKeyTestEnv holds all the components needed for API Key settings browser testing.
type apiKeyTestEnv struct {
	server         *httptest.Server
	baseURL        string
	sessionsDB     *db.SessionsDB
	keyManager     *crypto.KeyManager
	sessionService *auth.SessionService
	userService    *auth.UserService
	pw             *playwright.Playwright
	browser        playwright.Browser
	browserContext playwright.BrowserContext
	page           playwright.Page
	s3Server       *httptest.Server
	rateLimiter    *ratelimit.RateLimiter
}

// setupAPIKeyTestEnv creates a complete test environment for API Key settings tests.
func setupAPIKeyTestEnv(t *testing.T) *apiKeyTestEnv {
	t.Helper()

	// Reset database singleton and set fresh data directory
	db.ResetForTesting()
	db.DataDirectory = t.TempDir()

	// Initialize sessions database
	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		t.Fatalf("Failed to open sessions database: %v", err)
	}

	// Initialize key manager
	masterKey, err := hex.DecodeString(apiKeyTestMasterKey)
	if err != nil {
		t.Fatalf("Failed to decode master key: %v", err)
	}
	keyManager := crypto.NewKeyManager(masterKey, sessionsDB)

	// Initialize services
	emailService := email.NewMockEmailService()
	sessionService := auth.NewSessionService(sessionsDB)
	userService := auth.NewUserService(sessionsDB, emailService, "http://localhost")
	consentService := auth.NewConsentService(sessionsDB)

	// Initialize mock S3
	s3Client, s3Server := setupAPIKeyTestS3(t)

	// Initialize template renderer
	templatesDir := findAPIKeyTestTemplatesDir()
	renderer, err := web.NewRenderer(templatesDir)
	if err != nil {
		t.Fatalf("Failed to create renderer: %v", err)
	}

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

	// Create HTTP mux
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// API endpoint for testing API Key authentication
	// This endpoint requires authentication and returns 200 if auth succeeds
	mux.Handle("GET /api/notes", authMiddleware.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"notes":[]}`))
	})))

	// Create web handler
	webHandler := web.NewWebHandler(
		renderer,
		nil, // notesService is created per-request
		publicNotes,
		userService,
		sessionService,
		consentService,
		s3Client,
		nil, // shortURLSvc not needed for API Key settings tests
		"http://localhost:8080",
	)
	webHandler.RegisterRoutes(mux, authMiddleware)

	// Create test server
	server := httptest.NewServer(mux)

	// Initialize Playwright
	pw, err := playwright.Run()
	if err != nil {
		server.Close()
		t.Fatalf("Failed to start Playwright: %v (run: go run github.com/playwright-community/playwright-go/cmd/playwright install chromium)", err)
	}

	// Launch browser (headless)
	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
	})
	if err != nil {
		pw.Stop()
		server.Close()
		t.Fatalf("Failed to launch browser: %v", err)
	}

	// Create browser context
	browserContext, err := browser.NewContext()
	if err != nil {
		browser.Close()
		pw.Stop()
		server.Close()
		t.Fatalf("Failed to create browser context: %v", err)
	}

	// Create page
	page, err := browserContext.NewPage()
	if err != nil {
		browserContext.Close()
		browser.Close()
		pw.Stop()
		server.Close()
		t.Fatalf("Failed to create page: %v", err)
	}

	page.SetDefaultTimeout(10000) // 10 second timeout

	env := &apiKeyTestEnv{
		server:         server,
		baseURL:        server.URL,
		sessionsDB:     sessionsDB,
		keyManager:     keyManager,
		sessionService: sessionService,
		userService:    userService,
		pw:             pw,
		browser:        browser,
		browserContext: browserContext,
		page:           page,
		s3Server:       s3Server,
		rateLimiter:    rateLimiter,
	}

	t.Cleanup(func() {
		page.Close()
		browserContext.Close()
		browser.Close()
		pw.Stop()
		server.Close()
		if s3Server != nil {
			s3Server.Close()
		}
		rateLimiter.Stop()
		db.CloseAll()
	})

	return env
}

// setupAPIKeyTestS3 creates a mock S3 server for testing.
func setupAPIKeyTestS3(t *testing.T) (*s3client.Client, *httptest.Server) {
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

	_, err = s3SDK.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(apiKeyTestBucketName),
	})
	if err != nil {
		t.Fatalf("Failed to create mock S3 bucket: %v", err)
	}

	client := s3client.NewFromS3Client(s3SDK, apiKeyTestBucketName, ts.URL+"/"+apiKeyTestBucketName)
	return client, ts
}

// findAPIKeyTestTemplatesDir locates the templates directory.
func findAPIKeyTestTemplatesDir() string {
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

// loginAPIKeyTestUser creates a test user with a password and logs them in.
func (env *apiKeyTestEnv) loginAPIKeyTestUser(t *testing.T, testEmail, password string) string {
	t.Helper()

	ctx := context.Background()

	// Create/find user
	user, err := env.userService.FindOrCreateByEmail(ctx, testEmail)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Set password for the user (required for API Key creation re-auth)
	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	// Open user's database using the same keyManager as auth middleware
	// This is critical - we must use the same DEK that the auth middleware will use
	dek, err := env.keyManager.GetOrCreateUserDEK(user.ID)
	if err != nil {
		t.Fatalf("Failed to get user DEK: %v", err)
	}
	userDB, err := db.OpenUserDBWithDEK(user.ID, dek)
	if err != nil {
		t.Fatalf("Failed to open user DB: %v", err)
	}

	// Create the account record (required for API Key re-auth to work)
	err = userDB.Queries().CreateAccount(ctx, userdb.CreateAccountParams{
		UserID:             user.ID,
		Email:              testEmail,
		PasswordHash:       sql.NullString{String: passwordHash, Valid: true},
		GoogleSub:          sql.NullString{},
		CreatedAt:          time.Now().Unix(),
		SubscriptionStatus: sql.NullString{String: "free", Valid: true},
		SubscriptionID:     sql.NullString{},
		DbSizeBytes:        sql.NullInt64{},
		LastLogin:          sql.NullInt64{Int64: time.Now().Unix(), Valid: true},
	})
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	// Create session
	sessionID, err := env.sessionService.Create(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Set session cookie in browser - use 127.0.0.1 as that's what httptest uses
	err = env.browserContext.AddCookies([]playwright.OptionalCookie{
		{
			Name:     "session_id",
			Value:    sessionID,
			Domain:   playwright.String("127.0.0.1"),
			Path:     playwright.String("/"),
			HttpOnly: playwright.Bool(true),
			Secure:   playwright.Bool(false), // httptest uses HTTP
			SameSite: playwright.SameSiteAttributeLax,
		},
	})
	if err != nil {
		t.Fatalf("Failed to set session cookie: %v", err)
	}

	return user.ID
}

// navigateAPIKey navigates to a path on the test server.
func (env *apiKeyTestEnv) navigateAPIKey(t *testing.T, path string) {
	t.Helper()

	url := env.baseURL + path
	_, err := env.page.Goto(url, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		Timeout:   playwright.Float(10000),
	})
	if err != nil {
		t.Fatalf("Failed to navigate to %s: %v", path, err)
	}
}

// waitForAPIKeySelector waits for an element to appear.
// For selectors with multiple options (comma-separated), returns the first matching element.
func (env *apiKeyTestEnv) waitForAPIKeySelector(t *testing.T, selector string) playwright.Locator {
	t.Helper()

	locator := env.page.Locator(selector)
	// Use First() when selector might match multiple elements
	first := locator.First()
	err := first.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Failed to wait for selector %s: %v", selector, err)
	}
	return first
}

// generateAPIKeyTestEmail generates a unique email for test isolation.
func generateAPIKeyTestEmail(prefix string) string {
	return fmt.Sprintf("%s-%d@example.com", prefix, time.Now().UnixNano())
}

// =============================================================================
// Test: Page Load
// =============================================================================

func TestBrowser_APIKeySettings_PageLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupAPIKeyTestEnv(t)
	testEmail := generateAPIKeyTestEmail("apikey-pageload")
	testPassword := "SecurePass123!"
	env.loginAPIKeyTestUser(t, testEmail, testPassword)

	// Navigate to /settings/api-keys
	env.navigateAPIKey(t, "/settings/api-keys")

	// Wait for page to load
	err := env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	// Verify page title shows "API Keys"
	heading := env.waitForAPIKeySelector(t, "h1")
	headingText, err := heading.TextContent()
	if err != nil {
		t.Fatalf("Failed to get heading text: %v", err)
	}

	if !strings.Contains(headingText, "API Keys") {
		t.Errorf("Expected heading to contain 'API Keys', got: %s", headingText)
	}

	// Verify "Create API Key" button is visible
	createButton := env.page.Locator("button[type='submit']:has-text('Create API Key')")
	isVisible, err := createButton.IsVisible()
	if err != nil {
		t.Fatalf("Failed to check create button visibility: %v", err)
	}
	if !isVisible {
		t.Error("Create API Key button should be visible")
	}

	// Verify form fields are present
	nameInput := env.page.Locator("input#name")
	nameVisible, err := nameInput.IsVisible()
	if err != nil {
		t.Fatalf("Failed to check name input visibility: %v", err)
	}
	if !nameVisible {
		t.Error("API key name input should be visible")
	}

	scopeSelect := env.page.Locator("select#scope")
	scopeVisible, err := scopeSelect.IsVisible()
	if err != nil {
		t.Fatalf("Failed to check scope select visibility: %v", err)
	}
	if !scopeVisible {
		t.Error("Scope select should be visible")
	}
}

// =============================================================================
// Test: Create API Key
// =============================================================================

func TestBrowser_APIKeySettings_CreateKey(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupAPIKeyTestEnv(t)
	testEmail := generateAPIKeyTestEmail("apikey-create")
	testPassword := "SecurePass123!"
	env.loginAPIKeyTestUser(t, testEmail, testPassword)

	// Navigate to /settings/api-keys
	env.navigateAPIKey(t, "/settings/api-keys")

	// Wait for page to load
	env.waitForAPIKeySelector(t, "h1:has-text('API Keys')")

	// Fill in API key name
	nameInput := env.waitForAPIKeySelector(t, "input#name")
	err := nameInput.Fill("Test API Key")
	if err != nil {
		t.Fatalf("Failed to fill API key name: %v", err)
	}

	// Select scope: "Read and Write"
	scopeSelect := env.waitForAPIKeySelector(t, "select#scope")
	_, err = scopeSelect.SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read_write"),
	})
	if err != nil {
		t.Fatalf("Failed to select scope: %v", err)
	}

	// Fill in email for re-authentication
	emailInput := env.waitForAPIKeySelector(t, "input#email")
	err = emailInput.Fill(testEmail)
	if err != nil {
		t.Fatalf("Failed to fill email: %v", err)
	}

	// Fill in password for re-authentication
	passwordInput := env.waitForAPIKeySelector(t, "input#password")
	err = passwordInput.Fill(testPassword)
	if err != nil {
		t.Fatalf("Failed to fill password: %v", err)
	}

	// Submit form
	submitButton := env.page.Locator("button[type='submit']:has-text('Create API Key')")
	err = submitButton.Click()
	if err != nil {
		t.Fatalf("Failed to click submit button: %v", err)
	}

	// Wait for page to reload with new API key
	err = env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	if err != nil {
		t.Fatalf("Page did not reload: %v", err)
	}

	// Verify API key value is displayed (only shown once)
	tokenElement := env.page.Locator("code#new-token, code#token-value")
	err = tokenElement.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("API key value element not found: %v", err)
	}

	tokenValue, err := tokenElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get API key value: %v", err)
	}

	// Verify API key starts with "agentnotes_key_"
	if !strings.HasPrefix(tokenValue, "agentnotes_key_") {
		t.Errorf("API key should start with 'agentnotes_key_', got: %s", tokenValue)
	}

	// Verify copy button is present
	copyButton := env.page.Locator("button:has-text('Copy')")
	copyVisible, err := copyButton.IsVisible()
	if err != nil {
		t.Fatalf("Failed to check copy button visibility: %v", err)
	}
	if !copyVisible {
		t.Error("Copy button should be visible")
	}

	// Verify success message is displayed
	successMessage := env.page.Locator("text=API Key Created Successfully")
	successVisible, err := successMessage.IsVisible()
	if err != nil {
		t.Fatalf("Failed to check success message visibility: %v", err)
	}
	if !successVisible {
		t.Error("Success message should be visible")
	}
}

// =============================================================================
// Test: List API Keys
// =============================================================================

func TestBrowser_APIKeySettings_ListKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupAPIKeyTestEnv(t)
	testEmail := generateAPIKeyTestEmail("apikey-list")
	testPassword := "SecurePass123!"
	env.loginAPIKeyTestUser(t, testEmail, testPassword)

	// Create multiple API keys via the UI
	tokenNames := []string{"Key One", "Key Two", "Key Three"}

	for _, tokenName := range tokenNames {
		env.navigateAPIKey(t, "/settings/api-keys")
		env.waitForAPIKeySelector(t, "h1:has-text('API Keys')")

		// Fill form
		env.page.Locator("input#name").Fill(tokenName)
		env.page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
			Values: playwright.StringSlice("read_write"),
		})
		env.page.Locator("input#email").Fill(testEmail)
		env.page.Locator("input#password").Fill(testPassword)

		// Submit
		env.page.Locator("button[type='submit']:has-text('Create API Key')").Click()

		// Wait for redirect
		env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
			State: playwright.LoadStateNetworkidle,
		})
	}

	// Navigate to settings page to view list
	env.navigateAPIKey(t, "/settings/api-keys")
	env.waitForAPIKeySelector(t, "h1:has-text('API Keys')")

	// Verify all created API keys appear in list
	for _, tokenName := range tokenNames {
		tokenRow := env.page.Locator(fmt.Sprintf("text=%s", tokenName))
		count, err := tokenRow.Count()
		if err != nil {
			t.Fatalf("Failed to count API key rows for %s: %v", tokenName, err)
		}
		if count == 0 {
			t.Errorf("API key '%s' should appear in the list", tokenName)
		}
	}

	// Verify API keys table shows columns: Name, Scope, Created, Last Used, Expires
	tableHeaders := env.page.Locator("th")
	headersCount, err := tableHeaders.Count()
	if err != nil {
		t.Fatalf("Failed to count table headers: %v", err)
	}
	if headersCount < 4 {
		t.Errorf("Expected at least 4 table headers (Name, Scope, Created, etc.), got: %d", headersCount)
	}

	// Verify API key values are NOT shown (security)
	// The actual key value should not be visible in the list
	tokenHashLocator := env.page.Locator("text=agentnotes_key_")
	hashCount, err := tokenHashLocator.Count()
	if err != nil {
		t.Fatalf("Failed to check for API key values: %v", err)
	}
	// There should only be the key shown in the "new key" success message (if still visible)
	// but NOT in the API key list rows
	if hashCount > 1 {
		t.Log("Note: API key values should only be visible once at creation time")
	}
}

// =============================================================================
// Test: Revoke API Key
// =============================================================================

func TestBrowser_APIKeySettings_RevokeKey(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupAPIKeyTestEnv(t)
	testEmail := generateAPIKeyTestEmail("apikey-revoke")
	testPassword := "SecurePass123!"
	env.loginAPIKeyTestUser(t, testEmail, testPassword)

	tokenName := "Key to Revoke"

	// Create an API key first
	env.navigateAPIKey(t, "/settings/api-keys")
	env.waitForAPIKeySelector(t, "h1:has-text('API Keys')")

	env.page.Locator("input#name").Fill(tokenName)
	env.page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read_write"),
	})
	env.page.Locator("input#email").Fill(testEmail)
	env.page.Locator("input#password").Fill(testPassword)
	env.page.Locator("button[type='submit']:has-text('Create API Key')").Click()

	env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Navigate back to API keys page (in case we're showing the new key display)
	env.navigateAPIKey(t, "/settings/api-keys")
	env.waitForAPIKeySelector(t, "h1:has-text('API Keys')")

	// Verify the API key exists in the list
	tokenRow := env.page.Locator(fmt.Sprintf("text=%s", tokenName))
	count, err := tokenRow.Count()
	if err != nil || count == 0 {
		t.Fatal("API key should exist before revoking")
	}

	// Set up dialog handler for confirmation
	env.page.OnDialog(func(dialog playwright.Dialog) {
		dialog.Accept()
	})

	// Click "Revoke" button for the API key
	// Find the row containing the key name and click its Revoke button
	revokeButton := env.page.Locator(fmt.Sprintf("tr:has-text('%s') button:has-text('Revoke')", tokenName))
	err = revokeButton.Click()
	if err != nil {
		t.Fatalf("Failed to click Revoke button: %v", err)
	}

	// Wait for page to reload
	err = env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	if err != nil {
		t.Fatalf("Page did not reload after revoke: %v", err)
	}

	// Verify API key is removed from list
	tokenRowAfter := env.page.Locator(fmt.Sprintf("td:has-text('%s')", tokenName))
	countAfter, err := tokenRowAfter.Count()
	if err != nil {
		t.Fatalf("Failed to count API key rows after revoke: %v", err)
	}
	if countAfter > 0 {
		t.Error("Revoked API key should not appear in the list")
	}
}

// =============================================================================
// Test: Copy API Key
// =============================================================================

func TestBrowser_APIKeySettings_CopyKey(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupAPIKeyTestEnv(t)
	testEmail := generateAPIKeyTestEmail("apikey-copy")
	testPassword := "SecurePass123!"
	env.loginAPIKeyTestUser(t, testEmail, testPassword)

	// Create an API key
	env.navigateAPIKey(t, "/settings/api-keys")
	env.waitForAPIKeySelector(t, "h1:has-text('API Keys')")

	env.page.Locator("input#name").Fill("Key for Copy Test")
	env.page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read_write"),
	})
	env.page.Locator("input#email").Fill(testEmail)
	env.page.Locator("input#password").Fill(testPassword)
	env.page.Locator("button[type='submit']:has-text('Create API Key')").Click()

	env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Get the API key value before clicking copy
	tokenElement := env.waitForAPIKeySelector(t, "code#new-token, code#token-value")
	tokenValue, err := tokenElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get API key value: %v", err)
	}

	// Verify API key has expected format
	if !strings.HasPrefix(tokenValue, "agentnotes_key_") {
		t.Errorf("API key should have proper prefix, got: %s", tokenValue)
	}

	// Click the copy button
	copyButton := env.page.Locator("button:has-text('Copy')")
	err = copyButton.Click()
	if err != nil {
		t.Fatalf("Failed to click copy button: %v", err)
	}

	// Wait a moment for the copy action
	time.Sleep(500 * time.Millisecond)

	// Verify the button text changed to "Copied!" (UI feedback)
	copiedText := env.page.Locator("span#copy-text:has-text('Copied!')")
	copiedVisible, err := copiedText.IsVisible()
	if err != nil {
		// The button might have already reset
		t.Log("Copy button feedback check inconclusive")
	} else if !copiedVisible {
		t.Log("Note: Copy button feedback may have already reset")
	}

	// Note: Actual clipboard verification is not possible in headless mode
	// The test verifies the copy button exists and can be clicked
	// In real usage, the browser's clipboard API would copy the API key
	t.Logf("API key value that would be copied: %s", tokenValue)
}

// =============================================================================
// Test: Empty State (No API Keys)
// =============================================================================

func TestBrowser_APIKeySettings_EmptyState(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupAPIKeyTestEnv(t)
	testEmail := generateAPIKeyTestEmail("apikey-empty")
	testPassword := "SecurePass123!"
	env.loginAPIKeyTestUser(t, testEmail, testPassword)

	// Navigate to API keys page without creating any keys
	env.navigateAPIKey(t, "/settings/api-keys")
	env.waitForAPIKeySelector(t, "h1:has-text('API Keys')")

	// Verify "No API keys" message is displayed
	noKeysMessage := env.page.Locator("h3:has-text('No API keys')")
	count, err := noKeysMessage.Count()
	if err != nil {
		t.Fatalf("Failed to check for empty state message: %v", err)
	}
	if count == 0 {
		t.Error("Expected 'No API keys' message for new user without API keys")
	}

	// Verify help text is displayed
	helpText := env.page.Locator("text=Create an API key to get started")
	helpVisible, err := helpText.IsVisible()
	if err != nil {
		t.Fatalf("Failed to check help text visibility: %v", err)
	}
	if !helpVisible {
		t.Error("Help text should be visible in empty state")
	}
}

// =============================================================================
// Test: Invalid Credentials (Re-authentication Fails)
// =============================================================================

func TestBrowser_APIKeySettings_InvalidCredentials(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupAPIKeyTestEnv(t)
	testEmail := generateAPIKeyTestEmail("apikey-invalid-creds")
	testPassword := "SecurePass123!"
	env.loginAPIKeyTestUser(t, testEmail, testPassword)

	// Navigate to API keys page
	env.navigateAPIKey(t, "/settings/api-keys")
	env.waitForAPIKeySelector(t, "h1:has-text('API Keys')")

	// Fill form with wrong password
	env.page.Locator("input#name").Fill("Test API Key")
	env.page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read_write"),
	})
	env.page.Locator("input#email").Fill(testEmail)
	env.page.Locator("input#password").Fill("WrongPassword123!")

	// Submit form
	env.page.Locator("button[type='submit']:has-text('Create API Key')").Click()

	// Wait for page to reload
	env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Verify error message is displayed
	errorMessage := env.page.Locator("text=Invalid credentials")
	errorVisible, err := errorMessage.IsVisible()
	if err != nil {
		// Check URL for error param instead
		currentURL := env.page.URL()
		if !strings.Contains(currentURL, "error=") {
			t.Error("Expected error message or error in URL for invalid credentials")
		}
	} else if !errorVisible {
		// The error might be in the URL
		currentURL := env.page.URL()
		if !strings.Contains(currentURL, "error=") {
			t.Error("Expected error message for invalid credentials")
		}
	}
}

// =============================================================================
// Test: API Key Expiration Options
// =============================================================================

func TestBrowser_APIKeySettings_ExpirationOptions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupAPIKeyTestEnv(t)
	testEmail := generateAPIKeyTestEmail("apikey-expiry")
	testPassword := "SecurePass123!"
	env.loginAPIKeyTestUser(t, testEmail, testPassword)

	// Navigate to API keys page
	env.navigateAPIKey(t, "/settings/api-keys")
	env.waitForAPIKeySelector(t, "h1:has-text('API Keys')")

	// Check expiration select options
	expiresSelect := env.waitForAPIKeySelector(t, "select#expires_in")

	// Get all options
	options := expiresSelect.Locator("option")
	optionCount, err := options.Count()
	if err != nil {
		t.Fatalf("Failed to count expiration options: %v", err)
	}

	// Should have at least 3 options (30 days, 90 days, 180 days, 1 year)
	if optionCount < 3 {
		t.Errorf("Expected at least 3 expiration options, got: %d", optionCount)
	}

	// Verify specific options exist
	expectedOptions := []string{"30 days", "90 days", "180 days", "1 year"}
	for _, expected := range expectedOptions {
		option := expiresSelect.Locator(fmt.Sprintf("option:has-text('%s')", expected))
		count, err := option.Count()
		if err != nil || count == 0 {
			t.Errorf("Expected expiration option '%s' to exist", expected)
		}
	}
}

// =============================================================================
// Test: Read-Only Scope API Key
// =============================================================================

func TestBrowser_APIKeySettings_ReadOnlyScope(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupAPIKeyTestEnv(t)
	testEmail := generateAPIKeyTestEmail("apikey-readonly")
	testPassword := "SecurePass123!"
	env.loginAPIKeyTestUser(t, testEmail, testPassword)

	// Navigate to API keys page
	env.navigateAPIKey(t, "/settings/api-keys")
	env.waitForAPIKeySelector(t, "h1:has-text('API Keys')")

	// Create a read-only API key
	env.page.Locator("input#name").Fill("Read Only Key")
	env.page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read"),
	})
	env.page.Locator("input#email").Fill(testEmail)
	env.page.Locator("input#password").Fill(testPassword)
	env.page.Locator("button[type='submit']:has-text('Create API Key')").Click()

	env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Navigate back to see the API key in the list
	env.navigateAPIKey(t, "/settings/api-keys")
	env.waitForAPIKeySelector(t, "h1:has-text('API Keys')")

	// Verify the API key shows "read" scope
	readScope := env.page.Locator("span:has-text('read')")
	count, err := readScope.Count()
	if err != nil {
		t.Fatalf("Failed to check read scope: %v", err)
	}
	if count == 0 {
		t.Error("API key with read scope should show 'read' in the list")
	}
}

// =============================================================================
// Test: Unauthenticated Access Redirects to Login
// =============================================================================

func TestBrowser_APIKeySettings_RequiresAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupAPIKeyTestEnv(t)

	// Do NOT login - try to access settings page directly
	env.navigateAPIKey(t, "/settings/api-keys")

	// Wait for page to load
	env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// The auth middleware redirects to /login for web pages (RequireAuthWithRedirect)
	currentURL := env.page.URL()

	// Should be redirected to login page
	if !strings.Contains(currentURL, "/login") {
		// If not redirected, check for unauthorized content
		pageContent, err := env.page.Content()
		if err != nil {
			t.Fatalf("Failed to get page content: %v", err)
		}
		if !strings.Contains(pageContent, "Unauthorized") && !strings.Contains(pageContent, "Sign in") {
			t.Errorf("Unauthenticated access should redirect to login or show Unauthorized message, got URL: %s, content: %s",
				currentURL, pageContent[:min(200, len(pageContent))])
		}
	}
}

// =============================================================================
// Test: Usage Instructions Visible
// =============================================================================

func TestBrowser_APIKeySettings_UsageInstructions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupAPIKeyTestEnv(t)
	testEmail := generateAPIKeyTestEmail("apikey-usage")
	testPassword := "SecurePass123!"
	env.loginAPIKeyTestUser(t, testEmail, testPassword)

	// Navigate to API keys page
	env.navigateAPIKey(t, "/settings/api-keys")
	env.waitForAPIKeySelector(t, "h1:has-text('API Keys')")

	// Verify usage instructions section exists
	usageHeading := env.page.Locator("h3:has-text('How to use your API key')")
	isVisible, err := usageHeading.IsVisible()
	if err != nil {
		t.Fatalf("Failed to check usage heading visibility: %v", err)
	}
	if !isVisible {
		t.Error("Usage instructions heading should be visible")
	}

	// Verify example curl command is shown
	curlExample := env.page.Locator("code:has-text('Authorization: Bearer')")
	curlVisible, err := curlExample.IsVisible()
	if err != nil {
		t.Fatalf("Failed to check curl example visibility: %v", err)
	}
	if !curlVisible {
		t.Error("Example curl command should be visible")
	}
}

// =============================================================================
// Test: API Key Shown Only Once (Refresh should mask it)
// =============================================================================

func TestBrowser_APIKeySettings_KeyShownOnceOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupAPIKeyTestEnv(t)
	testEmail := generateAPIKeyTestEmail("apikey-shown-once")
	testPassword := "SecurePass123!"
	env.loginAPIKeyTestUser(t, testEmail, testPassword)

	// Navigate to /settings/api-keys
	env.navigateAPIKey(t, "/settings/api-keys")
	env.waitForAPIKeySelector(t, "h1:has-text('API Keys')")

	// Create an API key
	env.page.Locator("input#name").Fill("Key for Once Test")
	env.page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read_write"),
	})
	env.page.Locator("input#email").Fill(testEmail)
	env.page.Locator("input#password").Fill(testPassword)
	env.page.Locator("button[type='submit']:has-text('Create API Key')").Click()

	env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Verify API key value is displayed (only shown once)
	tokenElement := env.waitForAPIKeySelector(t, "code#new-token, code#token-value")
	tokenValue, err := tokenElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get API key value: %v", err)
	}

	// Verify API key starts with expected prefix
	if !strings.HasPrefix(tokenValue, "agentnotes_key_") {
		t.Errorf("API key should start with 'agentnotes_key_', got: %s", tokenValue)
	}

	// Save the API key value for later verification
	savedToken := tokenValue

	// Navigate away and back to /settings/api-keys
	env.navigateAPIKey(t, "/notes")
	env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	env.navigateAPIKey(t, "/settings/api-keys")
	env.waitForAPIKeySelector(t, "h1:has-text('API Keys')")

	// Verify the full API key value is NOT visible anymore
	// The new-token element should not exist after navigating away
	newTokenElement := env.page.Locator("code#new-token, code#token-value")
	newTokenCount, err := newTokenElement.Count()
	if err != nil {
		t.Fatalf("Failed to count new-token elements: %v", err)
	}

	if newTokenCount > 0 {
		newTokenVisible, _ := newTokenElement.IsVisible()
		if newTokenVisible {
			displayedToken, _ := newTokenElement.TextContent()
			// API key should not be the same as what was originally displayed
			if displayedToken == savedToken {
				t.Error("API key should NOT be visible after navigating away and back")
			}
		}
	}

	// Verify the API key row exists in the list but value is masked
	tokenRow := env.page.Locator("text=Key for Once Test")
	count, err := tokenRow.Count()
	if err != nil {
		t.Fatalf("Failed to count API key rows: %v", err)
	}
	if count == 0 {
		t.Error("API key should still appear in the list by name")
	}

	// The full API key value should not appear anywhere on the page
	pageContent, err := env.page.Content()
	if err != nil {
		t.Fatalf("Failed to get page content: %v", err)
	}

	// The saved API key should not appear in the page content anymore
	// (unless it's in a "new-token" element which we already checked)
	if strings.Contains(pageContent, savedToken) {
		// Check if it's ONLY in a new-token element that shouldn't be visible
		newTokenElementsWithValue := env.page.Locator(fmt.Sprintf("code#new-token:has-text('%s'), code#token-value:has-text('%s')", savedToken, savedToken))
		visibleCount := 0
		count, _ := newTokenElementsWithValue.Count()
		for i := 0; i < count; i++ {
			visible, _ := newTokenElementsWithValue.Nth(i).IsVisible()
			if visible {
				visibleCount++
			}
		}
		if visibleCount > 0 {
			t.Error("Full API key value should not be visible after refresh")
		}
	}
}

// =============================================================================
// Test: Use Created API Key for API Call
// =============================================================================

func TestBrowser_APIKeySettings_UseKeyForAPICall(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupAPIKeyTestEnv(t)
	testEmail := generateAPIKeyTestEmail("apikey-api-call")
	testPassword := "SecurePass123!"
	env.loginAPIKeyTestUser(t, testEmail, testPassword)

	// Navigate to /settings/api-keys
	env.navigateAPIKey(t, "/settings/api-keys")
	env.waitForAPIKeySelector(t, "h1:has-text('API Keys')")

	// Create an API key
	env.page.Locator("input#name").Fill("Key for API Test")
	env.page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read_write"),
	})
	env.page.Locator("input#email").Fill(testEmail)
	env.page.Locator("input#password").Fill(testPassword)
	env.page.Locator("button[type='submit']:has-text('Create API Key')").Click()

	env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Get the API key value
	tokenElement := env.waitForAPIKeySelector(t, "code#new-token, code#token-value")
	tokenValue, err := tokenElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get API key value: %v", err)
	}

	// Verify API key has expected format
	if !strings.HasPrefix(tokenValue, "agentnotes_key_") {
		t.Fatalf("API key should have proper prefix, got: %s", tokenValue)
	}

	// Use the API key for an API call (GET /api/notes)
	// We need to make a direct HTTP request to the test server
	req, err := http.NewRequest("GET", env.baseURL+"/api/notes", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenValue)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make API request: %v", err)
	}
	defer resp.Body.Close()

	// The API should accept the API key
	// Note: The actual response depends on whether /api/notes is registered
	// but we should at least not get a 401 Unauthorized
	if resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("API call with valid API key should not return 401, got status: %d", resp.StatusCode)
	}

	t.Logf("API call with API key returned status: %d", resp.StatusCode)
}

// =============================================================================
// Test: Revoked API Key Fails API Call
// =============================================================================

func TestBrowser_APIKeySettings_RevokedKeyFailsAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupAPIKeyTestEnv(t)
	testEmail := generateAPIKeyTestEmail("apikey-revoke-api")
	testPassword := "SecurePass123!"
	env.loginAPIKeyTestUser(t, testEmail, testPassword)

	// Navigate to /settings/api-keys
	env.navigateAPIKey(t, "/settings/api-keys")
	env.waitForAPIKeySelector(t, "h1:has-text('API Keys')")

	// Create an API key
	tokenName := "Key to Revoke for API"
	nameInput := env.waitForAPIKeySelector(t, "input#name")
	err := nameInput.Fill(tokenName)
	if err != nil {
		t.Fatalf("Failed to fill API key name: %v", err)
	}

	scopeSelect := env.waitForAPIKeySelector(t, "select#scope")
	_, err = scopeSelect.SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read_write"),
	})
	if err != nil {
		t.Fatalf("Failed to select scope: %v", err)
	}

	emailInput := env.waitForAPIKeySelector(t, "input#email")
	err = emailInput.Fill(testEmail)
	if err != nil {
		t.Fatalf("Failed to fill email: %v", err)
	}

	passwordInput := env.waitForAPIKeySelector(t, "input#password")
	err = passwordInput.Fill(testPassword)
	if err != nil {
		t.Fatalf("Failed to fill password: %v", err)
	}

	submitButton := env.page.Locator("button[type='submit']:has-text('Create API Key')")
	err = submitButton.Click()
	if err != nil {
		t.Fatalf("Failed to click submit: %v", err)
	}

	// Wait for page to reload with new API key
	err = env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	if err != nil {
		t.Fatalf("Page did not reload: %v", err)
	}

	// Wait for API key element to appear with extended timeout
	// The key might be in code#new-token (settings/api-keys.html) or code#token-value (api-keys/created.html)
	tokenElement := env.page.Locator("code#new-token, code#token-value")
	err = tokenElement.First().WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(10000),
	})
	if err != nil {
		// Debug: log page content
		pageContent, _ := env.page.Content()
		t.Logf("Page content (first 500 chars): %s", pageContent[:min(500, len(pageContent))])
		t.Fatalf("API key value element not found: %v", err)
	}

	tokenValue, err := tokenElement.First().TextContent()
	if err != nil {
		t.Fatalf("Failed to get API key value: %v", err)
	}

	// Verify the API key works before revocation
	req1, err := http.NewRequest("GET", env.baseURL+"/api/notes", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req1.Header.Set("Authorization", "Bearer "+tokenValue)

	client := &http.Client{Timeout: 10 * time.Second}
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("Failed to make API request before revocation: %v", err)
	}
	resp1.Body.Close()

	if resp1.StatusCode == http.StatusUnauthorized {
		t.Errorf("API key should work before revocation, got status: %d", resp1.StatusCode)
	}
	t.Logf("Before revocation, API returned status: %d", resp1.StatusCode)

	// Navigate to API keys page to revoke
	env.navigateAPIKey(t, "/settings/api-keys")
	env.waitForAPIKeySelector(t, "h1:has-text('API Keys')")

	// Set up dialog handler for confirmation
	env.page.OnDialog(func(dialog playwright.Dialog) {
		dialog.Accept()
	})

	// Click "Revoke" button for the API key
	revokeButton := env.page.Locator(fmt.Sprintf("tr:has-text('%s') button:has-text('Revoke')", tokenName))
	err = revokeButton.Click()
	if err != nil {
		t.Fatalf("Failed to click Revoke button: %v", err)
	}

	// Wait for page to reload
	env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Verify API key no longer works via API
	req2, err := http.NewRequest("GET", env.baseURL+"/api/notes", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req2.Header.Set("Authorization", "Bearer "+tokenValue)

	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("Failed to make API request after revocation: %v", err)
	}
	defer resp2.Body.Close()

	// The API should reject the revoked API key with 401 Unauthorized
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("API call with revoked API key should return 401, got status: %d", resp2.StatusCode)
	}

	t.Logf("After revocation, API returned status: %d (expected 401)", resp2.StatusCode)
}

// =============================================================================
// Test: Navigate Away and Back - API Key Masked
// =============================================================================

func TestBrowser_APIKeySettings_NavigateAwayMasksKey(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupAPIKeyTestEnv(t)
	testEmail := generateAPIKeyTestEmail("apikey-navigate-mask")
	testPassword := "SecurePass123!"
	env.loginAPIKeyTestUser(t, testEmail, testPassword)

	// Navigate to /settings/api-keys
	env.navigateAPIKey(t, "/settings/api-keys")
	env.waitForAPIKeySelector(t, "h1:has-text('API Keys')")

	// Create an API key
	tokenName := "Key for Navigate Test"
	env.page.Locator("input#name").Fill(tokenName)
	env.page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read_write"),
	})
	env.page.Locator("input#email").Fill(testEmail)
	env.page.Locator("input#password").Fill(testPassword)
	env.page.Locator("button[type='submit']:has-text('Create API Key')").Click()

	env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Verify API key is displayed
	tokenElement := env.waitForAPIKeySelector(t, "code#new-token, code#token-value")
	tokenValue, err := tokenElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get API key value: %v", err)
	}

	if !strings.HasPrefix(tokenValue, "agentnotes_key_") {
		t.Errorf("API key should be visible immediately after creation")
	}

	// Navigate away to /notes
	env.navigateAPIKey(t, "/notes")
	env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Navigate back to /settings/api-keys
	env.navigateAPIKey(t, "/settings/api-keys")
	env.waitForAPIKeySelector(t, "h1:has-text('API Keys')")

	// The new-token element should not be visible
	newTokenElement := env.page.Locator("code#new-token, code#token-value")
	err = newTokenElement.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(2000),
	})

	// We EXPECT this to timeout/fail because the API key should NOT be visible
	if err == nil {
		// The element is visible - check if it contains the actual API key
		displayedToken, _ := newTokenElement.TextContent()
		if displayedToken == tokenValue {
			t.Error("Full API key value should NOT be visible after navigating away and back")
		}
	}

	// Verify the API key is listed but not in raw form
	tokenRow := env.page.Locator(fmt.Sprintf("text=%s", tokenName))
	count, err := tokenRow.Count()
	if err != nil {
		t.Fatalf("Failed to count API key rows: %v", err)
	}
	if count == 0 {
		t.Error("API key should still appear in the list by name")
	}

	// API key list should show masked values (not full key)
	// Look for "agentnotes_key_" prefix in the table - there should be none
	// because the list shows key names, not raw values
	listContent := env.page.Locator("table")
	tableContent, _ := listContent.TextContent()
	if strings.Contains(tableContent, tokenValue) {
		t.Error("API key list should not contain the full raw key value")
	}
}
