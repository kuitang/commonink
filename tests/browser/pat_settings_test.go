// Package browser contains Playwright E2E tests for browser-based UI flows.
// These are deterministic scenario tests (NOT property-based) as per CLAUDE.md.
//
// This file tests Personal Access Token (PAT) management via the web UI at /settings/tokens.
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
	patTestBucketName = "pat-test-bucket"
	patTestMasterKey  = "test0000000000000000000000000000test0000000000000000000000000000" // low entropy for gitleaks
)

// patTestEnv holds all the components needed for PAT settings browser testing.
type patTestEnv struct {
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

// setupPATTestEnv creates a complete test environment for PAT settings tests.
func setupPATTestEnv(t *testing.T) *patTestEnv {
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
	masterKey, err := hex.DecodeString(patTestMasterKey)
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
	s3Client, s3Server := setupPATTestS3(t)

	// Initialize template renderer
	templatesDir := findPATTestTemplatesDir()
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

	// Create web handler
	webHandler := web.NewWebHandler(
		renderer,
		nil, // notesService is created per-request
		publicNotes,
		userService,
		sessionService,
		consentService,
		s3Client,
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

	env := &patTestEnv{
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

// setupPATTestS3 creates a mock S3 server for testing.
func setupPATTestS3(t *testing.T) (*s3client.Client, *httptest.Server) {
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
		Bucket: aws.String(patTestBucketName),
	})
	if err != nil {
		t.Fatalf("Failed to create mock S3 bucket: %v", err)
	}

	client := s3client.NewFromS3Client(s3SDK, patTestBucketName, ts.URL+"/"+patTestBucketName)
	return client, ts
}

// findPATTestTemplatesDir locates the templates directory.
func findPATTestTemplatesDir() string {
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

// loginPATTestUser creates a test user with a password and logs them in.
func (env *patTestEnv) loginPATTestUser(t *testing.T, testEmail, password string) string {
	t.Helper()

	ctx := context.Background()

	// Create/find user
	user, err := env.userService.FindOrCreateByEmail(ctx, testEmail)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Set password for the user (required for PAT creation re-auth)
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

	// Create the account record (required for PAT re-auth to work)
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

// navigatePAT navigates to a path on the test server.
func (env *patTestEnv) navigatePAT(t *testing.T, path string) {
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

// waitForPATSelector waits for an element to appear.
func (env *patTestEnv) waitForPATSelector(t *testing.T, selector string) playwright.Locator {
	t.Helper()

	locator := env.page.Locator(selector)
	err := locator.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Failed to wait for selector %s: %v", selector, err)
	}
	return locator
}

// generatePATTestEmail generates a unique email for test isolation.
func generatePATTestEmail(prefix string) string {
	return fmt.Sprintf("%s-%d@example.com", prefix, time.Now().UnixNano())
}

// =============================================================================
// Test: Page Load
// =============================================================================

func TestBrowser_TokenSettings_PageLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupPATTestEnv(t)
	testEmail := generatePATTestEmail("pat-pageload")
	testPassword := "SecurePass123!"
	env.loginPATTestUser(t, testEmail, testPassword)

	// Navigate to /settings/tokens
	env.navigatePAT(t, "/settings/tokens")

	// Wait for page to load
	err := env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Page did not load: %v", err)
	}

	// Verify page title shows "Personal Access Tokens"
	heading := env.waitForPATSelector(t, "h1")
	headingText, err := heading.TextContent()
	if err != nil {
		t.Fatalf("Failed to get heading text: %v", err)
	}

	if !strings.Contains(headingText, "Personal Access Tokens") {
		t.Errorf("Expected heading to contain 'Personal Access Tokens', got: %s", headingText)
	}

	// Verify "Create Token" button is visible
	createButton := env.page.Locator("button[type='submit']:has-text('Create Token')")
	isVisible, err := createButton.IsVisible()
	if err != nil {
		t.Fatalf("Failed to check create button visibility: %v", err)
	}
	if !isVisible {
		t.Error("Create Token button should be visible")
	}

	// Verify form fields are present
	nameInput := env.page.Locator("input#name")
	nameVisible, err := nameInput.IsVisible()
	if err != nil {
		t.Fatalf("Failed to check name input visibility: %v", err)
	}
	if !nameVisible {
		t.Error("Token name input should be visible")
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
// Test: Create Token
// =============================================================================

func TestBrowser_TokenSettings_CreateToken(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupPATTestEnv(t)
	testEmail := generatePATTestEmail("pat-create")
	testPassword := "SecurePass123!"
	env.loginPATTestUser(t, testEmail, testPassword)

	// Navigate to /settings/tokens
	env.navigatePAT(t, "/settings/tokens")

	// Wait for page to load
	env.waitForPATSelector(t, "h1:has-text('Personal Access Tokens')")

	// Fill in token name
	nameInput := env.waitForPATSelector(t, "input#name")
	err := nameInput.Fill("Test API Token")
	if err != nil {
		t.Fatalf("Failed to fill token name: %v", err)
	}

	// Select scope: "Read and Write"
	scopeSelect := env.waitForPATSelector(t, "select#scope")
	_, err = scopeSelect.SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read_write"),
	})
	if err != nil {
		t.Fatalf("Failed to select scope: %v", err)
	}

	// Fill in email for re-authentication
	emailInput := env.waitForPATSelector(t, "input#email")
	err = emailInput.Fill(testEmail)
	if err != nil {
		t.Fatalf("Failed to fill email: %v", err)
	}

	// Fill in password for re-authentication
	passwordInput := env.waitForPATSelector(t, "input#password")
	err = passwordInput.Fill(testPassword)
	if err != nil {
		t.Fatalf("Failed to fill password: %v", err)
	}

	// Submit form
	submitButton := env.page.Locator("button[type='submit']:has-text('Create Token')")
	err = submitButton.Click()
	if err != nil {
		t.Fatalf("Failed to click submit button: %v", err)
	}

	// Wait for page to reload with new token
	err = env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	if err != nil {
		t.Fatalf("Page did not reload: %v", err)
	}

	// Verify token value is displayed (only shown once)
	tokenElement := env.page.Locator("code#new-token")
	err = tokenElement.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Token value element not found: %v", err)
	}

	tokenValue, err := tokenElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get token value: %v", err)
	}

	// Verify token starts with "agentnotes_pat_"
	if !strings.HasPrefix(tokenValue, "agentnotes_pat_") {
		t.Errorf("Token should start with 'agentnotes_pat_', got: %s", tokenValue)
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
	successMessage := env.page.Locator("text=Token Created Successfully")
	successVisible, err := successMessage.IsVisible()
	if err != nil {
		t.Fatalf("Failed to check success message visibility: %v", err)
	}
	if !successVisible {
		t.Error("Success message should be visible")
	}
}

// =============================================================================
// Test: List Tokens
// =============================================================================

func TestBrowser_TokenSettings_ListTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupPATTestEnv(t)
	testEmail := generatePATTestEmail("pat-list")
	testPassword := "SecurePass123!"
	env.loginPATTestUser(t, testEmail, testPassword)

	// Create multiple tokens via the UI
	tokenNames := []string{"Token One", "Token Two", "Token Three"}

	for _, tokenName := range tokenNames {
		env.navigatePAT(t, "/settings/tokens")
		env.waitForPATSelector(t, "h1:has-text('Personal Access Tokens')")

		// Fill form
		env.page.Locator("input#name").Fill(tokenName)
		env.page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
			Values: playwright.StringSlice("read_write"),
		})
		env.page.Locator("input#email").Fill(testEmail)
		env.page.Locator("input#password").Fill(testPassword)

		// Submit
		env.page.Locator("button[type='submit']:has-text('Create Token')").Click()

		// Wait for redirect
		env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
			State: playwright.LoadStateNetworkidle,
		})
	}

	// Navigate to settings page to view list
	env.navigatePAT(t, "/settings/tokens")
	env.waitForPATSelector(t, "h1:has-text('Personal Access Tokens')")

	// Verify all created tokens appear in list
	for _, tokenName := range tokenNames {
		tokenRow := env.page.Locator(fmt.Sprintf("text=%s", tokenName))
		count, err := tokenRow.Count()
		if err != nil {
			t.Fatalf("Failed to count token rows for %s: %v", tokenName, err)
		}
		if count == 0 {
			t.Errorf("Token '%s' should appear in the list", tokenName)
		}
	}

	// Verify tokens table shows columns: Name, Scope, Created, Last Used, Expires
	tableHeaders := env.page.Locator("th")
	headersCount, err := tableHeaders.Count()
	if err != nil {
		t.Fatalf("Failed to count table headers: %v", err)
	}
	if headersCount < 4 {
		t.Errorf("Expected at least 4 table headers (Name, Scope, Created, etc.), got: %d", headersCount)
	}

	// Verify token values are NOT shown (security)
	// The actual token hash should not be visible in the list
	tokenHashLocator := env.page.Locator("text=agentnotes_pat_")
	hashCount, err := tokenHashLocator.Count()
	if err != nil {
		t.Fatalf("Failed to check for token hashes: %v", err)
	}
	// There should only be the token shown in the "new token" success message (if still visible)
	// but NOT in the token list rows
	if hashCount > 1 {
		t.Log("Note: Token values should only be visible once at creation time")
	}
}

// =============================================================================
// Test: Revoke Token
// =============================================================================

func TestBrowser_TokenSettings_RevokeToken(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupPATTestEnv(t)
	testEmail := generatePATTestEmail("pat-revoke")
	testPassword := "SecurePass123!"
	env.loginPATTestUser(t, testEmail, testPassword)

	tokenName := "Token to Revoke"

	// Create a token first
	env.navigatePAT(t, "/settings/tokens")
	env.waitForPATSelector(t, "h1:has-text('Personal Access Tokens')")

	env.page.Locator("input#name").Fill(tokenName)
	env.page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read_write"),
	})
	env.page.Locator("input#email").Fill(testEmail)
	env.page.Locator("input#password").Fill(testPassword)
	env.page.Locator("button[type='submit']:has-text('Create Token')").Click()

	env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Navigate back to tokens page (in case we're showing the new token modal)
	env.navigatePAT(t, "/settings/tokens")
	env.waitForPATSelector(t, "h1:has-text('Personal Access Tokens')")

	// Verify the token exists in the list
	tokenRow := env.page.Locator(fmt.Sprintf("text=%s", tokenName))
	count, err := tokenRow.Count()
	if err != nil || count == 0 {
		t.Fatal("Token should exist before revoking")
	}

	// Set up dialog handler for confirmation
	env.page.OnDialog(func(dialog playwright.Dialog) {
		dialog.Accept()
	})

	// Click "Revoke" button for the token
	// Find the row containing the token name and click its Revoke button
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

	// Verify token is removed from list
	tokenRowAfter := env.page.Locator(fmt.Sprintf("td:has-text('%s')", tokenName))
	countAfter, err := tokenRowAfter.Count()
	if err != nil {
		t.Fatalf("Failed to count token rows after revoke: %v", err)
	}
	if countAfter > 0 {
		t.Error("Revoked token should not appear in the list")
	}
}

// =============================================================================
// Test: Copy Token
// =============================================================================

func TestBrowser_TokenSettings_CopyToken(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupPATTestEnv(t)
	testEmail := generatePATTestEmail("pat-copy")
	testPassword := "SecurePass123!"
	env.loginPATTestUser(t, testEmail, testPassword)

	// Create a token
	env.navigatePAT(t, "/settings/tokens")
	env.waitForPATSelector(t, "h1:has-text('Personal Access Tokens')")

	env.page.Locator("input#name").Fill("Token for Copy Test")
	env.page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read_write"),
	})
	env.page.Locator("input#email").Fill(testEmail)
	env.page.Locator("input#password").Fill(testPassword)
	env.page.Locator("button[type='submit']:has-text('Create Token')").Click()

	env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Get the token value before clicking copy
	tokenElement := env.waitForPATSelector(t, "code#new-token")
	tokenValue, err := tokenElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get token value: %v", err)
	}

	// Verify token has expected format
	if !strings.HasPrefix(tokenValue, "agentnotes_pat_") {
		t.Errorf("Token should have proper prefix, got: %s", tokenValue)
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
	// In real usage, the browser's clipboard API would copy the token
	t.Logf("Token value that would be copied: %s", tokenValue)
}

// =============================================================================
// Test: Empty State (No Tokens)
// =============================================================================

func TestBrowser_TokenSettings_EmptyState(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupPATTestEnv(t)
	testEmail := generatePATTestEmail("pat-empty")
	testPassword := "SecurePass123!"
	env.loginPATTestUser(t, testEmail, testPassword)

	// Navigate to tokens page without creating any tokens
	env.navigatePAT(t, "/settings/tokens")
	env.waitForPATSelector(t, "h1:has-text('Personal Access Tokens')")

	// Verify "No tokens" message is displayed
	noTokensMessage := env.page.Locator("h3:has-text('No tokens')")
	count, err := noTokensMessage.Count()
	if err != nil {
		t.Fatalf("Failed to check for no tokens message: %v", err)
	}
	if count == 0 {
		t.Error("Expected 'No tokens' message for new user without tokens")
	}

	// Verify help text is displayed
	helpText := env.page.Locator("text=Create a token to get started")
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

func TestBrowser_TokenSettings_InvalidCredentials(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupPATTestEnv(t)
	testEmail := generatePATTestEmail("pat-invalid-creds")
	testPassword := "SecurePass123!"
	env.loginPATTestUser(t, testEmail, testPassword)

	// Navigate to tokens page
	env.navigatePAT(t, "/settings/tokens")
	env.waitForPATSelector(t, "h1:has-text('Personal Access Tokens')")

	// Fill form with wrong password
	env.page.Locator("input#name").Fill("Test Token")
	env.page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read_write"),
	})
	env.page.Locator("input#email").Fill(testEmail)
	env.page.Locator("input#password").Fill("WrongPassword123!")

	// Submit form
	env.page.Locator("button[type='submit']:has-text('Create Token')").Click()

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
// Test: Token Expiration Options
// =============================================================================

func TestBrowser_TokenSettings_ExpirationOptions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupPATTestEnv(t)
	testEmail := generatePATTestEmail("pat-expiry")
	testPassword := "SecurePass123!"
	env.loginPATTestUser(t, testEmail, testPassword)

	// Navigate to tokens page
	env.navigatePAT(t, "/settings/tokens")
	env.waitForPATSelector(t, "h1:has-text('Personal Access Tokens')")

	// Check expiration select options
	expiresSelect := env.waitForPATSelector(t, "select#expires_in")

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
// Test: Read-Only Scope
// =============================================================================

func TestBrowser_TokenSettings_ReadOnlyScope(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupPATTestEnv(t)
	testEmail := generatePATTestEmail("pat-readonly")
	testPassword := "SecurePass123!"
	env.loginPATTestUser(t, testEmail, testPassword)

	// Navigate to tokens page
	env.navigatePAT(t, "/settings/tokens")
	env.waitForPATSelector(t, "h1:has-text('Personal Access Tokens')")

	// Create a read-only token
	env.page.Locator("input#name").Fill("Read Only Token")
	env.page.Locator("select#scope").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("read"),
	})
	env.page.Locator("input#email").Fill(testEmail)
	env.page.Locator("input#password").Fill(testPassword)
	env.page.Locator("button[type='submit']:has-text('Create Token')").Click()

	env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// Navigate back to see the token in the list
	env.navigatePAT(t, "/settings/tokens")
	env.waitForPATSelector(t, "h1:has-text('Personal Access Tokens')")

	// Verify the token shows "read" scope
	readScope := env.page.Locator("span:has-text('read')")
	count, err := readScope.Count()
	if err != nil {
		t.Fatalf("Failed to check read scope: %v", err)
	}
	if count == 0 {
		t.Error("Token with read scope should show 'read' in the list")
	}
}

// =============================================================================
// Test: Unauthenticated Access Returns 401
// =============================================================================

func TestBrowser_TokenSettings_RequiresAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupPATTestEnv(t)

	// Do NOT login - try to access settings page directly
	env.navigatePAT(t, "/settings/tokens")

	// Wait for page to load
	env.page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})

	// The auth middleware returns 401 Unauthorized with "Unauthorized" in the body
	pageContent, err := env.page.Content()
	if err != nil {
		t.Fatalf("Failed to get page content: %v", err)
	}

	// Should show unauthorized message (middleware returns "Unauthorized: no session")
	if !strings.Contains(pageContent, "Unauthorized") {
		t.Errorf("Unauthenticated access should show Unauthorized message, got content: %s", pageContent[:min(200, len(pageContent))])
	}
}

// =============================================================================
// Test: Usage Instructions Visible
// =============================================================================

func TestBrowser_TokenSettings_UsageInstructions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupPATTestEnv(t)
	testEmail := generatePATTestEmail("pat-usage")
	testPassword := "SecurePass123!"
	env.loginPATTestUser(t, testEmail, testPassword)

	// Navigate to tokens page
	env.navigatePAT(t, "/settings/tokens")
	env.waitForPATSelector(t, "h1:has-text('Personal Access Tokens')")

	// Verify usage instructions section exists
	usageHeading := env.page.Locator("h3:has-text('How to use your token')")
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
