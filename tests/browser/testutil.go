// Package browser provides shared test utilities for Playwright browser tests.
// All browser test files use BrowserTestEnv via SetupBrowserTestEnv(t).
package browser

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-contrib/sse"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/playwright-community/playwright-go"

	"github.com/kuitang/agent-notes/internal/apps"
	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/billing"
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/email"
	"github.com/kuitang/agent-notes/internal/mcp"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/kuitang/agent-notes/internal/ratelimit"
	"github.com/kuitang/agent-notes/internal/s3client"
	"github.com/kuitang/agent-notes/internal/shorturl"
	"github.com/kuitang/agent-notes/internal/web"

	e2etestutil "github.com/kuitang/agent-notes/tests/e2e/testutil"
)

const (
	browserTestBucketName = "browser-test-bucket"
	browserTestMasterKey  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 64 hex chars = 32 bytes

	// CODING AGENT RULE: Always use these timeout constants for browser tests.
	// Never introduce a larger timeout value anywhere in tests/browser.
	browserMaxTimeoutMS = 5000
	browserMaxTimeout   = 5 * time.Second

	// Exported aliases for subpackages under tests/browser.
	BrowserMaxTimeoutMS = browserMaxTimeoutMS
	BrowserMaxTimeout   = browserMaxTimeout
)

var browserFixtureMu sync.Mutex
var browserSharedFixture *BrowserTestEnv

// BrowserTestEnv is the unified test environment for all browser tests.
// Every test gets the full mux: auth routes, mock OIDC, static pages, real CRUD, short URLs, API keys.
type BrowserTestEnv struct {
	Server         *httptest.Server
	BaseURL        string
	SessionsDB     *db.SessionsDB
	KeyManager     *crypto.KeyManager
	UserService    *auth.UserService
	SessionService *auth.SessionService
	ConsentService *auth.ConsentService
	EmailService   *email.MockEmailService
	AuthMiddleware *auth.Middleware
	S3Client       *s3client.Client
	Renderer       *web.Renderer
	RateLimiter    *ratelimit.RateLimiter
	PublicNotes    *notes.PublicNoteService
	ShortURLSvc    *shorturl.Service
	LocalMockOIDC  *auth.LocalMockOIDCProvider
	SpriteToken    string
	TempDir        string

	pw        *playwright.Playwright
	browser   playwright.Browser
	browserMu sync.Mutex

	fakeS3Server *httptest.Server
}

// SetupBrowserTestEnv creates a fully wired test server with all services.
func SetupBrowserTestEnv(t *testing.T) *BrowserTestEnv {
	t.Helper()

	env := getOrCreateSharedBrowserTestEnv(t)
	resetSharedBrowserTestEnvState(t, env)
	return env
}

func getOrCreateSharedBrowserTestEnv(t *testing.T) *BrowserTestEnv {
	t.Helper()

	browserFixtureMu.Lock()
	defer browserFixtureMu.Unlock()

	if browserSharedFixture != nil {
		if err := browserSharedFixture.SessionsDB.DB().Ping(); err == nil {
			return browserSharedFixture
		}
		cleanupSharedBrowserTestEnvLocked()
	}

	tempDir, err := os.MkdirTemp("", "browser-shared-*")
	if err != nil {
		t.Fatalf("Failed to create shared browser fixture temp dir: %v", err)
	}

	browserSharedFixture = createBrowserTestEnv(t, tempDir)
	return browserSharedFixture
}

func createBrowserTestEnv(t *testing.T, tempDir string) *BrowserTestEnv {
	t.Helper()

	db.ResetForTesting()
	db.DataDirectory = tempDir

	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		t.Fatalf("Failed to open sessions database: %v", err)
	}

	masterKey, err := hex.DecodeString(browserTestMasterKey)
	if err != nil {
		t.Fatalf("Failed to decode master key: %v", err)
	}
	keyManager := crypto.NewKeyManager(masterKey, sessionsDB)

	emailService := email.NewMockEmailService()
	sessionService := auth.NewSessionService(sessionsDB)
	consentService := auth.NewConsentService(sessionsDB)

	// Mock S3
	s3Client, fakeS3Server := createMockS3(t, browserTestBucketName)

	// Template renderer
	templatesDir := findTemplatesDir()
	renderer, err := web.NewRenderer(templatesDir)
	if err != nil {
		t.Fatalf("Failed to create renderer: %v", err)
	}

	// Auth middleware
	authMiddleware := auth.NewMiddleware(sessionService, keyManager)

	// Rate limiter (high limits for tests)
	rateLimiter := ratelimit.NewRateLimiter(ratelimit.Config{
		FreeRPS:         10000,
		FreeBurst:       100000,
		PaidRPS:         100000,
		PaidBurst:       1000000,
		CleanupInterval: time.Hour,
	})

	// Short URL service
	shortURLSvc := shorturl.NewService(sessionsDB.Queries())

	// Public notes service with short URL support — needs server URL, set after server created
	publicNotes := notes.NewPublicNoteService(s3Client)

	// Create mux + server once so all dependent services share a stable base URL.
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	// Wire services that need server URL
	userService := auth.NewUserService(sessionsDB, keyManager, emailService, server.URL, auth.FakeInsecureHasher{})
	publicNotes = publicNotes.WithShortURLService(shortURLSvc, server.URL)

	// Sprite token for MCP/apps
	spriteToken := os.Getenv("SPRITE_TOKEN")

	// Local mock OIDC
	localMockOIDC := auth.NewLocalMockOIDCProvider(server.URL)

	// Web handler
	webHandler := web.NewWebHandler(
		renderer,
		nil, // notesService created per-request
		publicNotes,
		userService,
		sessionService,
		consentService,
		s3Client,
		shortURLSvc,
		billing.NewMockService(),
		server.URL,
		spriteToken,
	)

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// Web + auth routes
	webHandler.RegisterRoutes(mux, authMiddleware)

	// Auth handler (OIDC, login, register)
	authHandler := auth.NewHandler(localMockOIDC, userService, sessionService)
	authHandler.RegisterRoutes(mux)
	localMockOIDC.RegisterRoutes(mux)

	// Static page handler
	staticSrcDir := findStaticSrcDir()
	staticHandler := web.NewStaticHandler(renderer, staticSrcDir, authMiddleware)
	staticHandler.RegisterRoutes(mux)

	// Rate-limited notes API
	getUserID := func(r *http.Request) string { return auth.GetUserID(r.Context()) }
	getIsPaid := func(r *http.Request) bool { return false }
	rateLimitMW := ratelimit.RateLimitMiddleware(rateLimiter, getUserID, getIsPaid)

	// Notes API uses real CRUD (auth middleware opens user DB)
	mux.Handle("GET /api/notes", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(apiNotesListHandler))))
	mux.Handle("POST /api/notes", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(apiNotesCreateHandler))))
	mux.Handle("GET /api/notes/{id}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(apiNotesGetHandler))))
	mux.Handle("PUT /api/notes/{id}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(apiNotesPutHandler))))
	mux.Handle("DELETE /api/notes/{id}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(apiNotesDeleteHandler))))

	// MCP handler (authenticated, all tools) - shared server built once
	mcpHandler := &authenticatedMCPHandler{
		Server:      mcp.NewServer(mcp.ToolsetAll),
		Toolset:     mcp.ToolsetAll,
		SpriteToken: spriteToken,
	}
	mux.Handle("POST /mcp", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(mcpHandler.ServeHTTP))))

	// Apps management API routes (authenticated)
	appsHandler := &authenticatedAppsHandler{
		SpriteToken: spriteToken,
		Renderer:    renderer,
	}
	mux.Handle("GET /api/apps", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(appsHandler.ListApps))))
	mux.Handle("GET /api/apps/{name}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(appsHandler.GetApp))))
	mux.Handle("DELETE /api/apps/{name}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(appsHandler.DeleteApp))))
	mux.Handle("GET /api/apps/{name}/files", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(appsHandler.ListFiles))))
	mux.Handle("GET /api/apps/{name}/files/{path...}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(appsHandler.GetFile))))
	mux.Handle("GET /api/apps/{name}/logs", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(appsHandler.GetLogs))))
	mux.Handle("GET /api/apps/{name}/stream", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(appsHandler.StreamApp))))
	mux.Handle("POST /api/apps/{name}/{action}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(appsHandler.HandleAction))))

	env := &BrowserTestEnv{
		Server:         server,
		BaseURL:        server.URL,
		SessionsDB:     sessionsDB,
		KeyManager:     keyManager,
		UserService:    userService,
		SessionService: sessionService,
		ConsentService: consentService,
		EmailService:   emailService,
		AuthMiddleware: authMiddleware,
		S3Client:       s3Client,
		Renderer:       renderer,
		RateLimiter:    rateLimiter,
		PublicNotes:    publicNotes,
		ShortURLSvc:    shortURLSvc,
		LocalMockOIDC:  localMockOIDC,
		SpriteToken:    spriteToken,
		TempDir:        tempDir,
		fakeS3Server:   fakeS3Server,
	}
	return env
}

func resetSharedBrowserTestEnvState(t *testing.T, env *BrowserTestEnv) {
	t.Helper()

	// Ensure shared fixture always points at its pinned temp dir.
	db.DataDirectory = env.TempDir

	if err := clearSharedBrowserSessionsDB(env.SessionsDB); err != nil {
		t.Fatalf("Failed to reset shared browser sessions database: %v", err)
	}
	if err := removeStaleBrowserUserDBs(env.TempDir); err != nil {
		t.Fatalf("Failed to reset shared browser user databases: %v", err)
	}
	db.ResetUserDBsForTesting()
	if env.EmailService != nil {
		env.EmailService.Clear()
	}
}

func clearSharedBrowserSessionsDB(sessionsDB *db.SessionsDB) error {
	tx, err := sessionsDB.DB().Begin()
	if err != nil {
		return fmt.Errorf("begin reset transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	for _, table := range e2etestutil.SharedFixtureSessionTables {
		if _, err := tx.Exec("DELETE FROM " + table); err != nil {
			return fmt.Errorf("clear %s: %w", table, err)
		}
	}

	// Ignore if sqlite_sequence does not exist.
	_, _ = tx.Exec("DELETE FROM sqlite_sequence WHERE name = 'short_urls'")

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit reset transaction: %w", err)
	}
	return nil
}

func removeStaleBrowserUserDBs(tempDir string) error {
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		return fmt.Errorf("read fixture temp dir: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) != ".db" || name == db.SessionsDBName {
			continue
		}
		if err := os.Remove(filepath.Join(tempDir, name)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale user db %q: %w", name, err)
		}
	}
	return nil
}

func cleanupSharedBrowserTestEnv() {
	browserFixtureMu.Lock()
	defer browserFixtureMu.Unlock()
	cleanupSharedBrowserTestEnvLocked()
}

func cleanupSharedBrowserTestEnvLocked() {
	if browserSharedFixture == nil {
		return
	}
	if browserSharedFixture.browser != nil {
		_ = browserSharedFixture.browser.Close()
	}
	if browserSharedFixture.pw != nil {
		_ = browserSharedFixture.pw.Stop()
	}
	if browserSharedFixture.Server != nil {
		browserSharedFixture.Server.Close()
	}
	if browserSharedFixture.fakeS3Server != nil {
		browserSharedFixture.fakeS3Server.Close()
	}
	if browserSharedFixture.RateLimiter != nil {
		browserSharedFixture.RateLimiter.Stop()
	}
	if browserSharedFixture.TempDir != "" {
		_ = os.RemoveAll(browserSharedFixture.TempDir)
	}
	db.ResetForTesting()
	browserSharedFixture = nil
}

func TestMain(m *testing.M) {
	code := m.Run()
	cleanupSharedBrowserTestEnv()
	os.Exit(code)
}

// =============================================================================
// Notes API handlers (real CRUD via auth context's user DB)
// =============================================================================

func apiNotesListHandler(w http.ResponseWriter, r *http.Request) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"notes":[]}`))
		return
	}
	svc := notes.NewService(userDB, notes.FreeStorageLimitBytes)
	result, err := svc.List(50, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"notes":%d}`, len(result.Notes))
}

func apiNotesCreateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"id":"test-note-1","title":"Test","content":""}`))
}

func apiNotesGetHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func apiNotesPutHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func apiNotesDeleteHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// S3 mock
// =============================================================================

func createMockS3(t *testing.T, bucketName string) (*s3client.Client, *httptest.Server) {
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
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Fatalf("Failed to create mock S3 bucket: %v", err)
	}

	client := s3client.NewFromS3Client(s3SDK, bucketName, ts.URL+"/"+bucketName)
	return client, ts
}

// =============================================================================
// Directory finders
// =============================================================================

func findTemplatesDir() string {
	repoRoot := repositoryRoot()
	candidates := []string{
		filepath.Join(repoRoot, "web", "templates"),
	}
	for _, dir := range candidates {
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}
	panic("Cannot find templates directory")
}

func findStaticSrcDir() string {
	repoRoot := repositoryRoot()
	candidates := []string{
		filepath.Join(repoRoot, "static", "src"),
	}
	for _, dir := range candidates {
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}
	panic("Cannot find static source directory")
}

func repositoryRoot() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("Failed to resolve repository root for test utilities")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

// =============================================================================
// Browser lifecycle helpers
// =============================================================================

// InitBrowser initializes Playwright and launches Chromium. Skips the test if not available.
func (env *BrowserTestEnv) InitBrowser(t *testing.T) {
	t.Helper()

	env.browserMu.Lock()
	defer env.browserMu.Unlock()

	if env.browser != nil {
		return
	}

	pw, err := playwright.Run()
	if err != nil {
		t.Skip("Playwright not available:", err)
	}

	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
	})
	if err != nil {
		_ = pw.Stop()
		t.Skip("Could not launch browser:", err)
	}
	env.pw = pw
	env.browser = browser
}

// NewPage creates a new browser page with default 5s timeout.
func (env *BrowserTestEnv) NewPage(t *testing.T) playwright.Page {
	t.Helper()

	page, err := env.browser.NewPage()
	if err != nil {
		t.Fatalf("could not create page: %v", err)
	}
	page.SetDefaultTimeout(browserMaxTimeoutMS)
	page.SetDefaultNavigationTimeout(browserMaxTimeoutMS)
	return page
}

// NewContext creates a new browser context.
func (env *BrowserTestEnv) NewContext(t *testing.T) playwright.BrowserContext {
	t.Helper()

	ctx, err := env.browser.NewContext()
	if err != nil {
		t.Fatalf("could not create browser context: %v", err)
	}
	ctx.SetDefaultTimeout(browserMaxTimeoutMS)
	ctx.SetDefaultNavigationTimeout(browserMaxTimeoutMS)
	return ctx
}

// NewContextWithOptions creates a new browser context with caller-provided options.
func (env *BrowserTestEnv) NewContextWithOptions(t *testing.T, options playwright.BrowserNewContextOptions) playwright.BrowserContext {
	t.Helper()

	ctx, err := env.browser.NewContext(options)
	if err != nil {
		t.Fatalf("could not create browser context with options: %v", err)
	}
	ctx.SetDefaultTimeout(browserMaxTimeoutMS)
	ctx.SetDefaultNavigationTimeout(browserMaxTimeoutMS)
	return ctx
}

// =============================================================================
// Navigation and wait helpers
// =============================================================================

// Navigate navigates to a path on the test server and waits for DOMContentLoaded.
func Navigate(t *testing.T, page playwright.Page, baseURL, path string) {
	t.Helper()

	_, err := page.Goto(baseURL+path, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		Timeout:   playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to navigate to %s: %v", path, err)
	}
}

// WaitForSelector waits for an element to be visible and returns its locator.
func WaitForSelector(t *testing.T, page playwright.Page, selector string) playwright.Locator {
	t.Helper()

	locator := page.Locator(selector)
	first := locator.First()
	err := first.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		currentURL := page.URL()
		title, _ := page.Title()
		content, _ := page.Content()
		if len(content) > 500 {
			content = content[:500] + "..."
		}
		t.Logf("Current URL: %s", currentURL)
		t.Logf("Current title: %s", title)
		t.Logf("Content preview: %s", content)
		t.Fatalf("Failed to wait for selector %s: %v", selector, err)
	}
	return first
}

// =============================================================================
// User/session helpers
// =============================================================================

// CreateUser creates a user via FindOrCreateByProvider and returns the user ID.
func (env *BrowserTestEnv) CreateUser(t *testing.T, emailAddr string) string {
	t.Helper()
	ctx := context.Background()
	user, err := env.UserService.FindOrCreateByProvider(ctx, emailAddr)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	return user.ID
}

// LoginAs creates a session for the given user ID and returns the session ID.
func (env *BrowserTestEnv) LoginAs(t *testing.T, userID string) string {
	t.Helper()
	ctx := context.Background()
	sessionID, err := env.SessionService.Create(ctx, userID)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	return sessionID
}

// SetSessionCookie sets the session cookie on a Playwright browser context.
func SetSessionCookie(t *testing.T, ctx playwright.BrowserContext, sessionID string) {
	t.Helper()
	err := ctx.AddCookies([]playwright.OptionalCookie{
		{
			Name:     auth.SessionCookieName,
			Value:    sessionID,
			Domain:   playwright.String("127.0.0.1"),
			Path:     playwright.String("/"),
			HttpOnly: playwright.Bool(true),
			Secure:   playwright.Bool(false),
			SameSite: playwright.SameSiteAttributeLax,
		},
	})
	if err != nil {
		t.Fatalf("Failed to set session cookie: %v", err)
	}
}

// LoginUser creates a user, creates a session, and sets the session cookie.
// Returns the user ID.
func (env *BrowserTestEnv) LoginUser(t *testing.T, ctx playwright.BrowserContext, emailAddr string) string {
	t.Helper()
	userID := env.CreateUser(t, emailAddr)
	sessionID := env.LoginAs(t, userID)
	SetSessionCookie(t, ctx, sessionID)
	return userID
}

// CreateNoteForUser seeds a note directly in the user's encrypted DB.
func (env *BrowserTestEnv) CreateNoteForUser(t *testing.T, userID, title, content string) string {
	t.Helper()

	dek, err := env.KeyManager.GetUserDEK(userID)
	if err != nil {
		t.Fatalf("Failed to get DEK for user %s: %v", userID, err)
	}

	userDB, err := db.OpenUserDBWithDEK(userID, dek)
	if err != nil {
		t.Fatalf("Failed to open user DB for %s: %v", userID, err)
	}

	noteSvc := notes.NewService(userDB, notes.FreeStorageLimitBytes)
	created, err := noteSvc.Create(notes.CreateNoteParams{
		Title:   title,
		Content: content,
	})
	if err != nil {
		t.Fatalf("Failed to create seeded note for %s: %v", userID, err)
	}
	return created.ID
}

// SetUserSubscription updates a user's subscription status and Stripe customer ID in their encrypted DB.
func (env *BrowserTestEnv) SetUserSubscription(t *testing.T, userID, status, stripeCustomerID string) {
	t.Helper()

	dek, err := env.KeyManager.GetUserDEK(userID)
	if err != nil {
		t.Fatalf("Failed to get DEK for user %s: %v", userID, err)
	}

	userDB, err := db.OpenUserDBWithDEK(userID, dek)
	if err != nil {
		t.Fatalf("Failed to open user DB for %s: %v", userID, err)
	}

	_, err = userDB.DB().Exec(
		`UPDATE account SET subscription_status = ?, stripe_customer_id = ? WHERE user_id = ?`,
		status, stripeCustomerID, userID,
	)
	if err != nil {
		t.Fatalf("Failed to update subscription for user %s: %v", userID, err)
	}
}

// GenerateUniqueEmail generates a unique email for test isolation.
func GenerateUniqueEmail(prefix string) string {
	suffix := make([]byte, 8)
	if _, err := crand.Read(suffix); err != nil {
		panic(fmt.Sprintf("failed to generate unique email suffix: %v", err))
	}
	return fmt.Sprintf("%s-%s@example.com", prefix, hex.EncodeToString(suffix))
}

// GenerateUniqueAppName generates a globally unique app name-safe identifier.
func GenerateUniqueAppName(prefix string) string {
	suffix := make([]byte, 16)
	if _, err := crand.Read(suffix); err != nil {
		panic(fmt.Sprintf("failed to generate unique app name suffix: %v", err))
	}
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(suffix))
}

// =============================================================================
// UI action helpers
// =============================================================================

// CreateNoteViaUI fills the new note form and submits it, waiting for redirect to the note view.
func CreateNoteViaUI(t *testing.T, page playwright.Page, baseURL, title, content string) {
	t.Helper()

	Navigate(t, page, baseURL, "/notes/new")

	titleInput := WaitForSelector(t, page, "input#title")
	contentTextarea := WaitForSelector(t, page, "textarea#content")

	if err := titleInput.Fill(title); err != nil {
		t.Fatalf("Failed to fill title: %v", err)
	}
	if err := contentTextarea.Fill(content); err != nil {
		t.Fatalf("Failed to fill content: %v", err)
	}

	submitButton := page.Locator("button[type='submit']:has-text('Create')")
	if err := submitButton.Click(); err != nil {
		t.Fatalf("Failed to click submit: %v", err)
	}

	err := page.WaitForURL(fmt.Sprintf("%s/notes/**", baseURL), playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(browserMaxTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to wait for note view page after create: %v", err)
	}
}

// PublishNoteViaUI clicks "Make Public", waits for reload, and returns the short share URL.
func PublishNoteViaUI(t *testing.T, page playwright.Page) string {
	t.Helper()

	publishBtn := page.Locator("button:has-text('Make Public')")
	if err := publishBtn.Click(); err != nil {
		t.Fatalf("Failed to click Make Public: %v", err)
	}

	err := page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	if err != nil {
		t.Fatalf("Failed to wait for page load after publish: %v", err)
	}

	shareURLInput := page.Locator("input#share-url")
	shareURL, err := shareURLInput.InputValue()
	if err != nil {
		t.Fatalf("Failed to get share URL: %v", err)
	}
	if shareURL == "" {
		t.Fatal("share URL is empty after publishing")
	}
	return shareURL
}

// =============================================================================
// Authenticated MCP handler (local copy for browser test env)
// =============================================================================

// authenticatedMCPHandler wraps MCP with auth context for the browser test env.
// The Server field holds a shared MCP server; per-user services are injected via context.
type authenticatedMCPHandler struct {
	Server      *mcp.Server // shared, built once
	Toolset     mcp.Toolset
	SpriteToken string
}

func (h *authenticatedMCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	userID := auth.GetUserID(r.Context())

	var notesSvc *notes.Service
	if h.Toolset != mcp.ToolsetApps {
		storageLimit := notes.FreeStorageLimitBytes
		account, err := userDB.Queries().GetAccount(r.Context(), userID)
		if err == nil && account.SubscriptionStatus.Valid {
			storageLimit = notes.StorageLimitForStatus(account.SubscriptionStatus.String)
		}
		notesSvc = notes.NewService(userDB, storageLimit)
		_ = notesSvc.Purge(30 * 24 * time.Hour)
	}

	var appsSvc *apps.Service
	if h.Toolset != mcp.ToolsetNotes {
		appsSvc = apps.NewService(userDB, userID, h.SpriteToken)
	}

	ctx := mcp.ContextWithServices(r.Context(), notesSvc, appsSvc)
	h.Server.ServeHTTP(w, r.WithContext(ctx))
}

// =============================================================================
// Authenticated apps handler (local copy for browser test env)
// =============================================================================

// authenticatedAppsHandler wraps apps management API operations with auth context.
type authenticatedAppsHandler struct {
	SpriteToken string
	Renderer    *web.Renderer
}

func (h *authenticatedAppsHandler) getService(r *http.Request) (*apps.Service, error) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		return nil, fmt.Errorf("no user database in context")
	}
	userID := auth.GetUserID(r.Context())
	return apps.NewService(userDB, userID, h.SpriteToken), nil
}

func hashTestJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:])
}

// TestSSEEventBody builds a valid SSE payload for an event and payload.
// This keeps browser fixtures aligned with the server-side SSE encoding.
func TestSSEEventBody(event string, payload any) string {
	var buf bytes.Buffer
	if err := sse.Encode(&buf, sse.Event{
		Event: event,
		Data:  payload,
	}); err != nil {
		return ""
	}
	return buf.String()
}

func writeTestSSEEvent(w http.ResponseWriter, flusher http.Flusher, event string, payload any) bool {
	if err := sse.Encode(w, sse.Event{
		Event: event,
		Data:  payload,
	}); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

func testFirstServiceName(servicesOutput string) string {
	output := strings.TrimSpace(servicesOutput)
	if output == "" {
		return ""
	}

	var list []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(output), &list); err == nil {
		for _, item := range list {
			name := strings.TrimSpace(item.Name)
			if name != "" {
				return name
			}
		}
	}

	var item struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(output), &item); err == nil {
		name := strings.TrimSpace(item.Name)
		if name != "" {
			return name
		}
	}

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.Contains(strings.ToLower(trimmed), "no services") {
			continue
		}
		if idx := strings.Index(trimmed, "[name:"); idx >= 0 {
			rest := trimmed[idx+len("[name:"):]
			if end := strings.Index(rest, "]"); end > 0 {
				name := strings.TrimSpace(rest[:end])
				if name != "" {
					return name
				}
			}
		}
		fields := strings.Fields(trimmed)
		if len(fields) > 0 {
			token := strings.TrimSpace(fields[0])
			token = strings.TrimPrefix(token, "[name:")
			token = strings.TrimSuffix(token, "]")
			if token != "" {
				return token
			}
		}
	}
	return ""
}

// TestFirstServiceName exposes service-name parsing for subpackage tests.
func TestFirstServiceName(servicesOutput string) string {
	return testFirstServiceName(servicesOutput)
}

func testLogStreamPayload(result *apps.AppLogsResult, err error) map[string]any {
	if err != nil {
		return map[string]any{
			"error": err.Error(),
		}
	}
	if result == nil {
		return map[string]any{
			"output":    "",
			"stderr":    "",
			"exit_code": 0,
		}
	}
	return map[string]any{
		"output":    result.Output,
		"stderr":    result.Stderr,
		"exit_code": result.ExitCode,
	}
}

func (h *authenticatedAppsHandler) renderFilesHTML(files []apps.AppFileEntry, filesErr string) (string, error) {
	if h.Renderer == nil {
		return "", fmt.Errorf("renderer is not configured")
	}
	rec := httptest.NewRecorder()
	if err := h.Renderer.RenderPartial(
		rec,
		"apps/detail.html",
		"app-files-list",
		map[string]any{
			"Files":    files,
			"FilesErr": filesErr,
		},
	); err != nil {
		return "", err
	}
	return rec.Body.String(), nil
}

func (h *authenticatedAppsHandler) ListApps(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		return
	}
	items, err := svc.List(r.Context())
	if err != nil {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeTestJSON(w, http.StatusOK, map[string]any{"apps": items})
}

func (h *authenticatedAppsHandler) GetApp(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		return
	}
	name := r.PathValue("name")
	item, err := svc.Get(r.Context(), name)
	if err != nil {
		writeTestJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeTestJSON(w, http.StatusOK, item)
}

func (h *authenticatedAppsHandler) DeleteApp(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		return
	}
	name := r.PathValue("name")
	result, err := svc.Delete(r.Context(), name)
	if err != nil {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeTestJSON(w, http.StatusOK, result)
}

func (h *authenticatedAppsHandler) ListFiles(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		return
	}
	name := r.PathValue("name")
	result, err := svc.ListFiles(r.Context(), name)
	if err != nil {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeTestJSON(w, http.StatusOK, result)
}

func (h *authenticatedAppsHandler) GetFile(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		return
	}
	name := r.PathValue("name")
	filePath := r.PathValue("path")
	result, err := svc.ReadFiles(r.Context(), name, []string{filePath})
	if err != nil {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeTestJSON(w, http.StatusOK, result)
}

func (h *authenticatedAppsHandler) GetLogs(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		return
	}
	name := r.PathValue("name")
	result, err := svc.TailLogs(r.Context(), name, 100)
	if err != nil {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeTestJSON(w, http.StatusOK, result)
}

func (h *authenticatedAppsHandler) StreamApp(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		return
	}

	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		writeTestJSON(w, http.StatusBadRequest, map[string]string{"error": "App name is required"})
		return
	}

	lines := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("lines")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			writeTestJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid lines parameter"})
			return
		}
		lines = parsed
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "Streaming not supported"})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	initialFiles, err := svc.ListFiles(r.Context(), name)
	if err != nil {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	initialLogs, err := svc.TailLogs(r.Context(), name, lines)
	if err != nil {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	filesHTML, err := h.renderFilesHTML(initialFiles.Files, "")
	if err != nil {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to render file list stream"})
		return
	}
	fileHash := hashTestJSON(map[string]string{"html": filesHTML})

	initialLogPayload := testLogStreamPayload(initialLogs, nil)
	logHash := hashTestJSON(initialLogPayload)

	if !writeTestSSEEvent(w, flusher, "file", map[string]any{"html": filesHTML}) {
		return
	}
	if !writeTestSSEEvent(w, flusher, "log", initialLogPayload) {
		return
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			sentEvent := false

			nextFiles, nextFilesErr := svc.ListFiles(r.Context(), name)
			nextFilesList := []apps.AppFileEntry{}
			nextFilesErrText := ""
			if nextFilesErr != nil {
				nextFilesErrText = nextFilesErr.Error()
			} else {
				nextFilesList = nextFiles.Files
			}
			nextFilesHTML, renderErr := h.renderFilesHTML(nextFilesList, nextFilesErrText)
			if renderErr != nil {
				return
			}
			nextFileHash := hashTestJSON(map[string]string{"html": nextFilesHTML})
			if nextFileHash != fileHash {
				fileHash = nextFileHash
				if !writeTestSSEEvent(w, flusher, "file", map[string]any{"html": nextFilesHTML}) {
					return
				}
				sentEvent = true
			}

			nextLogPayload := testLogStreamPayload(svc.TailLogs(r.Context(), name, lines))
			nextLogHash := hashTestJSON(nextLogPayload)
			if nextLogHash != logHash {
				logHash = nextLogHash
				if !writeTestSSEEvent(w, flusher, "log", nextLogPayload) {
					return
				}
				sentEvent = true
			}

			if sentEvent {
				continue
			}
			if !writeTestSSEEvent(w, flusher, "ping", map[string]any{
				"ts": time.Now().UTC().Format(time.RFC3339Nano),
			}) {
				return
			}
		}
	}
}

func (h *authenticatedAppsHandler) HandleAction(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		return
	}
	name := r.PathValue("name")
	action := r.PathValue("action")

	// Discover service name
	listResult, err := svc.RunExec(r.Context(), name, []string{"bash", "-lc", "sprite-env services list"}, 30)
	if err != nil {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	svcName := testFirstServiceName(listResult.Stdout)
	if svcName == "" {
		writeTestJSON(w, http.StatusBadRequest, map[string]string{"error": "No service registered"})
		return
	}

	var cmd string
	switch action {
	case "start":
		cmd = fmt.Sprintf("sprite-env services start %q", svcName)
	case "stop":
		cmd = fmt.Sprintf("sprite-env services stop %q", svcName)
	case "restart":
		cmd = fmt.Sprintf("sprite-env services stop %q && sprite-env services start %q", svcName, svcName)
	default:
		writeTestJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid action"})
		return
	}

	result, err := svc.RunExec(r.Context(), name, []string{"bash", "-lc", cmd}, 30)
	if err != nil {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeTestJSON(w, http.StatusOK, result)
}

func writeTestJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
