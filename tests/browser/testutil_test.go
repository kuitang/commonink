// Package browser provides shared test utilities for Playwright browser tests.
// All browser test files use BrowserTestEnv via SetupBrowserTestEnv(t).
package browser

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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
	"github.com/kuitang/agent-notes/internal/shorturl"
	"github.com/kuitang/agent-notes/internal/web"
)

const (
	browserTestBucketName = "browser-test-bucket"
	browserTestMasterKey  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 64 hex chars = 32 bytes
)

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

	pw      *playwright.Playwright
	browser playwright.Browser

	fakeS3Server *httptest.Server
}

// SetupBrowserTestEnv creates a fully wired test server with all services.
// Uses t.Cleanup for automatic teardown.
func SetupBrowserTestEnv(t *testing.T) *BrowserTestEnv {
	t.Helper()

	db.ResetForTesting()
	db.DataDirectory = t.TempDir()

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

	// Create mux + server first to get URL for services that need it
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	// Wire services that need server URL
	userService := auth.NewUserService(sessionsDB, keyManager, emailService, server.URL, auth.FakeInsecureHasher{})
	publicNotes = publicNotes.WithShortURLService(shortURLSvc, server.URL)

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
		server.URL,
	)

	// Close initial server, rebuild mux with all routes
	server.Close()
	mux = http.NewServeMux()

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

	// Final server
	server = httptest.NewServer(mux)
	localMockOIDC.SetBaseURL(server.URL)

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
		fakeS3Server:   fakeS3Server,
	}

	t.Cleanup(func() {
		if env.browser != nil {
			env.browser.Close()
		}
		if env.pw != nil {
			env.pw.Stop()
		}
		server.Close()
		fakeS3Server.Close()
		rateLimiter.Stop()
		db.CloseAll()
	})

	return env
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
	svc := notes.NewService(userDB)
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

// =============================================================================
// Browser lifecycle helpers
// =============================================================================

// InitBrowser initializes Playwright and launches Chromium. Skips the test if not available.
func (env *BrowserTestEnv) InitBrowser(t *testing.T) {
	t.Helper()

	pw, err := playwright.Run()
	if err != nil {
		t.Skip("Playwright not available:", err)
	}
	env.pw = pw

	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
	})
	if err != nil {
		pw.Stop()
		t.Skip("Could not launch browser:", err)
	}
	env.browser = browser
}

// NewPage creates a new browser page with default 10s timeout.
func (env *BrowserTestEnv) NewPage(t *testing.T) playwright.Page {
	t.Helper()

	page, err := env.browser.NewPage()
	if err != nil {
		t.Fatalf("could not create page: %v", err)
	}
	page.SetDefaultTimeout(10000)
	return page
}

// NewContext creates a new browser context.
func (env *BrowserTestEnv) NewContext(t *testing.T) playwright.BrowserContext {
	t.Helper()

	ctx, err := env.browser.NewContext()
	if err != nil {
		t.Fatalf("could not create browser context: %v", err)
	}
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
		Timeout:   playwright.Float(10000),
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
		Timeout: playwright.Float(5000),
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

// GenerateUniqueEmail generates a unique email for test isolation.
func GenerateUniqueEmail(prefix string) string {
	return fmt.Sprintf("%s-%d@example.com", prefix, time.Now().UnixNano())
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
		Timeout: playwright.Float(5000),
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
		State: playwright.LoadStateNetworkidle,
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
