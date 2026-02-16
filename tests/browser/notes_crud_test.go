// Package browser contains Playwright E2E tests for browser-based UI flows.
// These are deterministic scenario-based tests (NOT property-based).
//
// This file tests Notes CRUD operations via the web UI.
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

// notesCrudEnv holds all the components needed for notes CRUD browser testing.
// Named to avoid conflicts with other test files in this package.
type notesCrudEnv struct {
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

// setupNotesCrudEnv creates a complete test environment with a running server.
func setupNotesCrudEnv(t *testing.T) *notesCrudEnv {
	t.Helper()

	// Reset database singleton and set fresh data directory
	db.ResetForTesting()
	db.DataDirectory = t.TempDir()

	// Initialize sessions database (now uses fresh directory)
	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		t.Fatalf("Failed to open sessions database: %v", err)
	}

	// Generate a random master key for testing
	masterKey, err := crypto.GenerateDEK()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	keyManager := crypto.NewKeyManager(masterKey, sessionsDB)

	// Initialize services
	emailService := email.NewMockEmailService()
	sessionService := auth.NewSessionService(sessionsDB)
	userService := auth.NewUserService(sessionsDB, keyManager, emailService, "http://localhost:8080")
	consentService := auth.NewConsentService(sessionsDB)

	// Initialize mock S3
	s3Client, s3Server := setupMockS3ForCrud(t)

	// Initialize template renderer - use the actual templates
	templatesDir := findTemplatesDirForCrud()
	renderer, err := web.NewRenderer(templatesDir)
	if err != nil {
		t.Fatalf("Failed to initialize renderer: %v", err)
	}

	// Initialize public notes service
	publicNotes := notes.NewPublicNoteService(s3Client)

	// Initialize auth middleware
	authMiddleware := auth.NewMiddleware(sessionService, keyManager)

	// Initialize rate limiter (with high limits for testing)
	rateLimiter := ratelimit.NewRateLimiter(ratelimit.Config{
		FreeRPS:         10000.0, // High rate for testing
		FreeBurst:       100000,
		PaidRPS:         100000.0,
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
		nil, // shortURLSvc not needed for notes crud tests
		"http://localhost:8080",
	)
	webHandler.RegisterRoutes(mux, authMiddleware)

	// Note: WebHandler already registers auth routes, so we don't need authHandler here

	// Rate limiting middleware
	getUserID := func(r *http.Request) string {
		return auth.GetUserID(r.Context())
	}
	getIsPaid := func(r *http.Request) bool {
		return false
	}
	rateLimitMW := ratelimit.RateLimitMiddleware(rateLimiter, getUserID, getIsPaid)

	// Register protected notes API routes
	crudNotesHandler := &crudNotesAPIHandler{}
	mux.Handle("GET /api/notes", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(crudNotesHandler.listNotes))))
	mux.Handle("POST /api/notes", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(crudNotesHandler.createNote))))
	mux.Handle("GET /api/notes/{id}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(crudNotesHandler.getNote))))
	mux.Handle("PUT /api/notes/{id}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(crudNotesHandler.updateNote))))
	mux.Handle("DELETE /api/notes/{id}", rateLimitMW(authMiddleware.RequireAuth(http.HandlerFunc(crudNotesHandler.deleteNote))))

	// Create test server
	server := httptest.NewServer(mux)

	// Initialize Playwright
	pw, err := playwright.Run()
	if err != nil {
		server.Close()
		t.Fatalf("Failed to start Playwright: %v", err)
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

	env := &notesCrudEnv{
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

// setupMockS3ForCrud creates a mock S3 server and client for testing.
func setupMockS3ForCrud(t *testing.T) (*s3client.Client, *httptest.Server) {
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

	s3c := s3.NewFromConfig(sdkConfig, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(ts.URL)
		o.UsePathStyle = true
	})

	bucketName := "test-bucket-crud"
	_, err = s3c.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Fatalf("Failed to create mock S3 bucket: %v", err)
	}

	client := s3client.NewFromS3Client(s3c, bucketName, ts.URL+"/"+bucketName)
	return client, ts
}

// findTemplatesDirForCrud locates the templates directory.
func findTemplatesDirForCrud() string {
	// Try relative paths from the test file
	candidates := []string{
		"../../web/templates",
		"../../../web/templates",
		"web/templates",
	}

	for _, dir := range candidates {
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}

	// Fall back to absolute path
	return "/home/kuitang/git/agent-notes/web/templates"
}

// loginCrudTestUser creates a test user and logs them in, returning the session cookie.
func (env *notesCrudEnv) loginCrudTestUser(t *testing.T, testEmail string) {
	t.Helper()

	ctx := context.Background()

	// Create/find user
	user, err := env.userService.FindOrCreateByProvider(ctx, testEmail)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
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
}

// navigateCrud navigates to a path on the test server.
func (env *notesCrudEnv) navigateCrud(t *testing.T, path string) {
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

// waitForCrudSelector waits for an element to appear.
func (env *notesCrudEnv) waitForCrudSelector(t *testing.T, selector string) playwright.Locator {
	t.Helper()

	locator := env.page.Locator(selector)
	err := locator.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		// Debug: log the current page content and URL
		currentURL := env.page.URL()
		title, _ := env.page.Title()
		content, _ := env.page.Content()
		if len(content) > 500 {
			content = content[:500] + "..."
		}
		t.Logf("Current URL: %s", currentURL)
		t.Logf("Current title: %s", title)
		t.Logf("Content preview: %s", content)
		t.Fatalf("Failed to wait for selector %s: %v", selector, err)
	}
	return locator
}

// crudNotesAPIHandler wraps notes operations with auth context for testing.
type crudNotesAPIHandler struct{}

func (h *crudNotesAPIHandler) getService(r *http.Request) (*notes.Service, error) {
	userDB := auth.GetUserDB(r.Context())
	if userDB == nil {
		return nil, fmt.Errorf("no user database in context")
	}
	return notes.NewService(userDB), nil
}

func (h *crudNotesAPIHandler) listNotes(w http.ResponseWriter, r *http.Request) {
	svc, err := h.getService(r)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	result, err := svc.List(50, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"notes":%d}`, len(result.Notes))
}

func (h *crudNotesAPIHandler) getNote(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (h *crudNotesAPIHandler) createNote(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusCreated)
}

func (h *crudNotesAPIHandler) updateNote(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (h *crudNotesAPIHandler) deleteNote(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// generateUniqueEmail generates a unique email for test isolation.
func generateUniqueEmail(prefix string) string {
	return prefix + "-" + hex.EncodeToString([]byte(time.Now().String())[:8]) + "@example.com"
}

// =============================================================================
// Test: Create Note
// =============================================================================

func TestBrowser_NotesCRUD_CreateNote(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupNotesCrudEnv(t)
	testEmail := generateUniqueEmail("test-create")
	env.loginCrudTestUser(t, testEmail)

	// Navigate to /notes/new
	env.navigateCrud(t, "/notes/new")

	// Wait for the form to be visible
	titleInput := env.waitForCrudSelector(t, "input#title")
	contentTextarea := env.waitForCrudSelector(t, "textarea#content")

	// Fill in the form
	err := titleInput.Fill("Test Note from Playwright")
	if err != nil {
		t.Fatalf("Failed to fill title: %v", err)
	}

	err = contentTextarea.Fill("This is test content created by Playwright E2E test.\n\n**Bold text** and *italic text*.")
	if err != nil {
		t.Fatalf("Failed to fill content: %v", err)
	}

	// Click the submit button
	submitButton := env.page.Locator("button[type='submit']:has-text('Create Note')")
	err = submitButton.Click()
	if err != nil {
		t.Fatalf("Failed to click submit button: %v", err)
	}

	// Wait for redirect to the note view page
	err = env.page.WaitForURL("**/notes/**", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Failed to wait for redirect after create: %v", err)
	}

	// Verify the note title is displayed
	titleElement := env.waitForCrudSelector(t, "h1")
	titleText, err := titleElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get title text: %v", err)
	}

	if strings.TrimSpace(titleText) != "Test Note from Playwright" {
		t.Errorf("Expected title 'Test Note from Playwright', got '%s'", titleText)
	}
}

// =============================================================================
// Test: Read Note (View Note)
// =============================================================================

func TestBrowser_NotesCRUD_ReadNote(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupNotesCrudEnv(t)
	testEmail := generateUniqueEmail("test-read")
	env.loginCrudTestUser(t, testEmail)

	// First create a note
	env.navigateCrud(t, "/notes/new")

	titleInput := env.waitForCrudSelector(t, "input#title")
	contentTextarea := env.waitForCrudSelector(t, "textarea#content")

	err := titleInput.Fill("Note for Reading Test")
	if err != nil {
		t.Fatalf("Failed to fill title: %v", err)
	}

	err = contentTextarea.Fill("Content for the reading test note.")
	if err != nil {
		t.Fatalf("Failed to fill content: %v", err)
	}

	submitButton := env.page.Locator("button[type='submit']:has-text('Create Note')")
	err = submitButton.Click()
	if err != nil {
		t.Fatalf("Failed to click submit: %v", err)
	}

	// Wait for redirect to note view
	err = env.page.WaitForURL("**/notes/**", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Failed to wait for redirect: %v", err)
	}

	// Navigate to notes list
	env.navigateCrud(t, "/notes")

	// Wait for the notes list to load
	env.waitForCrudSelector(t, "h1:has-text('My Notes')")

	// Click on the note in the list
	noteLink := env.page.Locator("article a:has-text('Note for Reading Test')")
	err = noteLink.Click()
	if err != nil {
		t.Fatalf("Failed to click on note: %v", err)
	}

	// Wait for the note view page
	err = env.page.WaitForURL("**/notes/**", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Failed to wait for note view: %v", err)
	}

	// Verify title is displayed
	titleElement := env.waitForCrudSelector(t, "h1")
	titleText, err := titleElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get title text: %v", err)
	}

	if strings.TrimSpace(titleText) != "Note for Reading Test" {
		t.Errorf("Expected title 'Note for Reading Test', got '%s'", titleText)
	}

	// Verify content is displayed
	contentElement := env.page.Locator(".prose")
	contentText, err := contentElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get content text: %v", err)
	}

	if contentText == "" {
		t.Error("Expected note content to be displayed")
	}
}

// =============================================================================
// Test: Update Note (Edit Note)
// =============================================================================

func TestBrowser_NotesCRUD_EditNote(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupNotesCrudEnv(t)
	testEmail := generateUniqueEmail("test-edit")
	env.loginCrudTestUser(t, testEmail)

	// First create a note
	env.navigateCrud(t, "/notes/new")

	titleInput := env.waitForCrudSelector(t, "input#title")
	contentTextarea := env.waitForCrudSelector(t, "textarea#content")

	err := titleInput.Fill("Original Title")
	if err != nil {
		t.Fatalf("Failed to fill title: %v", err)
	}

	err = contentTextarea.Fill("Original content before editing.")
	if err != nil {
		t.Fatalf("Failed to fill content: %v", err)
	}

	submitButton := env.page.Locator("button[type='submit']:has-text('Create Note')")
	err = submitButton.Click()
	if err != nil {
		t.Fatalf("Failed to click submit: %v", err)
	}

	// Wait for redirect to note view
	err = env.page.WaitForURL("**/notes/**", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Failed to wait for redirect: %v", err)
	}

	// Click the Edit Note button
	editButton := env.waitForCrudSelector(t, "a:has-text('Edit Note')")
	err = editButton.Click()
	if err != nil {
		t.Fatalf("Failed to click edit button: %v", err)
	}

	// Wait for edit page to load
	err = env.page.WaitForURL("**/edit", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Failed to wait for edit page: %v", err)
	}

	// Clear and update the title
	titleInput = env.waitForCrudSelector(t, "input#title")
	err = titleInput.Fill("")
	if err != nil {
		t.Fatalf("Failed to clear title: %v", err)
	}
	err = titleInput.Fill("Updated Title")
	if err != nil {
		t.Fatalf("Failed to fill new title: %v", err)
	}

	// Clear and update the content
	contentTextarea = env.waitForCrudSelector(t, "textarea#content")
	err = contentTextarea.Fill("")
	if err != nil {
		t.Fatalf("Failed to clear content: %v", err)
	}
	err = contentTextarea.Fill("Updated content after editing.")
	if err != nil {
		t.Fatalf("Failed to fill new content: %v", err)
	}

	// Click Save Changes
	saveButton := env.page.Locator("button[type='submit']:has-text('Save Changes')")
	err = saveButton.Click()
	if err != nil {
		t.Fatalf("Failed to click save button: %v", err)
	}

	// Wait for redirect back to note view
	err = env.page.WaitForURL("**/notes/**", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Failed to wait for redirect after save: %v", err)
	}

	// Verify the updated title is displayed
	titleElement := env.waitForCrudSelector(t, "h1")
	titleText, err := titleElement.TextContent()
	if err != nil {
		t.Fatalf("Failed to get title text: %v", err)
	}

	if strings.TrimSpace(titleText) != "Updated Title" {
		t.Errorf("Expected title 'Updated Title', got '%s'", titleText)
	}
}

// =============================================================================
// Test: Delete Note
// =============================================================================

func TestBrowser_NotesCRUD_DeleteNote(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupNotesCrudEnv(t)
	testEmail := generateUniqueEmail("test-delete")
	env.loginCrudTestUser(t, testEmail)

	// First create a note
	env.navigateCrud(t, "/notes/new")

	titleInput := env.waitForCrudSelector(t, "input#title")
	contentTextarea := env.waitForCrudSelector(t, "textarea#content")

	noteTitle := "Note to Delete"
	err := titleInput.Fill(noteTitle)
	if err != nil {
		t.Fatalf("Failed to fill title: %v", err)
	}

	err = contentTextarea.Fill("This note will be deleted.")
	if err != nil {
		t.Fatalf("Failed to fill content: %v", err)
	}

	submitButton := env.page.Locator("button[type='submit']:has-text('Create Note')")
	err = submitButton.Click()
	if err != nil {
		t.Fatalf("Failed to click submit: %v", err)
	}

	// Wait for redirect to note view
	err = env.page.WaitForURL("**/notes/**", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Failed to wait for redirect: %v", err)
	}

	// Set up dialog handler for confirmation
	env.page.OnDialog(func(dialog playwright.Dialog) {
		dialog.Accept()
	})

	// Click the Delete button
	deleteButton := env.waitForCrudSelector(t, "button:has-text('Delete')")
	err = deleteButton.Click()
	if err != nil {
		t.Fatalf("Failed to click delete button: %v", err)
	}

	// Wait for redirect to notes list
	err = env.page.WaitForURL("**/notes", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Failed to wait for redirect after delete: %v", err)
	}

	// Verify the note is no longer in the list
	noteLink := env.page.Locator(fmt.Sprintf("article a:has-text('%s')", noteTitle))
	count, err := noteLink.Count()
	if err != nil {
		t.Fatalf("Failed to count note links: %v", err)
	}

	if count > 0 {
		t.Error("Deleted note should not appear in the list")
	}
}

// =============================================================================
// Test: Notes List Pagination
// =============================================================================

func TestBrowser_NotesCRUD_Pagination(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupNotesCrudEnv(t)
	testEmail := generateUniqueEmail("test-pagination")
	env.loginCrudTestUser(t, testEmail)

	// Create 15 notes to trigger pagination (default page size is 12)
	for i := 1; i <= 15; i++ {
		env.navigateCrud(t, "/notes/new")

		titleInput := env.waitForCrudSelector(t, "input#title")
		contentTextarea := env.waitForCrudSelector(t, "textarea#content")

		err := titleInput.Fill(fmt.Sprintf("Pagination Test Note %02d", i))
		if err != nil {
			t.Fatalf("Failed to fill title for note %d: %v", i, err)
		}

		err = contentTextarea.Fill(fmt.Sprintf("Content for pagination test note %d", i))
		if err != nil {
			t.Fatalf("Failed to fill content for note %d: %v", i, err)
		}

		submitButton := env.page.Locator("button[type='submit']:has-text('Create Note')")
		err = submitButton.Click()
		if err != nil {
			t.Fatalf("Failed to click submit for note %d: %v", i, err)
		}

		// Wait for redirect
		err = env.page.WaitForURL("**/notes/**", playwright.PageWaitForURLOptions{
			Timeout: playwright.Float(5000),
		})
		if err != nil {
			t.Fatalf("Failed to wait for redirect for note %d: %v", i, err)
		}
	}

	// Set desktop viewport to ensure pagination buttons are visible
	env.page.SetViewportSize(1280, 800)

	// Navigate to notes list
	env.navigateCrud(t, "/notes")

	// Wait for page to load
	env.waitForCrudSelector(t, "h1:has-text('My Notes')")

	// Verify pagination is shown
	paginationNav := env.page.Locator("nav[aria-label='Pagination']")
	err := paginationNav.First().WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		// Debug: show page content
		content, _ := env.page.Content()
		if len(content) > 1000 {
			content = content[:1000] + "..."
		}
		t.Fatalf("Pagination should be visible with 15 notes. Page content: %s", content)
	}

	// Click "Next" to go to page 2 - target the visible desktop button
	// The desktop buttons are in the inner nav element within the pagination nav
	nextButton := env.page.Locator("nav[aria-label='Pagination'] nav a[href*='page=2']")

	err = nextButton.First().Click()
	if err != nil {
		t.Fatalf("Failed to click next button: %v", err)
	}

	// Wait for page 2 to load by waiting for previous button to be visible
	// (on page 2, the previous button becomes an active link)
	prevButton := env.page.Locator("nav[aria-label='Pagination'] nav a[href*='page=1']")
	err = prevButton.First().WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		currentURL := env.page.URL()
		t.Fatalf("Failed to navigate to page 2 - prev button not visible. Current URL: %s, error: %v", currentURL, err)
	}

	// Verify we're actually on page 2
	currentURL := env.page.URL()
	if !strings.Contains(currentURL, "page=2") {
		t.Errorf("Expected URL to contain 'page=2', got: %s", currentURL)
	}
}

// =============================================================================
// Test: Empty State
// =============================================================================

func TestBrowser_NotesCRUD_EmptyState(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupNotesCrudEnv(t)
	// Use a unique email to ensure this is a fresh user with no notes
	testEmail := generateUniqueEmail("test-empty")
	env.loginCrudTestUser(t, testEmail)

	// Navigate to notes list
	env.navigateCrud(t, "/notes")

	// Wait for page to load
	env.waitForCrudSelector(t, "h1:has-text('My Notes')")

	// Verify "No notes yet" message is displayed
	emptyMessage := env.page.Locator("h3:has-text('No notes yet')")
	count, err := emptyMessage.Count()
	if err != nil {
		t.Fatalf("Failed to check empty message: %v", err)
	}

	if count == 0 {
		t.Error("Expected 'No notes yet' message for new user")
	}

	// Verify "Create your first note" button is displayed
	createButton := env.page.Locator("a:has-text('Create your first note')")
	count, err = createButton.Count()
	if err != nil {
		t.Fatalf("Failed to check create button: %v", err)
	}

	if count == 0 {
		t.Error("Expected 'Create your first note' button in empty state")
	}

	// Click the "Create your first note" button
	err = createButton.Click()
	if err != nil {
		t.Fatalf("Failed to click create button: %v", err)
	}

	// Verify redirect to /notes/new
	err = env.page.WaitForURL("**/notes/new", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Failed to navigate to new note page: %v", err)
	}

	// Verify the new note form is displayed
	env.waitForCrudSelector(t, "input#title")
	env.waitForCrudSelector(t, "textarea#content")
}

// =============================================================================
// Test: Login Flow (via password)
// =============================================================================

func TestBrowser_NotesCRUD_LoginFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupNotesCrudEnv(t)

	// Navigate to login page (without logging in first)
	env.navigateCrud(t, "/login")

	// Wait for login form to be visible
	env.waitForCrudSelector(t, "h2:has-text('Sign in to your account')")

	// Fill in the password login form
	emailInput := env.waitForCrudSelector(t, "input#login-email")
	passwordInput := env.waitForCrudSelector(t, "input#login-password")

	testEmail := generateUniqueEmail("login-test")

	err := emailInput.Fill(testEmail)
	if err != nil {
		t.Fatalf("Failed to fill email: %v", err)
	}

	err = passwordInput.Fill("TestPassword123!")
	if err != nil {
		t.Fatalf("Failed to fill password: %v", err)
	}

	// Click Sign In button (target the password login form specifically)
	signInButton := env.page.Locator("form[action='/auth/login'] button[type='submit']")
	err = signInButton.Click()
	if err != nil {
		t.Fatalf("Failed to click sign in button: %v", err)
	}

	// Wait for redirect to /notes
	err = env.page.WaitForURL("**/notes**", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Failed to redirect after login: %v", err)
	}

	// Verify we're on the notes page
	env.waitForCrudSelector(t, "h1:has-text('My Notes')")
}

// =============================================================================
// Test: New Note Button from List View
// =============================================================================

func TestBrowser_NotesCRUD_NewNoteButton(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}

	env := setupNotesCrudEnv(t)
	testEmail := generateUniqueEmail("test-new-button")
	env.loginCrudTestUser(t, testEmail)

	// Navigate to notes list
	env.navigateCrud(t, "/notes")

	// Wait for page to load
	env.waitForCrudSelector(t, "h1:has-text('My Notes')")

	// Click "New Note" button in the header
	newNoteButton := env.page.Locator("a:has-text('New Note')")
	err := newNoteButton.Click()
	if err != nil {
		t.Fatalf("Failed to click New Note button: %v", err)
	}

	// Verify redirect to /notes/new
	err = env.page.WaitForURL("**/notes/new", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(5000),
	})
	if err != nil {
		t.Fatalf("Failed to navigate to new note page: %v", err)
	}

	// Verify the new note form is displayed with proper heading
	heading := env.waitForCrudSelector(t, "h1:has-text('Create New Note')")
	headingText, err := heading.TextContent()
	if err != nil {
		t.Fatalf("Failed to get heading text: %v", err)
	}

	if !strings.Contains(headingText, "Create New Note") {
		t.Errorf("Expected heading 'Create New Note', got '%s'", headingText)
	}
}
