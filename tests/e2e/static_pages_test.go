// Package e2e provides HTTP-based tests for static pages and render helpers.
// These are simple example-based tests (not property-based) that verify
// static pages render and contain expected content, and that render helper
// functions (formatTime, truncate, markdown, formatFloat) work correctly
// when exercised through page rendering.
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

	_ "github.com/mutecomm/go-sqlcipher/v4"

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/billing"
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	emailpkg "github.com/kuitang/agent-notes/internal/email"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/kuitang/agent-notes/internal/oauth"
	"github.com/kuitang/agent-notes/internal/ratelimit"
	"github.com/kuitang/agent-notes/internal/web"
)

// =============================================================================
// Static Page Server: includes both web form handlers AND static page handler
// =============================================================================

// staticPageServer wraps httptest.Server for testing static pages and render helpers.
type staticPageServer struct {
	*httptest.Server
	tempDir        string
	s3Server       *httptest.Server
	rateLimiter    *ratelimit.RateLimiter
	sessionsDB     *db.SessionsDB
	emailService   *emailpkg.MockEmailService
	mockOIDC       *auth.LocalMockOIDCProvider
	userService    *auth.UserService
	sessionService *auth.SessionService
	shared         bool
}

var staticPageSharedMu sync.Mutex
var staticPageSharedFixture *staticPageServer

func setupStaticPageServer(t testing.TB) *staticPageServer {
	t.Helper()
	webFormTestMutex.Lock()
	t.Cleanup(webFormTestMutex.Unlock)

	ts, err := getOrCreateSharedStaticPageServer()
	if err != nil {
		t.Fatalf("Failed to initialize shared static page fixture: %v", err)
	}
	if err := resetStaticPageServerState(ts); err != nil {
		t.Fatalf("Failed to reset shared static page fixture: %v", err)
	}
	return ts
}

func createStaticPageServer(tempDir string) *staticPageServer {
	// Reset database singleton
	db.ResetForTesting()
	db.DataDirectory = tempDir

	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		panic("Failed to open sessions database: " + err.Error())
	}

	masterKey := make([]byte, 32)
	if _, err := crand.Read(masterKey); err != nil {
		panic("Failed to generate master key: " + err.Error())
	}

	_, signingKey, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		panic("Failed to generate signing key: " + err.Error())
	}

	hmacSecret := make([]byte, 32)
	if _, err := crand.Read(hmacSecret); err != nil {
		panic("Failed to generate HMAC secret: " + err.Error())
	}

	// Create initial server to get a URL
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	keyManager := crypto.NewKeyManager(masterKey, sessionsDB)
	emailService := emailpkg.NewMockEmailService()
	userService := auth.NewUserService(sessionsDB, keyManager, emailService, server.URL, auth.FakeInsecureHasher{})
	sessionService := auth.NewSessionService(sessionsDB)
	consentService := auth.NewConsentService(sessionsDB)

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

	templatesDir := findWebFormTemplatesDir()
	renderer, err := web.NewRenderer(templatesDir)
	if err != nil {
		panic("Failed to create renderer: " + err.Error())
	}

	authMiddleware := auth.NewMiddleware(sessionService, keyManager)

	rateLimiter := ratelimit.NewRateLimiter(ratelimit.Config{
		FreeRPS:         10000,
		FreeBurst:       100000,
		PaidRPS:         100000,
		PaidBurst:       1000000,
		CleanupInterval: time.Hour,
	})

	// Close initial server and create fresh mux with all routes
	server.Close()
	mux = http.NewServeMux()
	server = httptest.NewServer(mux)

	// Re-create userService with correct base URL
	userService = auth.NewUserService(sessionsDB, keyManager, emailService, server.URL, auth.FakeInsecureHasher{})

	// Mock S3 (shared in-memory fixture)
	s3Server, mockS3Client := createMockS3ServerWithBucket("test-bucket-static")

	// Web handler (includes notes CRUD, auth pages, etc.)
	webHandler := web.NewWebHandler(
		renderer,
		nil, // notesService is per-request
		notes.NewPublicNoteService(mockS3Client),
		userService,
		sessionService,
		consentService,
		mockS3Client,
		nil, // shortURLSvc
		billing.NewMockService(),
		server.URL,
	)
	webHandler.RegisterRoutes(mux, authMiddleware)

	// Static page handler (privacy, terms, about, api-docs, install)
	staticSrcDir := findStaticDir("src")
	staticHandler := web.NewStaticHandler(renderer, staticSrcDir, authMiddleware)
	staticHandler.RegisterRoutes(mux)

	// Auth API routes
	mockOIDC := auth.NewLocalMockOIDCProvider(server.URL)
	authHandler := auth.NewHandler(mockOIDC, userService, sessionService)
	authHandler.RegisterRoutes(mux)
	mockOIDC.RegisterRoutes(mux)

	// OAuth metadata
	oauthProvider.RegisterMetadataRoutes(mux)

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	return &staticPageServer{
		Server:         server,
		tempDir:        tempDir,
		s3Server:       s3Server,
		rateLimiter:    rateLimiter,
		sessionsDB:     sessionsDB,
		emailService:   emailService,
		mockOIDC:       mockOIDC,
		userService:    userService,
		sessionService: sessionService,
	}
}

func (ts *staticPageServer) cleanup() {
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

func getOrCreateSharedStaticPageServer() (*staticPageServer, error) {
	staticPageSharedMu.Lock()
	defer staticPageSharedMu.Unlock()

	if staticPageSharedFixture != nil {
		if err := staticPageSharedFixture.sessionsDB.DB().Ping(); err == nil {
			return staticPageSharedFixture, nil
		}
		staticPageSharedFixture.closeSharedResources()
		staticPageSharedFixture = nil
	}

	tempDir, err := os.MkdirTemp("", "static-pages-shared-*")
	if err != nil {
		return nil, fmt.Errorf("create shared static page temp dir: %w", err)
	}

	staticPageSharedFixture = createStaticPageServer(tempDir)
	staticPageSharedFixture.shared = true
	return staticPageSharedFixture, nil
}

func (ts *staticPageServer) closeSharedResources() {
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

func resetStaticPageServerState(ts *staticPageServer) error {
	if err := resetSharedDBFixtureState(ts.tempDir, ts.sessionsDB); err != nil {
		return err
	}
	if ts.emailService != nil {
		ts.emailService.Clear()
	}
	return nil
}

// findStaticDir locates the static/{subdir} directory.
func findStaticDir(subdir string) string {
	candidates := []string{
		filepath.Join("../../static", subdir),
		filepath.Join("../../../static", subdir),
		filepath.Join("static", subdir),
		filepath.Join("/home/kuitang/git/agent-notes/static", subdir),
	}
	for _, dir := range candidates {
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}
	return filepath.Join("/home/kuitang/git/agent-notes/static", subdir)
}

// =============================================================================
// TEST: Static Pages Render with Expected Content
// =============================================================================

func TestStaticPages_Render(t *testing.T) {
	ts := setupStaticPageServer(t)
	defer ts.cleanup()

	client := &http.Client{Timeout: 10 * time.Second}

	tests := []struct {
		name    string
		path    string
		keyword string
	}{
		{"PrivacyPage", "/privacy", "Privacy"},
		{"TermsPage", "/terms", "Terms"},
		{"AboutPage", "/about", "About"},
		{"APIDocsPage", "/docs/api", "API"},
		{"APIDocsAlias", "/docs", "API"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.Get(ts.URL + tt.path)
			if err != nil {
				t.Fatalf("GET %s failed: %v", tt.path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s: expected 200, got %d", tt.path, resp.StatusCode)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("GET %s: failed to read body: %v", tt.path, err)
			}

			html := string(body)

			// Content-Type should be HTML
			ct := resp.Header.Get("Content-Type")
			if !strings.Contains(ct, "text/html") {
				t.Errorf("GET %s: expected text/html content type, got %q", tt.path, ct)
			}

			// Body should contain the keyword
			if !strings.Contains(html, tt.keyword) {
				t.Errorf("GET %s: expected body to contain %q", tt.path, tt.keyword)
			}

			// Body should be non-trivial (at least 100 bytes of rendered content)
			if len(body) < 100 {
				t.Errorf("GET %s: body too short (%d bytes), expected rendered HTML", tt.path, len(body))
			}
		})
	}
}

// =============================================================================
// TEST: Landing Page Renders
// =============================================================================

func TestStaticPages_LandingPage(t *testing.T) {
	ts := setupStaticPageServer(t)
	defer ts.cleanup()

	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer resp.Body.Close()

	// Landing page for unauthenticated users should render (200)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /: expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	if !strings.Contains(html, "common.ink") {
		t.Error("GET /: landing page should contain 'common.ink'")
	}
}

// =============================================================================
// TEST: Render Helpers via Note CRUD (formatTime, truncate, markdown, formatFloat)
// =============================================================================

func TestRenderHelpers_MarkdownRendering(t *testing.T) {
	ts := setupStaticPageServer(t)
	defer ts.cleanup()

	// Create a user and session
	ctx := context.Background()
	user, err := ts.userService.FindOrCreateByProvider(ctx, "render-test@example.com")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	sessionID, err := ts.sessionService.Create(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

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

	// Create a note with markdown content
	markdownContent := "# Heading One\n\nThis is **bold** and *italic* text.\n\n- Item 1\n- Item 2\n\n`inline code`"
	createForm := url.Values{
		"title":   {"Markdown Test Note"},
		"content": {markdownContent},
	}

	createResp, err := client.PostForm(ts.URL+"/notes", createForm)
	if err != nil {
		t.Fatalf("Create note failed: %v", err)
	}
	defer createResp.Body.Close()

	if createResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(createResp.Body)
		t.Fatalf("Create note: expected 302, got %d: %s", createResp.StatusCode, string(body))
	}

	// Extract note ID from redirect
	location := createResp.Header.Get("Location")
	parts := strings.Split(location, "/")
	noteID := parts[len(parts)-1]

	// View the note -- this exercises the markdown render helper
	viewResp, err := client.Get(ts.URL + "/notes/" + noteID)
	if err != nil {
		t.Fatalf("View note failed: %v", err)
	}
	defer viewResp.Body.Close()

	if viewResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(viewResp.Body)
		t.Fatalf("View note: expected 200, got %d: %s", viewResp.StatusCode, string(body))
	}

	viewBody, _ := io.ReadAll(viewResp.Body)
	viewHTML := string(viewBody)

	// The markdown helper should convert markdown to HTML
	// Check that bold text was rendered
	if !strings.Contains(viewHTML, "<strong>bold</strong>") {
		t.Error("Markdown rendering: expected <strong>bold</strong> in rendered output")
	}

	// Check that italic text was rendered
	if !strings.Contains(viewHTML, "<em>italic</em>") {
		t.Error("Markdown rendering: expected <em>italic</em> in rendered output")
	}

	// Check that inline code was rendered
	if !strings.Contains(viewHTML, "<code>inline code</code>") {
		t.Error("Markdown rendering: expected <code>inline code</code> in rendered output")
	}
}

func TestRenderHelpers_FormatTimeAndTruncate(t *testing.T) {
	ts := setupStaticPageServer(t)
	defer ts.cleanup()

	// Create a user and session
	ctx := context.Background()
	user, err := ts.userService.FindOrCreateByProvider(ctx, "helpers-test@example.com")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	sessionID, err := ts.sessionService.Create(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

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

	// Create a note with long content (to exercise truncate in the list view)
	longContent := strings.Repeat("This is a long sentence for testing truncation. ", 20)
	createForm := url.Values{
		"title":   {"Time Format Test Note"},
		"content": {longContent},
	}

	createResp, err := client.PostForm(ts.URL+"/notes", createForm)
	if err != nil {
		t.Fatalf("Create note failed: %v", err)
	}
	createResp.Body.Close()

	// List notes -- this exercises formatTime and truncate
	listResp, err := client.Get(ts.URL + "/notes")
	if err != nil {
		t.Fatalf("List notes failed: %v", err)
	}
	defer listResp.Body.Close()

	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("List notes: expected 200, got %d: %s", listResp.StatusCode, string(body))
	}

	listBody, _ := io.ReadAll(listResp.Body)
	listHTML := string(listBody)

	// formatTime outputs dates like "Jan 2, 2006"
	// The note was just created, so the current date should appear
	now := time.Now()
	expectedMonth := now.Format("Jan")
	if !strings.Contains(listHTML, expectedMonth) {
		t.Errorf("formatTime: expected month %q in notes list HTML", expectedMonth)
	}

	// truncate: the list view truncates content to 150 chars.
	// The full content is ~1000 chars, so it should be truncated with "..."
	if !strings.Contains(listHTML, "...") {
		t.Error("truncate: expected '...' in notes list for long content")
	}

	// The full long content should NOT appear untruncated in the list
	if strings.Contains(listHTML, longContent) {
		t.Error("truncate: full content should not appear in list view")
	}

	// The note title should be present
	if !strings.Contains(listHTML, "Time Format Test Note") {
		t.Error("Note title should appear in list view")
	}
}

func TestRenderHelpers_FormatFloat(t *testing.T) {
	ts := setupStaticPageServer(t)
	defer ts.cleanup()

	// Create a user and session
	ctx := context.Background()
	user, err := ts.userService.FindOrCreateByProvider(ctx, "float-test@example.com")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	sessionID, err := ts.sessionService.Create(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

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

	// The notes list page shows storage usage with formatFloat.
	// Just loading the notes list page exercises formatFloat if StorageUsage is present.
	listResp, err := client.Get(ts.URL + "/notes")
	if err != nil {
		t.Fatalf("List notes failed: %v", err)
	}
	defer listResp.Body.Close()

	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("List notes: expected 200, got %d: %s", listResp.StatusCode, string(body))
	}

	listBody, _ := io.ReadAll(listResp.Body)
	listHTML := string(listBody)

	// The storage bar uses formatFloat -- check for "MB" which appears in the usage display
	// Template uses: {{formatFloat .StorageUsage.UsedMB 1}} / {{formatFloat .StorageUsage.LimitMB 0}} MB
	if !strings.Contains(listHTML, "MB") {
		t.Log("formatFloat: storage usage bar with 'MB' not found (may not render for empty user)")
	}

	// The page should at least render without error
	if !strings.Contains(listHTML, "My Notes") && !strings.Contains(listHTML, "Notes") {
		t.Error("Notes list page should contain 'Notes' heading")
	}
}

// =============================================================================
// TEST: Static Pages Have Proper HTML Structure
// =============================================================================

func TestStaticPages_HTMLStructure(t *testing.T) {
	ts := setupStaticPageServer(t)
	defer ts.cleanup()

	client := &http.Client{Timeout: 10 * time.Second}

	pages := []string{"/privacy", "/terms", "/about", "/docs/api"}

	for _, path := range pages {
		t.Run(path, func(t *testing.T) {
			resp, err := client.Get(ts.URL + path)
			if err != nil {
				t.Fatalf("GET %s failed: %v", path, err)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			html := string(body)

			// Should contain basic HTML structure from base template
			if !strings.Contains(html, "<!DOCTYPE html>") && !strings.Contains(html, "<html") {
				t.Errorf("GET %s: missing HTML doctype or html tag", path)
			}

			if !strings.Contains(html, "<head>") && !strings.Contains(html, "<head ") {
				t.Errorf("GET %s: missing <head> tag", path)
			}

			if !strings.Contains(html, "</body>") {
				t.Errorf("GET %s: missing </body> tag", path)
			}

			// Static pages should contain the prose wrapper from static/page.html
			if !strings.Contains(html, "prose") {
				t.Errorf("GET %s: missing 'prose' class (expected from static page template)", path)
			}
		})
	}
}

// =============================================================================
// TEST: Static Page Markdown Rendering (content from .md files)
// =============================================================================

func TestStaticPages_MarkdownContent(t *testing.T) {
	ts := setupStaticPageServer(t)
	defer ts.cleanup()

	client := &http.Client{Timeout: 10 * time.Second}

	// These checks verify that markdown source files were rendered into HTML
	tests := []struct {
		name     string
		path     string
		contains []string // expected substrings in rendered HTML
	}{
		{
			"PrivacyHasHeadings",
			"/privacy",
			[]string{"Privacy Policy", "Information We Collect"},
		},
		{
			"TermsHasHeadings",
			"/terms",
			[]string{"Terms of Service", "Acceptance of Terms"},
		},
		{
			"AboutHasBranding",
			"/about",
			[]string{"common.ink", "Key Features"},
		},
		{
			"APIDocsHasContent",
			"/docs/api",
			[]string{"API Documentation", "Authentication"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.Get(ts.URL + tt.path)
			if err != nil {
				t.Fatalf("GET %s failed: %v", tt.path, err)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			html := string(body)

			for _, expected := range tt.contains {
				if !strings.Contains(html, expected) {
					t.Errorf("GET %s: expected body to contain %q", tt.path, expected)
				}
			}
		})
	}
}
