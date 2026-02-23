// Package e2e provides HTTP-based property tests for static pages and render helpers.
// Invariant: any registered static route returns 200 with non-empty HTML containing
// expected structural elements and content-type headers.
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
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

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
		"", // spriteToken
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
	repoRoot := repositoryRoot()
	candidates := []string{
		filepath.Join(repoRoot, "static", subdir),
	}
	for _, dir := range candidates {
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}
	panic("Cannot find static directory")
}

// =============================================================================
// Registered static routes -- the canonical list for property tests.
// =============================================================================

var staticPageRoutes = []string{
	"/",
	"/privacy",
	"/terms",
	"/about",
	"/faq",
	"/docs/api",
	"/docs",
	"/docs/install",
}

// =============================================================================
// Property: Any registered static route returns 200 with non-empty HTML
// =============================================================================

func testStaticPages_RouteReturns200HTML_Properties(rt *rapid.T, ts *staticPageServer) {
	// Draw a random static route
	path := rapid.SampledFrom(staticPageRoutes).Draw(rt, "path")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(ts.URL + path)
	if err != nil {
		rt.Fatalf("GET %s failed: %v", path, err)
	}
	defer resp.Body.Close()

	// Property: status must be 200
	if resp.StatusCode != http.StatusOK {
		rt.Fatalf("GET %s: expected 200, got %d", path, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		rt.Fatalf("GET %s: failed to read body: %v", path, err)
	}

	// Property: Content-Type must include text/html
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		rt.Fatalf("GET %s: expected text/html content type, got %q", path, ct)
	}

	// Property: body must be non-empty (at least 100 bytes of rendered HTML)
	if len(body) < 100 {
		rt.Fatalf("GET %s: body too short (%d bytes), expected rendered HTML", path, len(body))
	}

	html := string(body)

	// Property: must contain basic HTML structure
	if !strings.Contains(html, "<!DOCTYPE html>") && !strings.Contains(html, "<html") {
		rt.Fatalf("GET %s: missing HTML doctype or html tag", path)
	}
	if !strings.Contains(html, "</body>") {
		rt.Fatalf("GET %s: missing </body> tag", path)
	}
}

func TestStaticPages_RouteReturns200HTML_Properties(t *testing.T) {
	ts := setupStaticPageServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		testStaticPages_RouteReturns200HTML_Properties(rt, ts)
	})
}

func FuzzStaticPages_RouteReturns200HTML_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		ts, err := getOrCreateSharedStaticPageServer()
		if err != nil {
			rt.Fatalf("Failed to get shared static page server: %v", err)
		}
		testStaticPages_RouteReturns200HTML_Properties(rt, ts)
	}))
}

// =============================================================================
// Property: Render helpers produce expected output invariants
// (markdown, formatTime, truncate)
// =============================================================================

func testRenderHelpers_Invariants_Properties(rt *rapid.T, ts *staticPageServer) {
	ctx := context.Background()

	// Use a random email suffix to avoid collision
	suffix := rapid.StringMatching(`[a-z0-9]{8}`).Draw(rt, "suffix")
	email := "render-prop-" + suffix + "@example.com"

	user, err := ts.userService.FindOrCreateByProvider(ctx, email)
	if err != nil {
		rt.Fatalf("Failed to create user: %v", err)
	}
	sessionID, err := ts.sessionService.Create(ctx, user.ID)
	if err != nil {
		rt.Fatalf("Failed to create session: %v", err)
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

	// Draw random note content -- some with markdown, some long for truncation
	title := rapid.StringMatching(`[A-Za-z ]{5,30}`).Draw(rt, "title")
	useMarkdown := rapid.Bool().Draw(rt, "useMarkdown")

	var content string
	if useMarkdown {
		content = "# " + title + "\n\nThis is **bold** and *italic* text.\n\n- Item 1\n- Item 2"
	} else {
		// Long content to exercise truncation
		sentence := rapid.StringMatching(`[A-Za-z ]{20,50}`).Draw(rt, "sentence")
		content = strings.Repeat(sentence+". ", 20)
	}

	createForm := url.Values{
		"title":   {title},
		"content": {content},
	}

	createResp, err := client.PostForm(ts.URL+"/notes", createForm)
	if err != nil {
		rt.Fatalf("Create note failed: %v", err)
	}
	defer createResp.Body.Close()

	// Property: Create should redirect (302)
	if createResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(createResp.Body)
		rt.Fatalf("Create note: expected 302, got %d: %s", createResp.StatusCode, string(body))
	}

	location := createResp.Header.Get("Location")
	parts := strings.Split(location, "/")
	noteID := parts[len(parts)-1]

	// View the individual note
	viewResp, err := client.Get(ts.URL + "/notes/" + noteID)
	if err != nil {
		rt.Fatalf("View note failed: %v", err)
	}
	defer viewResp.Body.Close()

	if viewResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(viewResp.Body)
		rt.Fatalf("View note: expected 200, got %d: %s", viewResp.StatusCode, string(body))
	}

	viewBody, _ := io.ReadAll(viewResp.Body)
	viewHTML := string(viewBody)

	if useMarkdown {
		// Property: markdown bold should render as <strong>
		if !strings.Contains(viewHTML, "<strong>bold</strong>") {
			rt.Fatalf("Markdown rendering: expected <strong>bold</strong> in output")
		}
		// Property: markdown italic should render as <em>
		if !strings.Contains(viewHTML, "<em>italic</em>") {
			rt.Fatalf("Markdown rendering: expected <em>italic</em> in output")
		}
	}

	// List notes -- exercises formatTime and truncate
	listResp, err := client.Get(ts.URL + "/notes")
	if err != nil {
		rt.Fatalf("List notes failed: %v", err)
	}
	defer listResp.Body.Close()

	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		rt.Fatalf("List notes: expected 200, got %d: %s", listResp.StatusCode, string(body))
	}

	listBody, _ := io.ReadAll(listResp.Body)
	listHTML := string(listBody)

	// Property: formatTime outputs dates matching "Mon D, YYYY" pattern
	datePattern := regexp.MustCompile(`\b[A-Z][a-z]{2} [0-9]{1,2}, [0-9]{4}\b`)
	if !datePattern.MatchString(listHTML) {
		rt.Fatalf("formatTime: expected at least one rendered date in 'Jan 2, 2006' format")
	}

	// Property: note title must appear in list view
	if !strings.Contains(listHTML, title) {
		rt.Fatalf("Note title %q should appear in list view", title)
	}

	// Property: if content is long (>200 chars), truncation marker "..." should appear
	if !useMarkdown && len(content) > 200 {
		if !strings.Contains(listHTML, "...") {
			rt.Fatalf("truncate: expected '...' in notes list for long content")
		}
		// Full content should NOT appear untruncated
		if strings.Contains(listHTML, content) {
			rt.Fatalf("truncate: full content should not appear in list view")
		}
	}
}

func TestRenderHelpers_Invariants_Properties(t *testing.T) {
	ts := setupStaticPageServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		testRenderHelpers_Invariants_Properties(rt, ts)
	})
}

func FuzzRenderHelpers_Invariants_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(rt *rapid.T) {
		ts, err := getOrCreateSharedStaticPageServer()
		if err != nil {
			rt.Fatalf("Failed to get shared static page server: %v", err)
		}
		testRenderHelpers_Invariants_Properties(rt, ts)
	}))
}
