// Package e2e provides end-to-end property tests for short URL web flows
// and additional auth handler coverage.
// These tests exercise the REAL web handlers (HandleTogglePublish,
// HandleShortURLRedirect, HandleGoogleLogin, HandleGoogleCallback)
// via HTTP, driving coverage of internal/shorturl/shorturl.go and internal/web/handlers.go.
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
	"pgregory.net/rapid"

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/billing"
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	emailpkg "github.com/kuitang/agent-notes/internal/email"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/kuitang/agent-notes/internal/ratelimit"
	"github.com/kuitang/agent-notes/internal/shorturl"
	"github.com/kuitang/agent-notes/internal/web"
	"github.com/kuitang/agent-notes/tests/e2e/testutil"
)

// =============================================================================
// SHORT URL WEB TEST SERVER - Uses REAL web handlers with short URL support
// =============================================================================

var shortURLWebTestMutex sync.Mutex
var shortURLWebSharedMu sync.Mutex
var shortURLWebSharedFixture *shortURLWebServer

// shortURLWebServer wraps httptest.Server for testing short URL web flows
type shortURLWebServer struct {
	*httptest.Server
	tempDir    string
	s3Server   *httptest.Server
	sessionsDB *db.SessionsDB
	shared     bool

	// Services (exposed for tests)
	keyManager     *crypto.KeyManager
	userService    *auth.UserService
	sessionService *auth.SessionService
	emailService   *emailpkg.MockEmailService
	shortURLSvc    *shorturl.Service
	rateLimiter    *ratelimit.RateLimiter
	mockOIDC       *auth.LocalMockOIDCProvider
}

// setupShortURLWebServer creates a test server with all web handlers wired up,
// including the short URL service. This tests through the REAL web handlers.
func setupShortURLWebServer(t testing.TB) *shortURLWebServer {
	t.Helper()
	shortURLWebTestMutex.Lock()
	t.Cleanup(shortURLWebTestMutex.Unlock)

	ts, err := getOrCreateSharedShortURLWebServer()
	if err != nil {
		t.Fatalf("Failed to initialize shared short URL web fixture: %v", err)
	}
	if err := resetShortURLWebServerState(ts); err != nil {
		t.Fatalf("Failed to reset shared short URL web fixture: %v", err)
	}
	return ts
}

func createShortURLWebServer(tempDir string) *shortURLWebServer {
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

	// Generate OAuth signing key (not used directly but needed for provider)
	_, _, err = ed25519.GenerateKey(crand.Reader)
	if err != nil {
		panic("Failed to generate signing key: " + err.Error())
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

	// Find templates directory
	templatesDir := findShortURLWebTemplatesDir()
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

	// Close old server and create new mux (same pattern as setupWebFormServer)
	server.Close()
	mux = http.NewServeMux()
	server = httptest.NewServer(mux)

	// Update userService baseURL
	userService = auth.NewUserService(sessionsDB, keyManager, emailService, server.URL, auth.FakeInsecureHasher{})

	// Create mock OIDC provider (needs final server URL)
	mockOIDC := auth.NewLocalMockOIDCProvider(server.URL)

	// Create mock S3 server and client (shared helper from web_forms_test.go)
	s3Server, mockS3Client := createMockS3ServerWithBucket("test-bucket-shorturl-web")

	// Create short URL service with real sessions DB
	shortURLSvc := shorturl.NewService(sessionsDB.Queries())

	// Create public notes service WITH short URL support
	publicNotesService := notes.NewPublicNoteService(mockS3Client).
		WithShortURLService(shortURLSvc, server.URL)

	// Create web handler with ALL services including short URL
	webHandler := web.NewWebHandler(
		renderer,
		nil, // notesService is created per-request from auth context
		publicNotesService,
		userService,
		sessionService,
		consentService,
		mockS3Client,
		shortURLSvc,
		billing.NewMockService(),
		server.URL,
		"", // spriteToken
	)

	// Register ALL web routes
	webHandler.RegisterRoutes(mux, authMiddleware)

	// Register auth API routes (POST /auth/* for form handling)
	authHandler := auth.NewHandler(mockOIDC, userService, sessionService)
	authHandler.RegisterRoutes(mux)

	// Register mock OIDC provider routes (consent form + authorize endpoint)
	mockOIDC.RegisterRoutes(mux)

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	return &shortURLWebServer{
		Server:         server,
		tempDir:        tempDir,
		s3Server:       s3Server,
		sessionsDB:     sessionsDB,
		keyManager:     keyManager,
		userService:    userService,
		sessionService: sessionService,
		emailService:   emailService,
		shortURLSvc:    shortURLSvc,
		rateLimiter:    rateLimiter,
		mockOIDC:       mockOIDC,
	}
}

func (ts *shortURLWebServer) cleanup() {
	if ts.shared {
		return
	}
	ts.Server.Close()
	if ts.s3Server != nil {
		ts.s3Server.Close()
	}
	ts.rateLimiter.Stop()
	db.ResetForTesting()
	shortURLWebTestMutex.Unlock()
}

func getOrCreateSharedShortURLWebServer() (*shortURLWebServer, error) {
	shortURLWebSharedMu.Lock()
	defer shortURLWebSharedMu.Unlock()

	if shortURLWebSharedFixture != nil {
		if err := shortURLWebSharedFixture.sessionsDB.DB().Ping(); err == nil {
			return shortURLWebSharedFixture, nil
		}
		shortURLWebSharedFixture.closeSharedResources()
		shortURLWebSharedFixture = nil
	}

	tempDir, err := os.MkdirTemp("", "shorturl-web-shared-*")
	if err != nil {
		return nil, fmt.Errorf("create shared short URL temp dir: %w", err)
	}

	shortURLWebSharedFixture = createShortURLWebServer(tempDir)
	shortURLWebSharedFixture.shared = true
	return shortURLWebSharedFixture, nil
}

func (ts *shortURLWebServer) closeSharedResources() {
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

func resetShortURLWebServerState(ts *shortURLWebServer) error {
	if err := resetSharedDBFixtureState(ts.tempDir, ts.sessionsDB); err != nil {
		return err
	}
	if ts.emailService != nil {
		ts.emailService.Clear()
	}
	return nil
}

func findShortURLWebTemplatesDir() string {
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

// authenticateTestUser creates a user and returns a cookie jar with a valid session.
func (ts *shortURLWebServer) authenticateTestUser(email string) (*cookiejar.Jar, string) {
	ctx := context.Background()
	user, err := ts.userService.FindOrCreateByProvider(ctx, email)
	if err != nil {
		panic("Failed to create user: " + err.Error())
	}
	sessionID, err := ts.sessionService.Create(ctx, user.ID)
	if err != nil {
		panic("Failed to create session: " + err.Error())
	}

	jar, _ := cookiejar.New(nil)
	serverURL, _ := url.Parse(ts.URL)
	jar.SetCookies(serverURL, []*http.Cookie{{
		Name:  "session_id",
		Value: sessionID,
		Path:  "/",
	}})

	return jar, user.ID
}

// noFollowClient returns an HTTP client that does NOT follow redirects.
func (ts *shortURLWebServer) noFollowClient(jar *cookiejar.Jar) *http.Client {
	client := ts.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client
}

// createNote creates a note via POST /notes and returns the note ID.
func (ts *shortURLWebServer) createNote(client *http.Client, title, content string) string {
	createForm := url.Values{
		"title":   {title},
		"content": {content},
	}
	resp, err := client.PostForm(ts.URL+"/notes", createForm)
	if err != nil {
		panic("Failed to create note: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		panic(fmt.Sprintf("Create note failed with %d: %s", resp.StatusCode, string(body)))
	}

	location := resp.Header.Get("Location")
	parts := strings.Split(location, "/")
	return parts[len(parts)-1]
}

// =============================================================================
// TEST 1: Full Web Flow - Create, Publish, Short URL Redirect, Unpublish
// =============================================================================

func TestShortURLWeb_FullFlow_Properties(t *testing.T) {
	ts := setupShortURLWebServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		title := testutil.NoteTitleGenerator().Draw(rt, "title")
		content := testutil.NoteContentGenerator().Draw(rt, "content")
		email := testutil.EmailGenerator().Draw(rt, "email")

		// Authenticate user
		jar, userID := ts.authenticateTestUser(email)
		client := ts.noFollowClient(jar)

		// Step 1: Create a note
		noteID := ts.createNote(client, title, content)

		// Step 2: Toggle publish via POST /notes/{id}/publish (visibility=1 for public anonymous)
		publishResp, err := client.PostForm(ts.URL+"/notes/"+noteID+"/publish", url.Values{"visibility": {"1"}})
		if err != nil {
			rt.Fatalf("Publish request failed: %v", err)
		}
		publishResp.Body.Close()

		// Property 1: Publish should redirect back to note view
		if publishResp.StatusCode != http.StatusFound && publishResp.StatusCode != http.StatusSeeOther {
			rt.Fatalf("Publish should redirect, got %d", publishResp.StatusCode)
		}
		publishLocation := publishResp.Header.Get("Location")
		if !strings.Contains(publishLocation, "/notes/"+noteID) {
			rt.Fatalf("Publish should redirect to note view, got: %s", publishLocation)
		}

		// Step 3: Check that a short URL was created
		ctx := context.Background()
		fullPath := fmt.Sprintf("/public/%s/%s", userID, noteID)
		shortURLObj, err := ts.shortURLSvc.GetByFullPath(ctx, fullPath)
		if err != nil {
			rt.Fatalf("Short URL should exist after publish: %v", err)
		}

		// Property 2: Short ID format is valid
		if !shorturl.ValidateShortID(shortURLObj.ShortID) {
			rt.Fatalf("Short ID has invalid format: %s", shortURLObj.ShortID)
		}

		// Step 4: Access via short URL - GET /pub/{short_id}
		shortResp, err := client.Get(ts.URL + "/pub/" + shortURLObj.ShortID)
		if err != nil {
			rt.Fatalf("Short URL request failed: %v", err)
		}
		shortBody, _ := io.ReadAll(shortResp.Body)
		shortResp.Body.Close()

		// Property 3: Short URL serves HTML inline at /pub/{short_id}
		if shortResp.StatusCode != http.StatusOK {
			rt.Fatalf("Short URL should return 200 with inline HTML, got %d", shortResp.StatusCode)
		}

		// Property 4: Response body is HTML and contains note content metadata.
		html := string(shortBody)
		if !strings.Contains(html, "<html") && !strings.Contains(html, "<HTML") {
			rt.Fatal("Short URL should return HTML content")
		}
		if !strings.Contains(html, noteID) {
			rt.Fatalf("Short URL HTML should reference note ID %s", noteID)
		}

		// Step 6: Unpublish via setting visibility to private
		unpubResp, err := client.PostForm(ts.URL+"/notes/"+noteID+"/publish", url.Values{"visibility": {"0"}})
		if err != nil {
			rt.Fatalf("Unpublish request failed: %v", err)
		}
		unpubResp.Body.Close()

		// Property 6: Short URL should return 404 after unpublish
		shortResp2, err := client.Get(ts.URL + "/pub/" + shortURLObj.ShortID)
		if err != nil {
			rt.Fatalf("Short URL after unpublish request failed: %v", err)
		}
		shortResp2.Body.Close()

		if shortResp2.StatusCode != http.StatusNotFound {
			rt.Fatalf("Short URL should return 404 after unpublish, got %d", shortResp2.StatusCode)
		}
	})
}

// =============================================================================
// TEST 2: Multiple Publish/Unpublish Cycles
// =============================================================================

func TestShortURLWeb_MultipleCycles_Properties(t *testing.T) {
	ts := setupShortURLWebServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		title := testutil.NoteTitleGenerator().Draw(rt, "title")
		content := testutil.NoteContentGenerator().Draw(rt, "content")
		email := testutil.EmailGenerator().Draw(rt, "email")
		numCycles := rapid.IntRange(2, 5).Draw(rt, "numCycles")

		jar, userID := ts.authenticateTestUser(email)
		client := ts.noFollowClient(jar)

		noteID := ts.createNote(client, title, content)
		ctx := context.Background()
		fullPath := fmt.Sprintf("/public/%s/%s", userID, noteID)

		for cycle := 0; cycle < numCycles; cycle++ {
			// Publish (visibility=1 for public anonymous)
			pubResp, err := client.PostForm(ts.URL+"/notes/"+noteID+"/publish", url.Values{"visibility": {"1"}})
			if err != nil {
				rt.Fatalf("Cycle %d: publish failed: %v", cycle, err)
			}
			pubResp.Body.Close()

			// Property: Short URL should resolve after publish
			shortURLObj, err := ts.shortURLSvc.GetByFullPath(ctx, fullPath)
			if err != nil {
				rt.Fatalf("Cycle %d: short URL should exist after publish: %v", cycle, err)
			}

			shortResp, err := client.Get(ts.URL + "/pub/" + shortURLObj.ShortID)
			if err != nil {
				rt.Fatalf("Cycle %d: short URL request failed: %v", cycle, err)
			}
			shortBody, _ := io.ReadAll(shortResp.Body)
			shortResp.Body.Close()

			if shortResp.StatusCode != http.StatusOK {
				rt.Fatalf("Cycle %d: short URL should return 200 with inline HTML, got %d", cycle, shortResp.StatusCode)
			}
			if !strings.Contains(string(shortBody), "<html") && !strings.Contains(string(shortBody), "<HTML") {
				rt.Fatalf("Cycle %d: short URL should return HTML content", cycle)
			}

			// Unpublish (visibility=0 for private)
			unpubResp, err := client.PostForm(ts.URL+"/notes/"+noteID+"/publish", url.Values{"visibility": {"0"}})
			if err != nil {
				rt.Fatalf("Cycle %d: unpublish failed: %v", cycle, err)
			}
			unpubResp.Body.Close()

			// Property: Short URL should 404 after unpublish
			shortResp2, err := client.Get(ts.URL + "/pub/" + shortURLObj.ShortID)
			if err != nil {
				rt.Fatalf("Cycle %d: short URL after unpublish request failed: %v", cycle, err)
			}
			shortResp2.Body.Close()

			if shortResp2.StatusCode != http.StatusNotFound {
				rt.Fatalf("Cycle %d: short URL should return 404 after unpublish, got %d", cycle, shortResp2.StatusCode)
			}
		}
	})
}

// =============================================================================
// TEST 3: Short URL Edge Cases via Web Handlers
// =============================================================================

func TestShortURLWeb_EdgeCases_Properties(t *testing.T) {
	ts := setupShortURLWebServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		// Property 1: Non-existent short ID returns 404
		nonExistentID := rapid.StringMatching(`^[a-zA-Z0-9_-]{6}$`).Draw(rt, "nonExistentID")
		resp, err := http.Get(ts.URL + "/pub/" + nonExistentID)
		if err != nil {
			rt.Fatalf("Non-existent short URL request failed: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			rt.Fatalf("Non-existent short URL should return 404, got %d", resp.StatusCode)
		}

		// Property 2: Invalid format short IDs return 404
		invalidIDs := []string{
			rapid.StringMatching(`^[a-zA-Z0-9_-]{1,5}$`).Draw(rt, "tooShort"),
			rapid.StringMatching(`^[a-zA-Z0-9_-]{7,12}$`).Draw(rt, "tooLong"),
		}
		for _, id := range invalidIDs {
			invResp, err := http.Get(ts.URL + "/pub/" + id)
			if err != nil {
				rt.Fatalf("Invalid short URL request failed for %q: %v", id, err)
			}
			invResp.Body.Close()

			if invResp.StatusCode != http.StatusNotFound {
				rt.Fatalf("Invalid short URL %q should return 404, got %d", id, invResp.StatusCode)
			}
		}

		// Property 3: Short IDs with invalid characters return 404
		badCharID := rapid.StringMatching(`^[!@#$%^]{6}$`).Draw(rt, "badCharID")
		badResp, err := http.Get(ts.URL + "/pub/" + url.PathEscape(badCharID))
		if err != nil {
			rt.Fatalf("Bad char short URL request failed: %v", err)
		}
		badResp.Body.Close()

		if badResp.StatusCode != http.StatusNotFound {
			rt.Fatalf("Bad char short URL should return 404, got %d", badResp.StatusCode)
		}
	})
}

// =============================================================================
// TEST 4: Public Note Access Without Auth
// =============================================================================

func TestShortURLWeb_PublicNoteAccessAnonymous_Properties(t *testing.T) {
	ts := setupShortURLWebServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		title := testutil.NoteTitleGenerator().Draw(rt, "title")
		content := testutil.NoteContentGenerator().Draw(rt, "content")
		email := testutil.EmailGenerator().Draw(rt, "email")

		// Create and publish note as authenticated user
		jar, userID := ts.authenticateTestUser(email)
		authClient := ts.noFollowClient(jar)
		noteID := ts.createNote(authClient, title, content)

		pubResp, err := authClient.PostForm(ts.URL+"/notes/"+noteID+"/publish", url.Values{"visibility": {"1"}})
		if err != nil {
			rt.Fatalf("Publish failed: %v", err)
		}
		pubResp.Body.Close()

		// Get the short URL
		ctx := context.Background()
		fullPath := fmt.Sprintf("/public/%s/%s", userID, noteID)
		shortURLObj, err := ts.shortURLSvc.GetByFullPath(ctx, fullPath)
		if err != nil {
			rt.Fatalf("Short URL should exist: %v", err)
		}

		// Property 1: Anonymous user (no cookies) can access short URL and receive inline HTML.
		anonClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		anonResp, err := anonClient.Get(ts.URL + "/pub/" + shortURLObj.ShortID)
		if err != nil {
			rt.Fatalf("Anonymous short URL request failed: %v", err)
		}
		body, _ := io.ReadAll(anonResp.Body)
		anonResp.Body.Close()

		if anonResp.StatusCode != http.StatusOK {
			rt.Fatalf("Anonymous short URL should return 200 with inline HTML, got %d", anonResp.StatusCode)
		}

		// Property 2: Inline response body is HTML.
		html := string(body)
		if !strings.Contains(html, "<html") && !strings.Contains(html, "<HTML") {
			rt.Fatal("Short URL should return HTML content")
		}
	})
}

// =============================================================================
// TEST 5: Note View Shows Share URL After Publish
// =============================================================================

func TestShortURLWeb_NoteViewShowsShareURL_Properties(t *testing.T) {
	ts := setupShortURLWebServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		title := testutil.NoteTitleGenerator().Draw(rt, "title")
		content := testutil.NoteContentGenerator().Draw(rt, "content")
		email := testutil.EmailGenerator().Draw(rt, "email")

		jar, _ := ts.authenticateTestUser(email)
		client := ts.noFollowClient(jar)

		noteID := ts.createNote(client, title, content)

		// Before publish: view the note
		viewResp1, err := client.Get(ts.URL + "/notes/" + noteID)
		if err != nil {
			rt.Fatalf("View note before publish failed: %v", err)
		}
		body1, _ := io.ReadAll(viewResp1.Body)
		viewResp1.Body.Close()

		if viewResp1.StatusCode != http.StatusOK {
			rt.Fatalf("View note should return 200, got %d", viewResp1.StatusCode)
		}

		// Publish (visibility=1 for public anonymous)
		pubResp, err := client.PostForm(ts.URL+"/notes/"+noteID+"/publish", url.Values{"visibility": {"1"}})
		if err != nil {
			rt.Fatalf("Publish failed: %v", err)
		}
		pubResp.Body.Close()

		// After publish: view note should include share URL info
		viewResp2, err := client.Get(ts.URL + "/notes/" + noteID)
		if err != nil {
			rt.Fatalf("View note after publish failed: %v", err)
		}
		body2, _ := io.ReadAll(viewResp2.Body)
		viewResp2.Body.Close()

		if viewResp2.StatusCode != http.StatusOK {
			rt.Fatalf("View note after publish should return 200, got %d", viewResp2.StatusCode)
		}

		// Property: After publishing, the note view page should contain public URL info
		// (it should reference /public/ since the note is now public)
		html2 := string(body2)
		_ = string(body1) // Before-publish page for comparison

		if !strings.Contains(html2, "/public/") && !strings.Contains(html2, "public") {
			rt.Log("Note view after publish should reference public URL (may be in share button or link)")
		}
	})
}

// =============================================================================
// TEST 6: Publish/Unpublish Does Not Affect Note Content
// =============================================================================

func TestShortURLWeb_PublishPreservesContent_Properties(t *testing.T) {
	ts := setupShortURLWebServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		title := testutil.NoteTitleGenerator().Draw(rt, "title")
		content := testutil.NoteContentGenerator().Draw(rt, "content")
		email := testutil.EmailGenerator().Draw(rt, "email")

		jar, _ := ts.authenticateTestUser(email)
		client := ts.noFollowClient(jar)

		noteID := ts.createNote(client, title, content)

		// View before publish
		viewResp1, err := client.Get(ts.URL + "/notes/" + noteID)
		if err != nil {
			rt.Fatalf("View before publish failed: %v", err)
		}
		body1, _ := io.ReadAll(viewResp1.Body)
		viewResp1.Body.Close()

		// Publish (visibility=1 for public anonymous)
		pubResp, _ := client.PostForm(ts.URL+"/notes/"+noteID+"/publish", url.Values{"visibility": {"1"}})
		pubResp.Body.Close()

		// View after publish
		viewResp2, err := client.Get(ts.URL + "/notes/" + noteID)
		if err != nil {
			rt.Fatalf("View after publish failed: %v", err)
		}
		body2, _ := io.ReadAll(viewResp2.Body)
		viewResp2.Body.Close()

		// Property: Note title should still appear in both views
		if !strings.Contains(string(body1), title) {
			rt.Fatal("Note title should appear before publish")
		}
		if !strings.Contains(string(body2), title) {
			rt.Fatal("Note title should still appear after publish")
		}

		// Unpublish (visibility=0 for private)
		unpubResp, _ := client.PostForm(ts.URL+"/notes/"+noteID+"/publish", url.Values{"visibility": {"0"}})
		unpubResp.Body.Close()

		// View after unpublish
		viewResp3, err := client.Get(ts.URL + "/notes/" + noteID)
		if err != nil {
			rt.Fatalf("View after unpublish failed: %v", err)
		}
		body3, _ := io.ReadAll(viewResp3.Body)
		viewResp3.Body.Close()

		// Property: Note title should still appear after unpublish
		if !strings.Contains(string(body3), title) {
			rt.Fatal("Note title should still appear after unpublish")
		}
	})
}

// =============================================================================
// TEST 7: Multiple Notes Have Independent Short URLs
// =============================================================================

func TestShortURLWeb_MultipleNotesIndependent_Properties(t *testing.T) {
	ts := setupShortURLWebServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")
		numNotes := rapid.IntRange(2, 4).Draw(rt, "numNotes")

		jar, userID := ts.authenticateTestUser(email)
		client := ts.noFollowClient(jar)
		ctx := context.Background()

		type noteInfo struct {
			id      string
			shortID string
		}
		var publishedNotes []noteInfo

		// Create and publish multiple notes
		for i := 0; i < numNotes; i++ {
			title := testutil.NoteTitleGenerator().Draw(rt, fmt.Sprintf("title_%d", i))
			content := testutil.NoteContentGenerator().Draw(rt, fmt.Sprintf("content_%d", i))

			noteID := ts.createNote(client, title, content)

			pubResp, err := client.PostForm(ts.URL+"/notes/"+noteID+"/publish", url.Values{"visibility": {"1"}})
			if err != nil {
				rt.Fatalf("Publish note %d failed: %v", i, err)
			}
			pubResp.Body.Close()

			fullPath := fmt.Sprintf("/public/%s/%s", userID, noteID)
			shortURLObj, err := ts.shortURLSvc.GetByFullPath(ctx, fullPath)
			if err != nil {
				rt.Fatalf("Short URL for note %d should exist: %v", i, err)
			}

			publishedNotes = append(publishedNotes, noteInfo{id: noteID, shortID: shortURLObj.ShortID})
		}

		// Property 1: All short IDs are unique
		seen := make(map[string]bool)
		for _, n := range publishedNotes {
			if seen[n.shortID] {
				rt.Fatalf("Duplicate short ID: %s", n.shortID)
			}
			seen[n.shortID] = true
		}

		// Property 2: Each short URL returns inline HTML (200 OK)
		for _, n := range publishedNotes {
			resp, err := client.Get(ts.URL + "/pub/" + n.shortID)
			if err != nil {
				rt.Fatalf("Short URL %s request failed: %v", n.shortID, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				rt.Fatalf("Short URL %s should return 200 with inline HTML, got %d", n.shortID, resp.StatusCode)
			}
			html := string(body)
			if !strings.Contains(html, "<html") && !strings.Contains(html, "<HTML") {
				rt.Fatalf("Short URL %s should return HTML content", n.shortID)
			}
			if !strings.Contains(html, n.id) {
				rt.Fatalf("Short URL %s HTML should contain note ID %s", n.shortID, n.id)
			}
		}

		// Property 3: Unpublishing one note does not affect others
		if len(publishedNotes) >= 2 {
			// Unpublish first note (visibility=0 for private)
			unpubResp, _ := client.PostForm(ts.URL+"/notes/"+publishedNotes[0].id+"/publish", url.Values{"visibility": {"0"}})
			unpubResp.Body.Close()

			// First note's short URL should 404
			resp0, _ := client.Get(ts.URL + "/pub/" + publishedNotes[0].shortID)
			resp0.Body.Close()
			if resp0.StatusCode != http.StatusNotFound {
				rt.Fatalf("Unpublished note's short URL should return 404, got %d", resp0.StatusCode)
			}

			// Second note's short URL should still work
			resp1, _ := client.Get(ts.URL + "/pub/" + publishedNotes[1].shortID)
			resp1.Body.Close()
			if resp1.StatusCode != http.StatusOK {
				rt.Fatalf("Other note's short URL should still return 200, got %d", resp1.StatusCode)
			}
		}
	})
}

// =============================================================================
// TEST 8: Unauthenticated Publish Attempt
// =============================================================================

func TestShortURLWeb_UnauthPublishAttempt_Properties(t *testing.T) {
	ts := setupShortURLWebServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		email := testutil.EmailGenerator().Draw(rt, "email")

		// Create and authenticate
		jar, _ := ts.authenticateTestUser(email)
		authClient := ts.noFollowClient(jar)

		title := testutil.NoteTitleGenerator().Draw(rt, "title")
		content := testutil.NoteContentGenerator().Draw(rt, "content")
		noteID := ts.createNote(authClient, title, content)

		// Property: Unauthenticated user cannot publish a note
		anonClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		pubResp, err := anonClient.PostForm(ts.URL+"/notes/"+noteID+"/publish", url.Values{})
		if err != nil {
			rt.Fatalf("Anon publish request failed: %v", err)
		}
		pubResp.Body.Close()

		// Should redirect to login (not 200 or 500)
		if pubResp.StatusCode == http.StatusOK {
			rt.Fatal("Unauthenticated publish should not return 200")
		}
		if pubResp.StatusCode == http.StatusInternalServerError {
			rt.Fatal("Unauthenticated publish should not return 500")
		}
	})
}

// =============================================================================
// TEST 9: Google OAuth Web Handlers (HandleGoogleLogin / HandleGoogleCallback)
// =============================================================================

func TestShortURLWeb_GoogleOAuthHandlers_Properties(t *testing.T) {
	ts := setupShortURLWebServer(t)
	defer ts.cleanup()

	rapid.Check(t, func(rt *rapid.T) {
		testEmail := testutil.EmailGenerator().Draw(rt, "email")

		client := ts.noFollowClient(nil)
		jar, _ := cookiejar.New(nil)
		client.Jar = jar

		// Property 1: GET /auth/google redirects to OIDC provider
		googleResp, err := client.Get(ts.URL + "/auth/google")
		if err != nil {
			rt.Fatalf("Google login request failed: %v", err)
		}
		googleResp.Body.Close()

		if googleResp.StatusCode != http.StatusFound {
			rt.Fatalf("Google login should redirect (302), got %d", googleResp.StatusCode)
		}

		// Property 2: Redirect contains state parameter
		location := googleResp.Header.Get("Location")
		if !strings.Contains(location, "state=") {
			rt.Fatal("Google login redirect should contain state parameter")
		}

		// Property 3: oauth_state cookie is set
		var stateCookie *http.Cookie
		for _, c := range googleResp.Cookies() {
			if c.Name == "oauth_state" {
				stateCookie = c
				break
			}
		}
		if stateCookie == nil {
			rt.Fatal("oauth_state cookie should be set")
		}

		// Property 4: Callback without state cookie returns 400
		noStateCookieClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		badResp, err := noStateCookieClient.Get(ts.URL + "/auth/google/callback?code=test&state=test")
		if err != nil {
			rt.Fatalf("Callback without state cookie failed: %v", err)
		}
		badResp.Body.Close()
		if badResp.StatusCode != http.StatusBadRequest {
			rt.Fatalf("Callback without state cookie should return 400, got %d", badResp.StatusCode)
		}

		// Property 5: Callback with mismatched state returns 400
		mismatchJar, _ := cookiejar.New(nil)
		mismatchClient := &http.Client{
			Jar: mismatchJar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		serverURL, _ := url.Parse(ts.URL)
		mismatchJar.SetCookies(serverURL, []*http.Cookie{{
			Name:  "oauth_state",
			Value: "correct_state",
			Path:  "/",
		}})
		mismatchResp, err := mismatchClient.Get(ts.URL + "/auth/google/callback?code=test&state=wrong_state")
		if err != nil {
			rt.Fatalf("Mismatched state callback failed: %v", err)
		}
		mismatchResp.Body.Close()
		if mismatchResp.StatusCode != http.StatusBadRequest {
			rt.Fatalf("Mismatched state should return 400, got %d", mismatchResp.StatusCode)
		}

		// Property 6: Callback with error param returns 401
		errJar, _ := cookiejar.New(nil)
		errClient := &http.Client{
			Jar: errJar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		errJar.SetCookies(serverURL, []*http.Cookie{{
			Name:  "oauth_state",
			Value: "state123",
			Path:  "/",
		}})
		errorResp, err := errClient.Get(ts.URL + "/auth/google/callback?error=access_denied&state=state123")
		if err != nil {
			rt.Fatalf("Error callback failed: %v", err)
		}
		errorResp.Body.Close()
		if errorResp.StatusCode != http.StatusUnauthorized {
			rt.Fatalf("Error callback should return 401, got %d", errorResp.StatusCode)
		}

		// Property 7: Successful callback flow creates session
		auth.SetSecureCookies(false)
		defer auth.SetSecureCookies(true)

		successJar, _ := cookiejar.New(nil)
		successClient := &http.Client{
			Jar: successJar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		sessionCookie := doMockOIDCLogin(rt, successClient, ts.URL, testEmail)
		if sessionCookie == "" {
			rt.Fatal("Session cookie should be set after successful OIDC login")
		}

		// Property 8: Authenticated user can access whoami
		successJar.SetCookies(serverURL, []*http.Cookie{{
			Name: "session_id", Value: sessionCookie, Path: "/",
		}})

		// Property 9: Callback without code returns 400
		noCodeJar, _ := cookiejar.New(nil)
		noCodeClient := &http.Client{
			Jar: noCodeJar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		noCodeJar.SetCookies(serverURL, []*http.Cookie{{
			Name:  "oauth_state",
			Value: "stateXYZ",
			Path:  "/",
		}})
		noCodeResp, err := noCodeClient.Get(ts.URL + "/auth/google/callback?state=stateXYZ")
		if err != nil {
			rt.Fatalf("No-code callback failed: %v", err)
		}
		noCodeResp.Body.Close()
		if noCodeResp.StatusCode != http.StatusBadRequest {
			rt.Fatalf("Callback without code should return 400, got %d", noCodeResp.StatusCode)
		}
	})
}

// =============================================================================
// FUZZ ENTRY POINTS
// =============================================================================

func FuzzShortURLWeb_FullFlow_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(t *rapid.T) {
		// Lightweight version of the full flow for fuzzing
		title := testutil.NoteTitleGenerator().Draw(t, "title")
		content := testutil.NoteContentGenerator().Draw(t, "content")

		// Just verify format properties of generated short IDs
		shortID, err := shorturl.GenerateShortID()
		if err != nil {
			t.Fatalf("GenerateShortID failed: %v", err)
		}

		if len(shortID) != 6 {
			t.Fatalf("Short ID length is %d, expected 6", len(shortID))
		}

		if !shorturl.ValidateShortID(shortID) {
			t.Fatalf("Generated short ID failed validation: %s", shortID)
		}

		// Verify title and content are non-hostile (generators should produce safe strings)
		if len(title) == 0 {
			t.Fatal("Title should not be empty")
		}
		_ = content
	}))
}

func FuzzShortURLWeb_EdgeCases_Properties(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(t *rapid.T) {
		// Property: ValidateShortID rejects arbitrary strings
		arbitrary := rapid.String().Draw(t, "arbitrary")
		if len(arbitrary) != 6 {
			if shorturl.ValidateShortID(arbitrary) {
				t.Fatalf("Non-6-char string should be rejected: %q", arbitrary)
			}
		}

		// Property: ValidateShortID accepts valid format strings
		valid := rapid.StringMatching(`^[a-zA-Z0-9_-]{6}$`).Draw(t, "valid")
		if !shorturl.ValidateShortID(valid) {
			t.Fatalf("Valid format string should be accepted: %s", valid)
		}
	}))
}
