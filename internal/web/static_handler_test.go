package web_test

import (
	"context"
	crand "crypto/rand"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	_ "github.com/mutecomm/go-sqlcipher/v4"
	_ "pgregory.net/rapid" // registers -rapid.checks flag for unified make test

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
	emailpkg "github.com/kuitang/agent-notes/internal/email"
	"github.com/kuitang/agent-notes/internal/web"
)

// staticTestEnv holds a test server with static routes, auth middleware, and services.
type staticTestEnv struct {
	server         *httptest.Server
	userService    *auth.UserService
	sessionService *auth.SessionService
}

func setupStaticTestEnv(t *testing.T) *staticTestEnv {
	t.Helper()

	tempDir := t.TempDir()
	db.ResetForTesting()
	db.DataDirectory = tempDir

	sessionsDB, err := db.OpenSessionsDB()
	if err != nil {
		t.Fatalf("Failed to open sessions database: %v", err)
	}

	masterKey := make([]byte, 32)
	if _, err := crand.Read(masterKey); err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	keyManager := crypto.NewKeyManager(masterKey, sessionsDB)
	emailService := emailpkg.NewMockEmailService()

	// Create initial server to get URL
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	userService := auth.NewUserService(sessionsDB, keyManager, emailService, server.URL, auth.FakeInsecureHasher{})
	sessionService := auth.NewSessionService(sessionsDB)
	authMiddleware := auth.NewMiddleware(sessionService, keyManager)

	// Close initial server, build final mux
	server.Close()
	mux = http.NewServeMux()
	server = httptest.NewServer(mux)

	// Re-create userService with correct URL
	userService = auth.NewUserService(sessionsDB, keyManager, emailService, server.URL, auth.FakeInsecureHasher{})

	// Template renderer
	templatesDir := findTemplatesDir()
	renderer, err := web.NewRenderer(templatesDir)
	if err != nil {
		t.Fatalf("Failed to create renderer: %v", err)
	}

	// Static handler with auth
	staticSrcDir := findStaticSrcDir()
	staticHandler := web.NewStaticHandler(renderer, staticSrcDir, authMiddleware)
	staticHandler.RegisterRoutes(mux)

	t.Cleanup(func() {
		server.Close()
		db.CloseAll()
	})

	return &staticTestEnv{
		server:         server,
		userService:    userService,
		sessionService: sessionService,
	}
}

// authenticatedClient returns an HTTP client with a valid session cookie.
func (env *staticTestEnv) authenticatedClient(t *testing.T, email string) (*http.Client, string) {
	t.Helper()
	ctx := context.Background()

	user, err := env.userService.FindOrCreateByProvider(ctx, email)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	sessionID, err := env.sessionService.Create(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	jar, _ := cookiejar.New(nil)
	serverURL, _ := url.Parse(env.server.URL)
	jar.SetCookies(serverURL, []*http.Cookie{{
		Name:  "session_id",
		Value: sessionID,
		Path:  "/",
	}})

	return &http.Client{Jar: jar}, email
}

func findTemplatesDir() string {
	candidates := []string{
		"../../web/templates",
		"../../../web/templates",
		"/home/kuitang/git/agent-notes/web/templates",
	}
	for _, d := range candidates {
		if _, err := os.Stat(d); err == nil {
			return d
		}
	}
	return "/home/kuitang/git/agent-notes/web/templates"
}

func findStaticSrcDir() string {
	candidates := []string{
		"../../static/src",
		"../../../static/src",
		"/home/kuitang/git/agent-notes/static/src",
	}
	for _, d := range candidates {
		if _, err := os.Stat(d); err == nil {
			return d
		}
	}
	return "/home/kuitang/git/agent-notes/static/src"
}

// =============================================================================
// Logged-in header: nav shows user email, not "Sign in"
// =============================================================================

func TestStaticPages_LoggedInHeader(t *testing.T) {
	env := setupStaticTestEnv(t)
	client, email := env.authenticatedClient(t, "header-test@example.com")

	pages := []string{"/privacy", "/terms", "/about", "/docs/api", "/docs/install"}

	for _, path := range pages {
		t.Run(path, func(t *testing.T) {
			resp, err := client.Get(env.server.URL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s: expected 200, got %d", path, resp.StatusCode)
			}

			body, _ := io.ReadAll(resp.Body)
			html := string(body)

			if !strings.Contains(html, email) {
				t.Errorf("GET %s: expected user email %q in nav", path, email)
			}
		})
	}
}

// =============================================================================
// Logged-out header: nav shows "Sign in", not user email
// =============================================================================

func TestStaticPages_LoggedOutHeader(t *testing.T) {
	env := setupStaticTestEnv(t)
	client := &http.Client{}

	pages := []string{"/privacy", "/terms", "/about", "/docs/api", "/docs/install"}

	for _, path := range pages {
		t.Run(path, func(t *testing.T) {
			resp, err := client.Get(env.server.URL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s: expected 200, got %d", path, resp.StatusCode)
			}

			body, _ := io.ReadAll(resp.Body)
			html := string(body)

			if !strings.Contains(html, "Sign in") {
				t.Errorf("GET %s: expected 'Sign in' in nav for logged-out user", path)
			}
		})
	}
}

// =============================================================================
// Content negotiation: Accept: text/markdown → raw .md
// =============================================================================

func TestStaticPages_ContentNegotiation_AcceptHeader(t *testing.T) {
	env := setupStaticTestEnv(t)
	client := &http.Client{}

	markdownPages := []string{"/privacy", "/terms", "/about", "/docs/api"}

	for _, path := range markdownPages {
		t.Run(path, func(t *testing.T) {
			req, _ := http.NewRequest("GET", env.server.URL+path, nil)
			req.Header.Set("Accept", "text/markdown")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s: expected 200, got %d", path, resp.StatusCode)
			}

			ct := resp.Header.Get("Content-Type")
			if ct != "text/markdown; charset=UTF-8" {
				t.Errorf("GET %s: expected Content-Type text/markdown; charset=UTF-8, got %q", path, ct)
			}

			vary := resp.Header.Get("Vary")
			if vary != "Accept" {
				t.Errorf("GET %s: expected Vary: Accept, got %q", path, vary)
			}

			body, _ := io.ReadAll(resp.Body)
			text := string(body)

			// Raw markdown should contain markdown syntax, not HTML tags
			if strings.Contains(text, "<html>") || strings.Contains(text, "<!DOCTYPE") {
				t.Errorf("GET %s: raw markdown should not contain HTML document structure", path)
			}

			// Should contain markdown heading
			if !strings.Contains(text, "#") {
				t.Errorf("GET %s: raw markdown should contain '#' headings", path)
			}
		})
	}
}

// =============================================================================
// Content negotiation: .md suffix → raw .md
// =============================================================================

func TestStaticPages_ContentNegotiation_MDSuffix(t *testing.T) {
	env := setupStaticTestEnv(t)
	client := &http.Client{}

	mdPaths := []string{"/privacy.md", "/terms.md", "/about.md", "/docs/api.md", "/docs.md"}

	for _, path := range mdPaths {
		t.Run(path, func(t *testing.T) {
			resp, err := client.Get(env.server.URL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s: expected 200, got %d", path, resp.StatusCode)
			}

			ct := resp.Header.Get("Content-Type")
			if ct != "text/markdown; charset=UTF-8" {
				t.Errorf("GET %s: expected Content-Type text/markdown; charset=UTF-8, got %q", path, ct)
			}

			body, _ := io.ReadAll(resp.Body)
			text := string(body)

			if strings.Contains(text, "<html>") || strings.Contains(text, "<!DOCTYPE") {
				t.Errorf("GET %s: .md route should not return HTML document", path)
			}
		})
	}
}

// =============================================================================
// No double rendering: exactly one <nav tag, no nested <!DOCTYPE
// =============================================================================

func TestStaticPages_NoDoubleRendering(t *testing.T) {
	env := setupStaticTestEnv(t)
	client := &http.Client{}

	pages := []string{"/privacy", "/terms", "/about", "/docs/api", "/docs/install"}

	for _, path := range pages {
		t.Run(path, func(t *testing.T) {
			resp, err := client.Get(env.server.URL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			html := string(body)

			// Exactly one <!DOCTYPE — the key double-render signal
			doctypeCount := strings.Count(html, "<!DOCTYPE")
			if doctypeCount != 1 {
				t.Errorf("GET %s: expected exactly 1 <!DOCTYPE>, found %d", path, doctypeCount)
			}

			// Exactly one <html tag
			htmlTagCount := strings.Count(html, "<html")
			if htmlTagCount != 1 {
				t.Errorf("GET %s: expected exactly 1 <html> tag, found %d", path, htmlTagCount)
			}
		})
	}
}

// =============================================================================
// Copy buttons: API docs page has copy-btn class
// =============================================================================

func TestStaticPages_CopyButtons(t *testing.T) {
	env := setupStaticTestEnv(t)
	client := &http.Client{}

	resp, err := client.Get(env.server.URL + "/docs/api")
	if err != nil {
		t.Fatalf("GET /docs/api: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	if !strings.Contains(html, "copy-btn") {
		t.Error("GET /docs/api: expected 'copy-btn' class for copy buttons")
	}
}
