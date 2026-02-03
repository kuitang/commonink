// Package lifecycle tests the server as a subprocess with real HTTP requests.
// Tests extract emails from server logs to complete auth flows.
package lifecycle

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// =============================================================================
// Test Fixture: Single server for all tests
// =============================================================================

var (
	testServer  *serverFixture
	testOnce    sync.Once
	testCleanup func()
)

type serverFixture struct {
	cmd     *exec.Cmd
	baseURL string
	port    int
	logs    *logCapture
	dataDir string
}

type logCapture struct {
	mu    sync.RWMutex
	lines []string
}

func (l *logCapture) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range strings.Split(string(p), "\n") {
		if line != "" {
			l.lines = append(l.lines, line)
		}
	}
	return len(p), nil
}

func (l *logCapture) Lines() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	cp := make([]string, len(l.lines))
	copy(cp, l.lines)
	return cp
}

func (l *logCapture) FindEmail(to string) (link string, template string, ok bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	toPattern := regexp.MustCompile(`\[EMAIL\] To: ` + regexp.QuoteMeta(to) + ` \| Template: (\w+)`)
	linkPattern := regexp.MustCompile(`\[EMAIL\] (?:Magic Link|Password Reset Link): (http[^\s]+)`)

	for i, line := range l.lines {
		if m := toPattern.FindStringSubmatch(line); m != nil {
			template = m[1]
			// Next line should have the link
			if i+1 < len(l.lines) {
				if lm := linkPattern.FindStringSubmatch(l.lines[i+1]); lm != nil {
					return lm[1], template, true
				}
			}
		}
	}
	return "", "", false
}

func (l *logCapture) WaitForEmail(to string, timeout time.Duration) (link, template string, err error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if link, template, ok := l.FindEmail(to); ok {
			return link, template, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return "", "", fmt.Errorf("timeout waiting for email to %s", to)
}

// getServer returns the shared server fixture, starting it if needed.
func getServer(t *testing.T) *serverFixture {
	testOnce.Do(func() {
		testServer, testCleanup = startServer(t)
	})
	t.Cleanup(func() {
		// Don't stop server after each test - reuse it
		// Server stops when all tests complete via TestMain
	})
	return testServer
}

func TestMain(m *testing.M) {
	code := m.Run()
	if testCleanup != nil {
		testCleanup()
	}
	os.Exit(code)
}

func startServer(t *testing.T) (*serverFixture, func()) {
	// Find project root
	projectRoot := findProjectRoot()

	// Create temp data dir
	dataDir, err := os.MkdirTemp("", "lifecycle-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Build server
	binary := filepath.Join(dataDir, "server")
	buildCmd := exec.Command("go", "build", "-o", binary, "./cmd/server")
	buildCmd.Dir = projectRoot
	buildCmd.Env = append(os.Environ(),
		"CGO_ENABLED=1",
		"CGO_CFLAGS=-DSQLITE_ENABLE_FTS5",
		"CGO_LDFLAGS=-lm",
	)
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Build failed: %v\n%s", err, out)
	}

	// Find free port
	port := findFreePort()

	// Start server
	logs := &logCapture{}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, "--test")
	cmd.Dir = dataDir
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("LISTEN_ADDR=:%d", port),
		fmt.Sprintf("DATA_DIR=%s", dataDir),
		fmt.Sprintf("BASE_URL=http://localhost:%d", port),
		fmt.Sprintf("TEMPLATES_DIR=%s", filepath.Join(projectRoot, "web/templates")),
	)

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("Failed to start server: %v", err)
	}

	// Capture logs from both stdout and stderr
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			logs.Write([]byte(line + "\n"))
			fmt.Println("[SERVER]", line) // Also print to test output
		}
	}()
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			logs.Write([]byte(line + "\n"))
			fmt.Println("[SERVER-ERR]", line)
		}
	}()

	baseURL := fmt.Sprintf("http://localhost:%d", port)

	// Wait for server ready (short timeout - server should start quickly)
	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		resp, err := client.Get(baseURL + "/health")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			t.Logf("Server started on port %d", port)
			ready = true
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		cancel()
		t.Fatalf("Server did not become ready within 5s. Logs:\n%s", strings.Join(logs.Lines(), "\n"))
	}

	fixture := &serverFixture{
		cmd:     cmd,
		baseURL: baseURL,
		port:    port,
		logs:    logs,
		dataDir: dataDir,
	}

	cleanup := func() {
		cmd.Process.Signal(syscall.SIGTERM)
		time.Sleep(500 * time.Millisecond)
		cancel()
		os.RemoveAll(dataDir)
	}

	return fixture, cleanup
}

func findProjectRoot() string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("could not find project root")
		}
		dir = parent
	}
}

func findFreePort() int {
	l, _ := net.Listen("tcp", ":0")
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// =============================================================================
// HTTP Client Helper
// =============================================================================

func newClient(baseURL string) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// =============================================================================
// Email Generators
// =============================================================================

func genValidEmail() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		local := rapid.StringMatching(`[a-z]{3,10}`).Draw(t, "local")
		domains := []string{"example.com", "test.org", "mail.co.uk", "company.io"}
		domain := domains[rapid.IntRange(0, len(domains)-1).Draw(t, "domainIdx")]
		return local + "@" + domain
	})
}

func genEdgeCaseEmail() *rapid.Generator[string] {
	return rapid.SampledFrom([]string{
		"a@b.co",
		"test+tag@example.com",
		"user.name@example.com",
		"user-name@example.com",
		"USER@EXAMPLE.COM",
		"123@example.com",
		"test@sub.domain.example.com",
	})
}

// =============================================================================
// Tests
// =============================================================================

func TestLifecycle_HealthCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping lifecycle test")
	}
	srv := getServer(t)

	resp, err := http.Get(srv.baseURL + "/health")
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}
}

func TestLifecycle_MagicLink_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping lifecycle test")
	}
	srv := getServer(t)

	rapid.Check(t, func(rt *rapid.T) {
		email := genValidEmail().Draw(rt, "email")
		client := newClient(srv.baseURL)

		// Request magic link - returns redirect to login page
		resp, err := client.PostForm(srv.baseURL+"/auth/magic", url.Values{"email": {email}})
		if err != nil {
			rt.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()
		// Expect redirect (303 See Other) to login page
		if resp.StatusCode != http.StatusSeeOther {
			rt.Fatalf("Expected 303, got %d", resp.StatusCode)
		}

		// Extract from logs
		link, template, err := srv.logs.WaitForEmail(email, 5*time.Second)
		if err != nil {
			rt.Fatalf("Email not found: %v", err)
		}

		// Verify properties
		if template != "magic_link" {
			rt.Fatalf("Expected magic_link template, got %s", template)
		}
		if !strings.Contains(link, "/auth/magic/verify") {
			rt.Fatalf("Link should contain verify endpoint: %s", link)
		}
		parsed, _ := url.Parse(link)
		if parsed.Query().Get("token") == "" {
			rt.Fatalf("Link should have token: %s", link)
		}
	})
}

func TestLifecycle_MagicLink_EdgeCases_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping lifecycle test")
	}
	srv := getServer(t)

	rapid.Check(t, func(rt *rapid.T) {
		email := genEdgeCaseEmail().Draw(rt, "email")
		client := newClient(srv.baseURL)

		resp, _ := client.PostForm(srv.baseURL+"/auth/magic", url.Values{"email": {email}})
		if resp != nil {
			resp.Body.Close()
		}

		link, _, err := srv.logs.WaitForEmail(email, 5*time.Second)
		if err != nil {
			rt.Fatalf("Email not found for edge case %q: %v", email, err)
		}
		if !strings.HasPrefix(link, "http") {
			rt.Fatalf("Invalid link for %q: %s", email, link)
		}
	})
}

func TestLifecycle_MagicLink_FullFlow_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping lifecycle test")
	}
	srv := getServer(t)

	rapid.Check(t, func(rt *rapid.T) {
		email := genValidEmail().Draw(rt, "email")
		client := newClient(srv.baseURL)

		// 1. Request magic link
		resp, _ := client.PostForm(srv.baseURL+"/auth/magic", url.Values{"email": {email}})
		if resp != nil {
			resp.Body.Close()
		}

		// 2. Get link from logs
		link, _, err := srv.logs.WaitForEmail(email, 5*time.Second)
		if err != nil {
			rt.Fatalf("Email not found: %v", err)
		}

		// 3. Visit magic link (authenticates)
		resp, err = client.Get(link)
		if err != nil {
			rt.Fatalf("Visit magic link failed: %v", err)
		}
		resp.Body.Close()

		// 4. Verify authenticated - can list notes
		resp, err = client.Get(srv.baseURL + "/api/notes")
		if err != nil {
			rt.Fatalf("List notes failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			rt.Fatalf("Expected 200, got %d (not authenticated?)", resp.StatusCode)
		}

		// 5. Cleanup: logout
		client.PostForm(srv.baseURL+"/auth/logout", nil)
	})
}

func TestLifecycle_JSONAPI_CRUD_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping lifecycle test")
	}
	srv := getServer(t)

	// Auth once for all iterations
	client := newClient(srv.baseURL)
	authEmail := "jsontest-" + fmt.Sprintf("%d", time.Now().UnixNano()) + "@example.com"

	resp, _ := client.PostForm(srv.baseURL+"/auth/magic", url.Values{"email": {authEmail}})
	if resp != nil {
		resp.Body.Close()
	}
	link, _, _ := srv.logs.WaitForEmail(authEmail, 5*time.Second)
	resp, _ = client.Get(link)
	if resp != nil {
		resp.Body.Close()
	}

	rapid.Check(t, func(rt *rapid.T) {
		title := rapid.StringMatching(`[A-Za-z0-9 ]{1,50}`).Draw(rt, "title")
		content := rapid.StringMatching(`[A-Za-z0-9 ]{0,100}`).Draw(rt, "content") // Limit to safe chars

		// Create - use json.Marshal for proper encoding
		noteData := map[string]string{"title": title, "content": content}
		bodyBytes, _ := json.Marshal(noteData)
		req, _ := http.NewRequest("POST", srv.baseURL+"/api/notes", strings.NewReader(string(bodyBytes)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			rt.Fatalf("Create failed: %v", err)
		}
		if resp.StatusCode != 201 {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			rt.Fatalf("Create expected 201, got %d: %s", resp.StatusCode, b)
		}
		var created struct {
			ID string `json:"id"`
		}
		json.NewDecoder(resp.Body).Decode(&created)
		resp.Body.Close()

		// Read
		resp, _ = client.Get(srv.baseURL + "/api/notes/" + created.ID)
		if resp.StatusCode != 200 {
			rt.Fatalf("Read expected 200, got %d", resp.StatusCode)
		}
		var note struct {
			Title   string `json:"title"`
			Content string `json:"content"`
		}
		json.NewDecoder(resp.Body).Decode(&note)
		resp.Body.Close()
		if note.Title != title || note.Content != content {
			rt.Fatalf("Roundtrip failed: got %q/%q, want %q/%q", note.Title, note.Content, title, content)
		}

		// Delete (cleanup)
		req, _ = http.NewRequest("DELETE", srv.baseURL+"/api/notes/"+created.ID, nil)
		resp, _ = client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
	})
}

func TestLifecycle_Unauthenticated_Redirects(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping lifecycle test")
	}
	srv := getServer(t)
	client := newClient(srv.baseURL)

	// HTML pages should redirect to login
	pages := []string{"/notes", "/notes/new", "/settings/tokens"}
	for _, page := range pages {
		resp, err := client.Get(srv.baseURL + page)
		if err != nil {
			t.Fatalf("Get %s failed: %v", page, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 302 {
			t.Errorf("%s: expected 302, got %d", page, resp.StatusCode)
		}
		if !strings.Contains(resp.Header.Get("Location"), "/login") {
			t.Errorf("%s: should redirect to /login, got %s", page, resp.Header.Get("Location"))
		}
	}

	// API endpoints should return 401
	apis := []string{"/api/notes"}
	for _, api := range apis {
		resp, err := client.Get(srv.baseURL + api)
		if err != nil {
			t.Fatalf("Get %s failed: %v", api, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("%s: expected 401, got %d", api, resp.StatusCode)
		}
	}
}

func TestLifecycle_PasswordReset_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping lifecycle test")
	}
	srv := getServer(t)

	rapid.Check(t, func(rt *rapid.T) {
		email := genValidEmail().Draw(rt, "email")
		password := "TestPass123!"
		client := newClient(srv.baseURL)

		// Register user first
		resp, _ := client.PostForm(srv.baseURL+"/auth/register", url.Values{
			"email":    {email},
			"password": {password},
		})
		if resp != nil {
			resp.Body.Close()
		}

		// Request password reset
		resp, _ = client.PostForm(srv.baseURL+"/auth/password-reset", url.Values{"email": {email}})
		if resp != nil {
			resp.Body.Close()
		}

		// Check logs for reset email
		link, template, err := srv.logs.WaitForEmail(email, 5*time.Second)
		if err != nil {
			rt.Fatalf("Password reset email not found: %v", err)
		}
		if template != "password_reset" {
			rt.Fatalf("Expected password_reset template, got %s", template)
		}
		if !strings.Contains(link, "password-reset") {
			rt.Fatalf("Link should contain password-reset: %s", link)
		}
	})
}
