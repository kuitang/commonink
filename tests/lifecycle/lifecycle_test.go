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
	testServer   *serverFixture
	testOnce     sync.Once
	testCleanup  func()
	testStartErr error
)

const (
	testMasterKey    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testOAuthHMACKey = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testOAuthSignKey = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

type serverFixture struct {
	cmd     *exec.Cmd
	baseURL string
	port    int
	logs    *logCapture
	outbox  *emailOutbox
	dataDir string
}

type logCapture struct {
	mu     sync.Mutex
	lines  []string
	notify chan struct{}
}

func newLogCapture() *logCapture {
	return &logCapture{
		lines:  make([]string, 0, 256),
		notify: make(chan struct{}),
	}
}

func (l *logCapture) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	added := false
	for _, line := range strings.Split(string(p), "\n") {
		if line != "" {
			l.lines = append(l.lines, line)
			added = true
		}
	}
	if added {
		close(l.notify)
		l.notify = make(chan struct{})
	}
	return len(p), nil
}

func (l *logCapture) Lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := make([]string, len(l.lines))
	copy(cp, l.lines)
	return cp
}

func (l *logCapture) waitCh() <-chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.notify
}

func (l *logCapture) Cursor() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.lines)
}

func (l *logCapture) waitForSubstringSince(ctx context.Context, substr string, start int) error {
	cursor := start

	for {
		l.mu.Lock()
		if cursor < 0 {
			cursor = 0
		}
		for i := cursor; i < len(l.lines); i++ {
			if strings.Contains(l.lines[i], substr) {
				l.mu.Unlock()
				return nil
			}
		}
		cursor = len(l.lines)
		waitCh := l.notify
		l.mu.Unlock()

		select {
		case <-waitCh:
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for log line containing %q: %w", substr, ctx.Err())
		}
	}
}

type emailOutbox struct {
	dir string
}

type outboxEmailEvent struct {
	Sequence uint64 `json:"sequence"`
	To       string `json:"to"`
	Template string `json:"template"`
	Link     string `json:"link"`
}

func newEmailOutbox(dir string) *emailOutbox {
	return &emailOutbox{dir: dir}
}

func (o *emailOutbox) Cursor() uint64 {
	entries, err := os.ReadDir(o.dir)
	if err != nil {
		return 0
	}

	var maxSeq uint64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		seq, ok := parseOutboxSequence(entry.Name())
		if ok && seq > maxSeq {
			maxSeq = seq
		}
	}
	return maxSeq
}

func (o *emailOutbox) WaitForEmailSince(
	to string,
	startSeq uint64,
	ctx context.Context,
	logs *logCapture,
) (link, template string, err error) {
	cursor := startSeq

	for {
		var ok bool
		link, template, cursor, ok, err = o.findEmailSince(to, cursor)
		if err != nil {
			return "", "", err
		}
		if ok {
			return link, template, nil
		}

		waitCh := logs.waitCh()
		select {
		case <-waitCh:
		case <-ctx.Done():
			return "", "", fmt.Errorf("timeout waiting for email to %s: %w", to, ctx.Err())
		}
	}
}

func (o *emailOutbox) findEmailSince(to string, startSeq uint64) (link, template string, next uint64, ok bool, err error) {
	entries, err := os.ReadDir(o.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", startSeq, false, nil
		}
		return "", "", startSeq, false, fmt.Errorf("read outbox: %w", err)
	}

	maxSeq := startSeq
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		seq, seqOK := parseOutboxSequence(entry.Name())
		if !seqOK {
			continue
		}
		if seq > maxSeq {
			maxSeq = seq
		}
		if seq <= startSeq {
			continue
		}

		path := filepath.Join(o.dir, entry.Name())
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}

		var event outboxEmailEvent
		if unmarshalErr := json.Unmarshal(raw, &event); unmarshalErr != nil {
			continue
		}
		if strings.EqualFold(event.To, to) {
			return event.Link, event.Template, maxSeq, true, nil
		}
	}

	return "", "", maxSeq, false, nil
}

func parseOutboxSequence(fileName string) (uint64, bool) {
	parts := strings.SplitN(fileName, "-", 2)
	if len(parts) < 2 {
		return 0, false
	}
	var seq uint64
	if _, err := fmt.Sscanf(parts[0], "%d", &seq); err != nil {
		return 0, false
	}
	return seq, true
}

// getServer returns the shared server fixture, starting it if needed.
func getServer(t *testing.T) *serverFixture {
	t.Helper()

	testOnce.Do(func() {
		testServer, testCleanup, testStartErr = startServer(t)
	})
	if testStartErr != nil {
		t.Fatalf("Failed to start lifecycle server fixture: %v", testStartErr)
	}
	if testServer == nil {
		t.Fatalf("Lifecycle server fixture is nil")
	}
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

func startServer(t *testing.T) (*serverFixture, func(), error) {
	// Find project root
	projectRoot := findProjectRoot()

	// Create temp data dir
	dataDir, err := os.MkdirTemp("", "lifecycle-test-*")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp dir: %w", err)
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
		return nil, nil, fmt.Errorf("build failed: %w\n%s", err, out)
	}

	// Find free port
	port := findFreePort()
	outboxDir := filepath.Join(dataDir, "email-outbox")
	if err := os.MkdirAll(outboxDir, 0o755); err != nil {
		return nil, nil, fmt.Errorf("failed to create mock email outbox dir: %w", err)
	}

	// Start server
	logs := newLogCapture()
	outbox := newEmailOutbox(outboxDir)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, "--test")
	cmd.Dir = dataDir
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("LISTEN_ADDR=:%d", port),
		fmt.Sprintf("DATABASE_PATH=%s", dataDir),
		fmt.Sprintf("TEMPLATES_DIR=%s", filepath.Join(projectRoot, "web/templates")),
		fmt.Sprintf("MASTER_KEY=%s", testMasterKey),
		fmt.Sprintf("OAUTH_HMAC_SECRET=%s", testOAuthHMACKey),
		fmt.Sprintf("OAUTH_SIGNING_KEY=%s", testOAuthSignKey),
		fmt.Sprintf("MOCK_EMAIL_OUTBOX_DIR=%s", outboxDir),
	)

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, nil, fmt.Errorf("failed to start server: %w", err)
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

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	waitCtx, cancelWait := waitContext(t)
	defer cancelWait()
	readyCursor := logs.Cursor()
	if err := logs.waitForSubstringSince(waitCtx, "Server ready to accept connections", readyCursor); err != nil {
		cancel()
		_ = stopProcess(cmd)
		return nil, nil, fmt.Errorf("%w. logs:\n%s", err, strings.Join(logs.Lines(), "\n"))
	}
	t.Logf("Server started on port %d", port)

	fixture := &serverFixture{
		cmd:     cmd,
		baseURL: baseURL,
		port:    port,
		logs:    logs,
		outbox:  outbox,
		dataDir: dataDir,
	}

	cleanup := func() {
		cancel()
		_ = stopProcess(cmd)
		_ = os.RemoveAll(dataDir)
	}

	return fixture, cleanup, nil
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

func waitContext(t testing.TB) (context.Context, context.CancelFunc) {
	if tbWithDeadline, ok := any(t).(interface{ Deadline() (time.Time, bool) }); ok {
		if deadline, ok := tbWithDeadline.Deadline(); ok {
			return context.WithDeadline(context.Background(), deadline)
		}
	}
	return context.WithCancel(context.Background())
}

func stopProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	_ = cmd.Process.Signal(syscall.SIGTERM)
	return <-done
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
	waitCtx, cancelWait := waitContext(t)
	defer cancelWait()

	rapid.Check(t, func(rt *rapid.T) {
		email := genValidEmail().Draw(rt, "email")
		client := newClient(srv.baseURL)
		emailCursor := srv.outbox.Cursor()

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

		// Extract from outbox (mock still logs for humans).
		link, template, err := srv.outbox.WaitForEmailSince(email, emailCursor, waitCtx, srv.logs)
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
	waitCtx, cancelWait := waitContext(t)
	defer cancelWait()

	rapid.Check(t, func(rt *rapid.T) {
		email := genEdgeCaseEmail().Draw(rt, "email")
		client := newClient(srv.baseURL)
		emailCursor := srv.outbox.Cursor()

		resp, _ := client.PostForm(srv.baseURL+"/auth/magic", url.Values{"email": {email}})
		if resp != nil {
			resp.Body.Close()
		}

		link, _, err := srv.outbox.WaitForEmailSince(email, emailCursor, waitCtx, srv.logs)
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
	waitCtx, cancelWait := waitContext(t)
	defer cancelWait()

	rapid.Check(t, func(rt *rapid.T) {
		email := genValidEmail().Draw(rt, "email")
		client := newClient(srv.baseURL)
		emailCursor := srv.outbox.Cursor()

		// 1. Request magic link
		resp, _ := client.PostForm(srv.baseURL+"/auth/magic", url.Values{"email": {email}})
		if resp != nil {
			resp.Body.Close()
		}

		// 2. Get link from outbox
		link, _, err := srv.outbox.WaitForEmailSince(email, emailCursor, waitCtx, srv.logs)
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
	waitCtx, cancelWait := waitContext(t)
	defer cancelWait()

	// Auth once for all iterations
	client := newClient(srv.baseURL)
	authEmail := "jsontest-" + fmt.Sprintf("%d", time.Now().UnixNano()) + "@example.com"
	authCursor := srv.outbox.Cursor()

	resp, _ := client.PostForm(srv.baseURL+"/auth/magic", url.Values{"email": {authEmail}})
	if resp != nil {
		resp.Body.Close()
	}
	link, _, _ := srv.outbox.WaitForEmailSince(authEmail, authCursor, waitCtx, srv.logs)
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
	pages := []string{"/notes", "/notes/new", "/settings/api-keys"}
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
	waitCtx, cancelWait := waitContext(t)
	defer cancelWait()

	rapid.Check(t, func(rt *rapid.T) {
		email := genValidEmail().Draw(rt, "email")
		password := "TestPass123!"
		newPassword := "NewSecure456!"
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
		emailCursor := srv.outbox.Cursor()
		resp, _ = client.PostForm(srv.baseURL+"/auth/password-reset", url.Values{"email": {email}})
		if resp != nil {
			resp.Body.Close()
		}

		// Check outbox for reset email
		link, template, err := srv.outbox.WaitForEmailSince(email, emailCursor, waitCtx, srv.logs)
		if err != nil {
			rt.Fatalf("Password reset email not found: %v", err)
		}
		if template != "password_reset" {
			rt.Fatalf("Expected password_reset template, got %s", template)
		}
		if !strings.Contains(link, "password-reset") {
			rt.Fatalf("Link should contain password-reset: %s", link)
		}

		// Extract token from link and confirm reset
		parsedLink, err := url.Parse(link)
		if err != nil {
			rt.Fatalf("Failed to parse reset link: %v", err)
		}
		token := parsedLink.Query().Get("token")
		if token == "" {
			rt.Fatalf("Reset link should contain token")
		}

		// Confirm password reset
		confirmResp, err := client.PostForm(srv.baseURL+"/auth/password-reset-confirm", url.Values{
			"token":            {token},
			"password":         {newPassword},
			"confirm_password": {newPassword},
		})
		if err != nil {
			rt.Fatalf("Password reset confirm failed: %v", err)
		}
		confirmResp.Body.Close()

		// Login with NEW password should succeed (303 to /notes)
		freshClient := newClient(srv.baseURL)
		newPwResp, err := freshClient.PostForm(srv.baseURL+"/auth/login", url.Values{
			"email":    {email},
			"password": {newPassword},
		})
		if err != nil {
			rt.Fatalf("Login with new password failed: %v", err)
		}
		newPwResp.Body.Close()
		if newPwResp.StatusCode != http.StatusSeeOther {
			rt.Fatalf("Login with new password should 303, got %d", newPwResp.StatusCode)
		}
		newPwLoc := newPwResp.Header.Get("Location")
		if !strings.Contains(newPwLoc, "/notes") {
			rt.Fatalf("Login with new password should redirect to /notes, got: %s", newPwLoc)
		}

		// Login with OLD password should fail (303 to /login?error=...)
		oldClient := newClient(srv.baseURL)
		oldResp, err := oldClient.PostForm(srv.baseURL+"/auth/login", url.Values{
			"email":    {email},
			"password": {password},
		})
		if err != nil {
			rt.Fatalf("Login with old password request failed: %v", err)
		}
		oldResp.Body.Close()
		if oldResp.StatusCode != http.StatusSeeOther {
			rt.Fatalf("Login with old password should redirect (303), got %d", oldResp.StatusCode)
		}
		oldLoc := oldResp.Header.Get("Location")
		if !strings.Contains(oldLoc, "error") {
			rt.Fatalf("Login with old password should redirect with error, got: %s", oldLoc)
		}
	})
}
