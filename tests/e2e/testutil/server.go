// Package testutil provides shared test infrastructure for e2e tests.
// Provides a subprocess-based server fixture that builds and runs the actual
// server binary, starts once via sync.Once, and supports cleanup in TestMain.
//
// Uses golang.org/x/oauth2 for OAuth flows to prove conformance with standard clients.
package testutil

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/hex"
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

	"golang.org/x/oauth2"
)

// =============================================================================
// Server Fixture: Subprocess-based server that starts once
// =============================================================================

var (
	testServer   *ServerFixture
	testOnce     sync.Once
	testCleanup  func()
	testStartErr error
	testMu       sync.Mutex
)

const (
	testMasterKey    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testOAuthHMACKey = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testOAuthSignKey = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

// ServerFixture holds the running server instance
type ServerFixture struct {
	cmd        *exec.Cmd
	BaseURL    string
	Port       int
	Logs       *LogCapture
	Outbox     *EmailOutbox
	DataDir    string
	ProjectDir string
	cancel     context.CancelFunc
}

// EmailOutbox reads mock-email files written by internal/email.MockEmailService.
type EmailOutbox struct {
	dir string
}

type outboxEmailEvent struct {
	Sequence uint64 `json:"sequence"`
	To       string `json:"to"`
	Template string `json:"template"`
	Link     string `json:"link"`
}

func NewEmailOutbox(dir string) *EmailOutbox {
	return &EmailOutbox{dir: dir}
}

func (o *EmailOutbox) Cursor() uint64 {
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

func (o *EmailOutbox) WaitForEmailSince(
	to string,
	startSeq uint64,
	ctx context.Context,
	logs *LogCapture,
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

func (o *EmailOutbox) findEmailSince(to string, startSeq uint64) (link, template string, next uint64, ok bool, err error) {
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

// LogCapture captures server logs for inspection
type LogCapture struct {
	mu     sync.Mutex
	lines  []string
	notify chan struct{}
}

func NewLogCapture() *LogCapture {
	return &LogCapture{
		lines:  make([]string, 0, 256),
		notify: make(chan struct{}),
	}
}

func (l *LogCapture) Write(p []byte) (int, error) {
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

// Lines returns a copy of all captured log lines
func (l *LogCapture) Lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := make([]string, len(l.lines))
	copy(cp, l.lines)
	return cp
}

// Cursor returns the current log index.
func (l *LogCapture) Cursor() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.lines)
}

func (l *LogCapture) waitCh() <-chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.notify
}

// FindEmail searches logs for an email sent to the given address
func (l *LogCapture) FindEmail(to string) (link string, template string, ok bool) {
	link, template, _, ok = l.FindEmailSince(to, 0)
	return link, template, ok
}

// FindEmailSince searches logs from a cursor and returns the next cursor.
func (l *LogCapture) FindEmailSince(to string, start int) (link string, template string, next int, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	toPattern := regexp.MustCompile(`\[EMAIL\] To: ` + regexp.QuoteMeta(to) + ` \| Template: (\w+)`)
	linkPattern := regexp.MustCompile(`\[EMAIL\] (?:Magic Link|Password Reset Link): (http[^\s]+)`)

	if start < 0 {
		start = 0
	}
	for i := start; i < len(l.lines); i++ {
		line := l.lines[i]
		if m := toPattern.FindStringSubmatch(line); m != nil {
			template = m[1]
			if i+1 < len(l.lines) {
				if lm := linkPattern.FindStringSubmatch(l.lines[i+1]); lm != nil {
					return lm[1], template, i + 2, true
				}
			}
		}
	}
	return "", "", len(l.lines), false
}

// WaitForEmail waits for an email to appear in logs
func (l *LogCapture) WaitForEmail(to string, timeout time.Duration) (link, template string, err error) {
	return l.WaitForEmailSince(to, 0, timeout)
}

// WaitForEmailSince waits for a matching email after the provided cursor.
func (l *LogCapture) WaitForEmailSince(to string, start int, timeout time.Duration) (link, template string, err error) {
	deadline := time.Now().Add(timeout)
	cursor := start
	for {
		var ok bool
		link, template, cursor, ok = l.FindEmailSince(to, cursor)
		if ok {
			return link, template, nil
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}

		waitCh := l.waitCh()
		timer := time.NewTimer(remaining)
		select {
		case <-waitCh:
			timer.Stop()
		case <-timer.C:
			return "", "", fmt.Errorf("timeout waiting for email to %s", to)
		}
	}
	return "", "", fmt.Errorf("timeout waiting for email to %s", to)
}

func (l *LogCapture) waitForSubstringSince(ctx context.Context, substr string, start int) error {
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

// GetServer returns the shared server fixture, starting it if needed.
// Uses sync.Once to ensure server is started only once across all tests.
func GetServer(t testing.TB) *ServerFixture {
	t.Helper()

	testMu.Lock()
	defer testMu.Unlock()

	testOnce.Do(func() {
		testServer, testCleanup, testStartErr = startServer(t)
	})
	if testStartErr != nil {
		t.Fatalf("Failed to start shared e2e server fixture: %v", testStartErr)
	}
	if testServer == nil {
		t.Fatalf("Shared e2e server fixture is nil")
	}
	return testServer
}

// Cleanup stops the server. Call from TestMain after m.Run().
func Cleanup() {
	testMu.Lock()
	defer testMu.Unlock()
	if testCleanup != nil {
		testCleanup()
		testCleanup = nil
	}
}

func startServer(t testing.TB) (*ServerFixture, func(), error) {
	projectRoot := FindProjectRoot()

	// Create temp data dir
	dataDir, err := os.MkdirTemp("", "e2e-test-*")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	// Build server with required CGO flags
	binary := filepath.Join(dataDir, "server")
	buildCmd := exec.Command("go", "build", "-tags", "fts5", "-o", binary, "./cmd/server")
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

	// Start server as subprocess
	logs := NewLogCapture()
	outbox := NewEmailOutbox(outboxDir)
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

	// Capture logs
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			logs.Write([]byte(line + "\n"))
			fmt.Println("[SERVER]", line)
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

	waitCtx, cancelWait := waitContext(t)
	defer cancelWait()
	readyCursor := logs.Cursor()
	if err := logs.waitForSubstringSince(waitCtx, "Server ready to accept connections", readyCursor); err != nil {
		cancel()
		_ = stopProcess(cmd)
		return nil, nil, fmt.Errorf("%w. logs:\n%s", err, strings.Join(logs.Lines(), "\n"))
	}

	t.Logf("Server started on port %d", port)

	fixture := &ServerFixture{
		cmd:        cmd,
		BaseURL:    baseURL,
		Port:       port,
		Logs:       logs,
		Outbox:     outbox,
		DataDir:    dataDir,
		ProjectDir: projectRoot,
		cancel:     cancel,
	}

	cleanup := func() {
		cancel()
		_ = stopProcess(cmd)
		_ = os.RemoveAll(dataDir)
	}

	return fixture, cleanup, nil
}

// FindProjectRoot locates the project root by finding go.mod
func FindProjectRoot() string {
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
// HTTP Client Helpers
// =============================================================================

// NewHTTPClient creates an HTTP client with cookie jar and no-redirect policy
func NewHTTPClient() *http.Client {
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
// OAuth Helpers using golang.org/x/oauth2
// =============================================================================

// OAuthCredentials holds OAuth client credentials and access token
type OAuthCredentials struct {
	ClientID    string
	AccessToken string
	UserID      string
}

// PerformOAuthFlow performs the full OAuth 2.1 + PKCE flow using golang.org/x/oauth2
// This proves our server is conformant with standard OAuth clients.
func PerformOAuthFlow(t testing.TB, baseURL string, clientName string) *OAuthCredentials {
	t.Helper()

	client := NewHTTPClient()
	redirectURI := "http://localhost:8080/callback"

	// Step 1: Dynamic Client Registration (DCR)
	// This is server-specific - not part of golang.org/x/oauth2
	clientID := registerOAuthClient(t, client, baseURL, clientName, redirectURI)

	// Step 2: Create user session via magic link
	// This is server-specific authentication
	testEmail := clientName + "-" + generateSecureRandom(8) + "@example.com"
	authenticateUser(t, client, baseURL, testEmail)

	// Step 3: Use golang.org/x/oauth2 for Authorization Code + PKCE flow
	// This proves our server is conformant with the standard OAuth2 client library
	oauthConfig := &oauth2.Config{
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:  baseURL + "/oauth/authorize",
			TokenURL: baseURL + "/oauth/token",
		},
		RedirectURL: redirectURI,
		Scopes:      []string{"notes:read", "notes:write"},
	}

	// Generate PKCE verifier using golang.org/x/oauth2
	verifier := oauth2.GenerateVerifier()
	state := generateSecureRandom(32)

	// Build authorization URL with PKCE
	authURL := oauthConfig.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))

	// Make authorization request (our client is pre-authenticated via magic link)
	authResp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("Authorization request failed: %v", err)
	}

	var authCode string
	t.Logf("[OAuth] Authorization response status: %d", authResp.StatusCode)
	if authResp.StatusCode == http.StatusFound {
		// Direct redirect with code
		location := authResp.Header.Get("Location")
		t.Logf("[OAuth] Direct redirect to: %s", location)
		authCode = extractCodeFromLocation(location)
		authResp.Body.Close()
	} else if authResp.StatusCode == http.StatusOK {
		// Consent page shown - submit consent
		body, _ := io.ReadAll(authResp.Body)
		authResp.Body.Close()
		t.Logf("[OAuth] Consent page shown, body length: %d", len(body))

		consentResp, err := client.PostForm(baseURL+"/oauth/consent", url.Values{"decision": {"allow"}})
		if err != nil {
			t.Fatalf("Consent submission failed: %v", err)
		}

		t.Logf("[OAuth] Consent response status: %d", consentResp.StatusCode)
		if consentResp.StatusCode == http.StatusFound {
			location := consentResp.Header.Get("Location")
			t.Logf("[OAuth] Consent redirect to: %s", location)
			authCode = extractCodeFromLocation(location)
		} else {
			body, _ := io.ReadAll(consentResp.Body)
			t.Logf("[OAuth] Consent response body: %s", string(body))
		}
		consentResp.Body.Close()
	} else {
		body, _ := io.ReadAll(authResp.Body)
		authResp.Body.Close()
		t.Fatalf("Unexpected auth response: %d - %s", authResp.StatusCode, string(body))
	}

	if authCode == "" {
		t.Fatal("Failed to get authorization code")
	}

	// Step 4: Exchange code for token using golang.org/x/oauth2
	// This proves our token endpoint is conformant
	ctx := context.Background()
	token, err := oauthConfig.Exchange(ctx, authCode, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatalf("Token exchange failed: %v", err)
	}

	t.Logf("[OAuth] Obtained access token via golang.org/x/oauth2 for %s", clientName)

	return &OAuthCredentials{
		ClientID:    clientID,
		AccessToken: token.AccessToken,
		UserID:      testEmail,
	}
}

// registerOAuthClient performs Dynamic Client Registration
func registerOAuthClient(t testing.TB, client *http.Client, baseURL, clientName, redirectURI string) string {
	t.Helper()

	dcrReq := map[string]interface{}{
		"client_name":                clientName,
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none", // Public client
	}
	dcrBody, _ := json.Marshal(dcrReq)
	dcrResp, err := client.Post(baseURL+"/oauth/register", "application/json", strings.NewReader(string(dcrBody)))
	if err != nil {
		t.Fatalf("DCR request failed: %v", err)
	}
	defer dcrResp.Body.Close()

	if dcrResp.StatusCode != http.StatusOK && dcrResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(dcrResp.Body)
		t.Fatalf("DCR failed with status %d: %s", dcrResp.StatusCode, string(body))
	}

	var dcrResult map[string]interface{}
	json.NewDecoder(dcrResp.Body).Decode(&dcrResult)
	return dcrResult["client_id"].(string)
}

// authenticateUser creates a user session via magic link
func authenticateUser(t testing.TB, client *http.Client, baseURL, email string) {
	t.Helper()

	srv := GetServer(t)
	emailCursor := srv.Outbox.Cursor()

	// Request magic link
	magicResp, err := client.PostForm(baseURL+"/auth/magic", url.Values{"email": {email}})
	if err != nil {
		t.Fatalf("Magic link request failed: %v", err)
	}
	magicResp.Body.Close()

	// Wait for magic link in outbox (still logged to stdout for humans).
	waitCtx, cancelWait := waitContext(t)
	defer cancelWait()
	link, _, err := srv.Outbox.WaitForEmailSince(email, emailCursor, waitCtx, srv.Logs)
	if err != nil {
		t.Fatalf("Failed to get magic link: %v", err)
	}

	// Visit magic link to authenticate
	// We need to follow redirects here to ensure the session is properly established
	// The session cookie is set during the redirect chain
	originalCheckRedirect := client.CheckRedirect
	client.CheckRedirect = nil // Allow following redirects
	authResp, err := client.Get(link)
	client.CheckRedirect = originalCheckRedirect // Restore original behavior
	if err != nil {
		t.Fatalf("Magic link visit failed: %v", err)
	}
	authResp.Body.Close()
}

func extractCodeFromLocation(location string) string {
	if strings.Contains(location, "code=") {
		parsed, _ := url.Parse(location)
		return parsed.Query().Get("code")
	}
	return ""
}

func generateSecureRandom(length int) string {
	bytes := make([]byte, length)
	crand.Read(bytes)
	return hex.EncodeToString(bytes)[:length]
}

// =============================================================================
// MCP Client Helpers
// =============================================================================

// MCPClient makes MCP JSON-RPC calls to the server
type MCPClient struct {
	BaseURL     string
	AccessToken string
	HTTPClient  *http.Client
	requestID   int
	initialized bool
	sessionID   string
}

// NewMCPClient creates an MCP client
func NewMCPClient(baseURL, accessToken string) *MCPClient {
	return &MCPClient{
		BaseURL:     baseURL,
		AccessToken: accessToken,
		HTTPClient:  &http.Client{Timeout: 30 * time.Second},
		requestID:   0,
	}
}

// MCPResponse represents a JSON-RPC response
type MCPResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *MCPError       `json:"error,omitempty"`
}

// MCPError represents a JSON-RPC error
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Call makes an MCP JSON-RPC call
func (c *MCPClient) Call(method string, params interface{}) (*MCPResponse, error) {
	c.requestID++

	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"id":      c.requestID,
	}
	if params != nil {
		reqBody["params"] = params
	}

	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", c.BaseURL+"/mcp", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("MCP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Capture session ID from response header
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.sessionID = sid
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("MCP returned %d: %s", resp.StatusCode, string(respBody))
	}

	var mcpResp MCPResponse
	if err := json.NewDecoder(resp.Body).Decode(&mcpResp); err != nil {
		return nil, fmt.Errorf("failed to decode MCP response: %w", err)
	}

	return &mcpResp, nil
}

// CallTool calls an MCP tool
// Note: With stateless MCP servers, no initialization is needed.
func (c *MCPClient) CallTool(name string, arguments map[string]interface{}) (*MCPResponse, error) {
	return c.Call("tools/call", map[string]interface{}{
		"name":      name,
		"arguments": arguments,
	})
}

// Initialize performs the MCP initialization handshake.
// Must be called before other MCP methods.
func (c *MCPClient) Initialize() error {
	if c.initialized {
		return nil
	}

	// Step 1: Send initialize request
	initParams := map[string]interface{}{
		"protocolVersion": "2025-03-26",
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]interface{}{
			"name":    "test-client",
			"version": "1.0.0",
		},
	}

	resp, err := c.Call("initialize", initParams)
	if err != nil {
		return fmt.Errorf("initialize failed: %w", err)
	}
	if resp.Error != nil {
		return fmt.Errorf("initialize error: %s", resp.Error.Message)
	}

	// Step 2: Send initialized notification
	// Notifications have no id and expect no response
	c.requestID++
	notifBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	body, _ := json.Marshal(notifBody)

	req, _ := http.NewRequest("POST", c.BaseURL+"/mcp", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}

	notifResp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("initialized notification failed: %w", err)
	}
	notifResp.Body.Close()

	c.initialized = true
	return nil
}

// ListTools lists available MCP tools
// Note: With stateless MCP servers, no initialization is needed.
func (c *MCPClient) ListTools() (*MCPResponse, error) {
	return c.Call("tools/list", nil)
}

// =============================================================================
// Note Helpers (parsed from MCP responses)
// =============================================================================

// Note represents a note from MCP responses
type Note struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

// NoteListResult represents the result of listing notes
type NoteListResult struct {
	Notes []Note `json:"notes"`
	Total int    `json:"total"`
}

// ParseToolResult extracts the content from an MCP tool result
func ParseToolResult(resp *MCPResponse) (string, error) {
	if resp.Error != nil {
		return "", fmt.Errorf("MCP error: %s", resp.Error.Message)
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return "", fmt.Errorf("failed to parse tool result: %w", err)
	}

	for _, c := range result.Content {
		if c.Type == "text" {
			return c.Text, nil
		}
	}
	return "", nil
}
