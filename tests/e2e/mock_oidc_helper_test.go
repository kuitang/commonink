package e2e

import (
	"io"
	"net/http"
	"net/url"
	"testing"
)

// testFataler is the minimal interface satisfied by both testing.TB and rapid.T.
type testFataler interface {
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

// doMockOIDCLogin performs the full LocalMockOIDCProvider login flow:
// POST /auth/google → GET consent form → POST consent → GET callback.
// The client MUST have CheckRedirect set to http.ErrUseLastResponse.
// Caller must call auth.SetSecureCookies(false) for plain HTTP test servers.
// Returns the session_id cookie value.
func doMockOIDCLogin(t testFataler, client *http.Client, baseURL, email string) string {
	if tb, ok := t.(testing.TB); ok {
		tb.Helper()
	}

	// Step 1: Start OAuth flow
	resp, err := client.Post(baseURL+"/auth/google", "", nil)
	if err != nil {
		t.Fatalf("doMockOIDCLogin: POST /auth/google failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("doMockOIDCLogin: expected 302 from /auth/google, got %d", resp.StatusCode)
	}

	authURL := resp.Header.Get("Location")
	if authURL == "" {
		t.Fatal("doMockOIDCLogin: no Location header from /auth/google")
	}

	// Make auth URL absolute if relative
	if parsed, err := url.Parse(authURL); err == nil && !parsed.IsAbs() {
		authURL = baseURL + authURL
	}

	// Extract state from auth URL
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("doMockOIDCLogin: failed to parse auth URL %q: %v", authURL, err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatal("doMockOIDCLogin: no state in auth URL")
	}

	// Step 2: GET consent form (verify it renders)
	consentResp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("doMockOIDCLogin: GET consent form failed: %v", err)
	}
	body, _ := io.ReadAll(consentResp.Body)
	consentResp.Body.Close()
	if consentResp.StatusCode != http.StatusOK {
		t.Fatalf("doMockOIDCLogin: expected 200 from consent form, got %d: %s", consentResp.StatusCode, string(body))
	}

	// Step 3: POST consent with email + state
	form := url.Values{"state": {state}, "email": {email}}
	consentPostResp, err := client.PostForm(baseURL+"/auth/mock-oidc/authorize", form)
	if err != nil {
		t.Fatalf("doMockOIDCLogin: POST consent failed: %v", err)
	}
	consentPostResp.Body.Close()
	if consentPostResp.StatusCode != http.StatusFound {
		t.Fatalf("doMockOIDCLogin: expected 302 from consent POST, got %d", consentPostResp.StatusCode)
	}

	callbackURL := consentPostResp.Header.Get("Location")
	if callbackURL == "" {
		t.Fatal("doMockOIDCLogin: no Location header from consent POST")
	}

	// Make callback URL absolute if relative
	if callbackParsed, err := url.Parse(callbackURL); err == nil && !callbackParsed.IsAbs() {
		callbackURL = baseURL + callbackURL
	}

	// Step 4: Follow callback redirect
	callbackResp, err := client.Get(callbackURL)
	if err != nil {
		t.Fatalf("doMockOIDCLogin: GET callback failed: %v", err)
	}
	callbackResp.Body.Close()
	if callbackResp.StatusCode != http.StatusFound {
		t.Fatalf("doMockOIDCLogin: expected 302 from callback, got %d", callbackResp.StatusCode)
	}

	// Extract session cookie from response
	for _, c := range callbackResp.Cookies() {
		if c.Name == "session_id" && c.Value != "" {
			return c.Value
		}
	}
	t.Fatal("doMockOIDCLogin: no session_id cookie set after callback")
	return ""
}

// startMockOIDCFlow initiates the OIDC flow and returns the auth URL and state.
// Useful for tests that need to test intermediate steps (error cases, etc.).
// The client MUST have CheckRedirect set to http.ErrUseLastResponse.
func startMockOIDCFlow(t testFataler, client *http.Client, baseURL string) (authURL, state string) {
	if tb, ok := t.(testing.TB); ok {
		tb.Helper()
	}

	resp, err := client.Get(baseURL + "/auth/google")
	if err != nil {
		t.Fatalf("startMockOIDCFlow: GET /auth/google failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("startMockOIDCFlow: expected 302, got %d", resp.StatusCode)
	}

	authURL = resp.Header.Get("Location")
	if authURL == "" {
		t.Fatal("startMockOIDCFlow: no Location header")
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("startMockOIDCFlow: failed to parse auth URL: %v", err)
	}
	state = parsed.Query().Get("state")
	if state == "" {
		t.Fatal("startMockOIDCFlow: no state in auth URL")
	}

	return authURL, state
}
