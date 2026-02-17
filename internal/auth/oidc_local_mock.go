package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// LocalMockOIDCProvider is a self-contained OIDC mock for local development.
// Instead of redirecting to a dead URL, it serves a local consent page where
// the developer can enter an email to "sign in as". This makes "Sign in with
// Google" functional in --no-oidc / make run-test mode.
type LocalMockOIDCProvider struct {
	baseURL        string
	callbackOrigins map[string]string

	mu    sync.Mutex
	codes map[string]pendingCode // code -> pending auth info
}

type pendingCode struct {
	email     string
	createdAt time.Time
}

// NewLocalMockOIDCProvider creates a mock OIDC provider that serves local endpoints.
func NewLocalMockOIDCProvider(baseURL string) *LocalMockOIDCProvider {
	return &LocalMockOIDCProvider{
		baseURL:         strings.TrimRight(baseURL, "/"),
		callbackOrigins: make(map[string]string),
		codes:           make(map[string]pendingCode),
	}
}

// SetBaseURL updates the base URL. Used in test setups where the server URL
// isn't known at construction time.
func (p *LocalMockOIDCProvider) SetBaseURL(baseURL string) {
	p.baseURL = baseURL
}

// SetCallbackOrigin stores a request-specific origin for a given auth state.
// This is used by /auth/google/login to ensure callback redirects include the
// originating host for previews and local deployments.
func (p *LocalMockOIDCProvider) SetCallbackOrigin(state, origin string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.callbackOrigins[strings.TrimSpace(state)] = strings.TrimRight(strings.TrimSpace(origin), "/")
}

// GetAuthURL returns a URL to the local mock consent page.
func (p *LocalMockOIDCProvider) GetAuthURL(state, _ string) string {
	return fmt.Sprintf("%s/auth/mock-oidc/authorize?state=%s", p.baseURL, url.QueryEscape(state))
}

// ExchangeCode looks up a previously-issued code and returns mock claims.
func (p *LocalMockOIDCProvider) ExchangeCode(_ context.Context, code, _ string) (*Claims, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	pending, ok := p.codes[code]
	if !ok {
		return nil, ErrCodeExchangeFailed
	}
	delete(p.codes, code)

	// Reject expired codes (10 min)
	if time.Since(pending.createdAt) > 10*time.Minute {
		return nil, ErrCodeExchangeFailed
	}

	return &Claims{
		Sub:           "mock-" + pending.email,
		Email:         pending.email,
		Name:          "Test User",
		EmailVerified: true,
	}, nil
}

// RegisterRoutes registers the mock OIDC consent page and handler.
func (p *LocalMockOIDCProvider) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/mock-oidc/authorize", p.handleAuthorize)
	mux.HandleFunc("POST /auth/mock-oidc/authorize", p.handleConsent)
}

// handleAuthorize renders a simple consent form.
func (p *LocalMockOIDCProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "Missing state parameter", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Mock Google Sign-In</title>
<style>
body { font-family: system-ui; max-width: 400px; margin: 80px auto; padding: 0 20px; }
h1 { font-size: 1.3em; color: #333; }
.note { background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 12px; margin: 16px 0; font-size: 0.9em; }
input[type=email] { width: 100%%; padding: 10px; border: 1px solid #ccc; border-radius: 6px; font-size: 1em; box-sizing: border-box; }
button { width: 100%%; padding: 10px; background: #4285F4; color: white; border: none; border-radius: 6px; font-size: 1em; cursor: pointer; margin-top: 12px; }
button:hover { background: #3367D6; }
</style></head>
<body>
<h1>Mock Google Sign-In</h1>
<div class="note">This is a local mock. In production, this redirects to Google.</div>
<form method="POST" action="/auth/mock-oidc/authorize">
<input type="hidden" name="state" value="%s">
<label for="email">Sign in as:</label><br><br>
<input type="email" id="email" name="email" value="test@example.com" required autofocus>
<button type="submit">Sign In</button>
</form>
</body></html>`, state)
}

// handleConsent processes the consent form and redirects back with a code.
func (p *LocalMockOIDCProvider) handleConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	state := r.FormValue("state")
	email := r.FormValue("email")
	if state == "" || email == "" {
		http.Error(w, "Missing state or email", http.StatusBadRequest)
		return
	}

	// Generate a random authorization code
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	code := hex.EncodeToString(codeBytes)

	// Store the code
	p.mu.Lock()
	p.codes[code] = pendingCode{email: email, createdAt: time.Now()}
	p.mu.Unlock()

	callbackBase := p.popCallbackOrigin(state)
	if callbackBase == "" {
		callbackBase = r.Header.Get("X-Forwarded-Proto")
		if callbackBase == "" {
			if r.TLS != nil {
				callbackBase = "https"
			} else {
				callbackBase = "http"
			}
		}
		if strings.Contains(callbackBase, ",") {
			callbackBase = strings.TrimSpace(strings.Split(callbackBase, ",")[0])
		}
		callbackBase = strings.TrimSpace(callbackBase)
		if callbackBase != "http" && callbackBase != "https" {
			callbackBase = "http"
		}

		host := strings.TrimSpace(r.Host)
		if host != "" {
			callbackBase = callbackBase + "://" + host
		} else {
			callbackBase = strings.TrimRight(p.baseURL, "/")
		}
	}

	// Redirect back to the callback with code and state
	callbackURL := fmt.Sprintf("%s/auth/google/callback?code=%s&state=%s",
		strings.TrimRight(callbackBase, "/"), url.QueryEscape(code), url.QueryEscape(state))
	http.Redirect(w, r, callbackURL, http.StatusFound)
}

func (p *LocalMockOIDCProvider) popCallbackOrigin(state string) string {
	state = strings.TrimSpace(state)
	if state == "" {
		return ""
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	origin := strings.TrimRight(p.callbackOrigins[state], "/")
	delete(p.callbackOrigins, state)
	return origin
}
