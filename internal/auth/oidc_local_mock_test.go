package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Test that mock OIDC callbacks use request-specific callback origins when provided.
func TestLocalMockOIDC_CallbackUsesConfiguredOrigin(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		provider := NewLocalMockOIDCProvider("https://fallback.local")

		state := rapid.StringMatching(`[a-zA-Z0-9_-]{16,24}`).Draw(rt, "state")
		host := rapid.StringMatching(`[a-z]{3,12}`).Draw(rt, "host") + ".example.test"
		callbackOrigin := "https://" + host
		provider.SetCallbackOrigin(state, callbackOrigin)

		body := strings.NewReader(url.Values{"state": {state}, "email": {"test@example.com"}}.Encode())
		req := httptest.NewRequest(http.MethodPost, "/auth/mock-oidc/authorize", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Host = "localhost:8080"
		req.Header.Set("X-Forwarded-Proto", "https")
		rr := httptest.NewRecorder()

		provider.handleConsent(rr, req)

		location := rr.Result().Header.Get("Location")
		if location == "" {
			rt.Fatal("expected redirect location")
		}
		parsed, err := url.Parse(location)
		if err != nil {
			rt.Fatalf("failed to parse callback location: %v", err)
		}
		if parsed.Scheme != "https" {
			rt.Fatalf("expected https callback scheme, got %s", parsed.Scheme)
		}
		if parsed.Host != host {
			rt.Fatalf("expected callback host %s, got %s", host, parsed.Host)
		}
		if parsed.Path != "/auth/google/callback" {
			rt.Fatalf("expected callback path /auth/google/callback, got %s", parsed.Path)
		}
		if parsed.Query().Get("state") != state {
			rt.Fatalf("expected callback state %s, got %s", state, parsed.Query().Get("state"))
		}
		if parsed.Query().Get("code") == "" {
			rt.Fatal("expected callback code query param")
		}
	})
}

// Test that, when no callback origin is set for a state, the provider falls back to request origin.
func TestLocalMockOIDC_CallbackFallsBackToRequestOrigin(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		provider := NewLocalMockOIDCProvider("https://fallback.local")

		state := rapid.StringMatching(`[a-zA-Z0-9_-]{16,24}`).Draw(rt, "state")
		host := rapid.StringMatching(`[a-z]{3,12}`).Draw(rt, "host") + ".fly.dev"
		schemeRaw := rapid.SampledFrom([]string{
			"https",
			"http",
			"https, http",
			"wss, https",
			"",
		}).Draw(rt, "scheme")

		body := strings.NewReader(url.Values{"state": {state}, "email": {"test@example.com"}}.Encode())
		req := httptest.NewRequest(http.MethodPost, "/auth/mock-oidc/authorize", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Host = host
		if schemeRaw != "" {
			req.Header.Set("X-Forwarded-Proto", schemeRaw)
		}
		rr := httptest.NewRecorder()

		provider.handleConsent(rr, req)

		location := rr.Result().Header.Get("Location")
		if location == "" {
			rt.Fatal("expected redirect location")
		}
		parsed, err := url.Parse(location)
		if err != nil {
			rt.Fatalf("failed to parse callback location: %v", err)
		}
		expectedScheme := "http"
		if first := strings.TrimSpace(strings.SplitN(schemeRaw, ",", 2)[0]); first != "" {
			if first == "http" || first == "https" {
				expectedScheme = first
			}
		}
		if parsed.Scheme != expectedScheme {
			rt.Fatalf("expected %s callback scheme, got %s", expectedScheme, parsed.Scheme)
		}
		if parsed.Host != host {
			rt.Fatalf("expected callback host %s, got %s", host, parsed.Host)
		}
		if parsed.Path != "/auth/google/callback" {
			rt.Fatalf("expected callback path /auth/google/callback, got %s", parsed.Path)
		}
		if parsed.Query().Get("state") != state {
			rt.Fatalf("expected callback state %s, got %s", state, parsed.Query().Get("state"))
		}
		if parsed.Query().Get("code") == "" {
			rt.Fatal("expected callback code query param")
		}
	})
}

// Test that callback-origin overrides are consumed once and not reused.
func TestLocalMockOIDC_CallbackOriginIsConsumedAfterUse(t *testing.T) {
	provider := NewLocalMockOIDCProvider("https://fallback.local")
	state := "state_once"
	hostA := "tenant-a.example.test"
	hostB := "tenant-b.example.test"

	provider.SetCallbackOrigin(state, "https://"+hostA)

	bodyA := strings.NewReader(url.Values{"state": {state}, "email": {"test@example.com"}}.Encode())
	reqA := httptest.NewRequest(http.MethodPost, "/auth/mock-oidc/authorize", bodyA)
	reqA.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqA.Header.Set("X-Forwarded-Proto", "https")
	reqA.Host = "fallback.local"
	rrA := httptest.NewRecorder()
	provider.handleConsent(rrA, reqA)

	locationA := rrA.Result().Header.Get("Location")
	if locationA == "" {
		t.Fatal("expected redirect location")
	}
	parsedA, err := url.Parse(locationA)
	if err != nil {
		t.Fatalf("failed to parse callback location: %v", err)
	}
	if parsedA.Host != hostA {
		t.Fatalf("expected first callback host %s, got %s", hostA, parsedA.Host)
	}

	bodyB := strings.NewReader(url.Values{"state": {state}, "email": {"test@example.com"}}.Encode())
	reqB := httptest.NewRequest(http.MethodPost, "/auth/mock-oidc/authorize", bodyB)
	reqB.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqB.Header.Set("X-Forwarded-Proto", "https")
	reqB.Host = hostB
	rrB := httptest.NewRecorder()
	provider.handleConsent(rrB, reqB)

	locationB := rrB.Result().Header.Get("Location")
	parsedB, err := url.Parse(locationB)
	if err != nil {
		t.Fatalf("failed to parse callback location: %v", err)
	}
	if parsedB.Host != hostB {
		t.Fatalf("expected fallback callback host %s, got %s", hostB, parsedB.Host)
	}
}
