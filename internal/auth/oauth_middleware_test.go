package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"pgregory.net/rapid"
)

func signAccessToken(t *testing.T, privateKey ed25519.PrivateKey, issuer, audience, subject, scope, clientID string, issuedAt, expiresAt time.Time) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: privateKey}, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	claims := struct {
		jwt.Claims
		Scope    string `json:"scope,omitempty"`
		ClientID string `json:"client_id,omitempty"`
	}{
		Claims: jwt.Claims{
			Issuer:   issuer,
			Subject:  subject,
			Audience: jwt.Audience{audience},
			IssuedAt: jwt.NewNumericDate(issuedAt),
			Expiry:   jwt.NewNumericDate(expiresAt),
		},
		Scope:    scope,
		ClientID: clientID,
	}

	token, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return token
}

func TestTokenVerifier_VerifyToken_SuccessAndClaims(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	verifier := NewTokenVerifier("issuer-test", "resource-test", publicKey)
	token := signAccessToken(
		t,
		privateKey,
		"issuer-test",
		"resource-test",
		"user-123",
		"notes:read notes:write",
		"client-abc",
		time.Now().Add(-time.Minute),
		time.Now().Add(10*time.Minute),
	)

	claims, err := verifier.VerifyToken(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyToken failed: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Fatalf("subject mismatch: got=%q", claims.Subject)
	}
	if claims.ClientID != "client-abc" {
		t.Fatalf("client_id mismatch: got=%q", claims.ClientID)
	}
	if !claims.HasScope("notes:read") || !claims.HasScope("notes:write") {
		t.Fatalf("scope parsing mismatch: got=%q", claims.Scope)
	}
}

func TestTokenVerifier_VerifyToken_RejectsExpired(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	verifier := NewTokenVerifier("issuer-test", "resource-test", publicKey)
	token := signAccessToken(
		t,
		privateKey,
		"issuer-test",
		"resource-test",
		"user-123",
		"notes:read",
		"client-abc",
		time.Now().Add(-2*time.Hour),
		time.Now().Add(-time.Hour),
	)

	_, err = verifier.VerifyToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected expired token error")
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func testExtractBearerToken_ParsingRules(t *rapid.T) {
	token := rapid.StringMatching(`[A-Za-z0-9._=-]{1,80}`).Draw(t, "token")
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	parsed, err := extractBearerToken(req)
	if err != nil {
		t.Fatalf("extractBearerToken failed: %v", err)
	}
	if parsed != token {
		t.Fatalf("token mismatch: got=%q want=%q", parsed, token)
	}

	reqBad := httptest.NewRequest(http.MethodGet, "/x", nil)
	reqBad.Header.Set("Authorization", "Basic abc")
	if _, err := extractBearerToken(reqBad); err == nil {
		t.Fatal("expected malformed token error for non-bearer scheme")
	}
}

func TestExtractBearerToken_ParsingRules(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testExtractBearerToken_ParsingRules)
}

func TestOAuthMiddleware_RequiredMissingTokenReturns401(t *testing.T) {
	t.Parallel()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	verifier := NewTokenVerifier("issuer-test", "resource-test", publicKey)

	nextCalled := false
	handler := OAuthMiddleware(verifier, "https://example.com/.well-known/oauth-protected-resource", true)(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			nextCalled = true
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if nextCalled {
		t.Fatal("next handler should not be called when token is required and missing")
	}
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.Code)
	}
	if !strings.Contains(resp.Header().Get("WWW-Authenticate"), "missing_token") {
		t.Fatalf("missing expected WWW-Authenticate error: %q", resp.Header().Get("WWW-Authenticate"))
	}
}

func TestOAuthMiddleware_OptionalMissingTokenPassesThrough(t *testing.T) {
	t.Parallel()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	verifier := NewTokenVerifier("issuer-test", "resource-test", publicKey)

	nextCalled := false
	handler := OAuthMiddleware(verifier, "https://example.com/.well-known/oauth-protected-resource", false)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusNoContent)
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if !nextCalled {
		t.Fatal("expected optional auth middleware to call next handler")
	}
	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected 204 from downstream, got %d", resp.Code)
	}
}

func TestRequireScope_EnforcesScope(t *testing.T) {
	t.Parallel()
	handler := RequireScope("notes:write", "https://example.com/.well-known/oauth-protected-resource")(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req = req.WithContext(context.WithValue(req.Context(), oauthScopeKey, "notes:read"))
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for insufficient scope, got %d", resp.Code)
	}
	if !strings.Contains(resp.Header().Get("WWW-Authenticate"), "insufficient_scope") {
		t.Fatalf("expected insufficient_scope challenge, got %q", resp.Header().Get("WWW-Authenticate"))
	}
}

func TestRequireScope_AllowsMatchingScope(t *testing.T) {
	t.Parallel()
	handler := RequireScope("notes:write", "https://example.com/.well-known/oauth-protected-resource")(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req = req.WithContext(context.WithValue(req.Context(), oauthScopeKey, "notes:read notes:write"))
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected 204 when scope is present, got %d", resp.Code)
	}
}
