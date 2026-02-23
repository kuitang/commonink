package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func TestParseAuthorizeRequest_MissingParams(t *testing.T) {
	t.Parallel()
	handler := &Handler{}
	required := []string{
		"client_id",
		"redirect_uri",
		"response_type",
		"state",
		"code_challenge",
		"code_challenge_method",
	}

	for _, missing := range required {
		t.Run(missing, func(t *testing.T) {
			values := url.Values{
				"client_id":             {"client"},
				"redirect_uri":          {"https://client.example/callback"},
				"response_type":         {"code"},
				"state":                 {"state-1"},
				"code_challenge":        {"challenge"},
				"code_challenge_method": {"S256"},
			}
			values.Del(missing)

			req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+values.Encode(), nil)
			_, err := handler.parseAuthorizeRequest(req)
			if err == nil {
				t.Fatalf("expected parse error when %q is missing", missing)
			}
			if !strings.Contains(err.Error(), missing) {
				t.Fatalf("expected error mentioning %q, got %v", missing, err)
			}
		})
	}
}

func testVerifyPKCE_RoundTripS256(t *rapid.T) {
	verifier := rapid.StringMatching(`[A-Za-z0-9._~\-]{43,96}`).Draw(t, "code_verifier")
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	if !verifyPKCE(verifier, challenge) {
		t.Fatalf("verifyPKCE should pass for matching verifier/challenge")
	}
	if verifyPKCE(verifier+"x", challenge) {
		t.Fatalf("verifyPKCE should fail for mismatched verifier")
	}
}

func TestVerifyPKCE_RoundTripS256(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testVerifyPKCE_RoundTripS256)
}

func TestWriteTokenError_JSONShapeAndHeaders(t *testing.T) {
	t.Parallel()
	handler := &Handler{}
	resp := httptest.NewRecorder()

	handler.writeTokenError(resp, http.StatusBadRequest, "invalid_request", "grant_type is required")

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("status mismatch: got=%d want=%d", resp.Code, http.StatusBadRequest)
	}
	if ct := resp.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("content type mismatch: %q", ct)
	}
	if cache := resp.Header().Get("Cache-Control"); cache != "no-store" {
		t.Fatalf("cache control mismatch: %q", cache)
	}
	if pragma := resp.Header().Get("Pragma"); pragma != "no-cache" {
		t.Fatalf("pragma mismatch: %q", pragma)
	}

	var payload TokenErrorResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal token error payload failed: %v", err)
	}
	if payload.Error != "invalid_request" || payload.ErrorDescription != "grant_type is required" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestRedirectWithError_AppendsOAuthErrorQuery(t *testing.T) {
	t.Parallel()
	handler := &Handler{}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
	resp := httptest.NewRecorder()

	handler.redirectWithError(
		resp,
		req,
		"https://client.example/callback?foo=bar",
		"state-123",
		"invalid_request",
		"missing code_challenge",
	)

	if resp.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", resp.Code)
	}
	location := resp.Header().Get("Location")
	if location == "" {
		t.Fatal("missing redirect Location header")
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect location failed: %v", err)
	}
	q := parsed.Query()
	if q.Get("foo") != "bar" {
		t.Fatalf("expected original query parameter to survive, got %q", location)
	}
	if q.Get("error") != "invalid_request" {
		t.Fatalf("error query mismatch: %q", q.Get("error"))
	}
	if q.Get("error_description") != "missing code_challenge" {
		t.Fatalf("error_description mismatch: %q", q.Get("error_description"))
	}
	if q.Get("state") != "state-123" {
		t.Fatalf("state mismatch: %q", q.Get("state"))
	}
}

func TestBuildScopeList_DefaultAndUnknownDescriptions(t *testing.T) {
	t.Parallel()
	empty := buildScopeList("")
	if len(empty) == 0 {
		t.Fatal("expected default scopes for empty input")
	}

	custom := buildScopeList("notes:read unknown:scope")
	if len(custom) != 2 {
		t.Fatalf("unexpected scope count: got=%d want=2", len(custom))
	}
	if custom[0].Name != "notes:read" {
		t.Fatalf("unexpected first scope: %+v", custom[0])
	}
	if custom[1].Name != "unknown:scope" || custom[1].Description != "unknown:scope" {
		t.Fatalf("unknown scope description should fall back to name: %+v", custom[1])
	}
}

func TestMergeScopes_DeduplicatesAndKeepsAllMembers(t *testing.T) {
	t.Parallel()
	merged := mergeScopes(
		[]string{"notes:read", "notes:write"},
		[]string{"notes:write", "notes:admin"},
	)

	got := map[string]bool{}
	for _, scope := range merged {
		got[scope] = true
	}
	for _, expected := range []string{"notes:read", "notes:write", "notes:admin"} {
		if !got[expected] {
			t.Fatalf("missing merged scope %q in %#v", expected, merged)
		}
	}
}

func TestRedirectWithError_InvalidRedirectFallsBackTo400(t *testing.T) {
	t.Parallel()
	handler := &Handler{}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
	resp := httptest.NewRecorder()

	handler.redirectWithError(resp, req, "://bad-uri", "state", "invalid_request", "bad redirect")
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when redirect URI is invalid, got %d", resp.Code)
	}
}
