package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func testFormatMCPHeadersForLog_RedactsSensitiveHeaders(t *rapid.T) {
	token := rapid.StringMatching(`[A-Za-z0-9._=-]{10,40}`).Draw(t, "token")

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)
	headers.Set("Cookie", "session="+token)
	headers.Set("X-OpenAI-Session", "sess-123")
	headers.Set("Content-Type", "application/json")

	formatted := formatMCPHeadersForLog(headers)
	lower := strings.ToLower(formatted)
	if strings.Contains(formatted, token) {
		t.Fatalf("sensitive token leaked in header log: %q", formatted)
	}
	for _, key := range []string{"authorization", "cookie", "x-openai-session", "content-type"} {
		if !strings.Contains(lower, key) {
			t.Fatalf("expected key %q in formatted headers: %q", key, formatted)
		}
	}
	if !strings.Contains(formatted, "[REDACTED]") {
		t.Fatalf("expected redaction marker in header log: %q", formatted)
	}
}

func TestFormatMCPHeadersForLog_RedactsSensitiveHeaders(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testFormatMCPHeadersForLog_RedactsSensitiveHeaders)
}

func testIsASCII_RejectsControlsAndWhitespaceOnly(t *rapid.T) {
	printable := rapid.StringMatching(`[A-Za-z0-9._:-]{1,64}`).Draw(t, "printable")
	if !isASCII(printable) {
		t.Fatalf("expected printable ASCII to pass, got %q", printable)
	}

	bad := rapid.SampledFrom([]string{
		"",
		"   ",
		"abc\tdef",
		"abc\n",
		"ümlaut",
	}).Draw(t, "bad")
	if isASCII(bad) {
		t.Fatalf("expected non-ASCII/control value to fail, got %q", bad)
	}
}

func TestIsASCII_RejectsControlsAndWhitespaceOnly(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testIsASCII_RejectsControlsAndWhitespaceOnly)
}

func TestServeHTTP_RequestBodyTooLargeReturns413(t *testing.T) {
	t.Parallel()
	server := &Server{
		httpHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("delegate should not be called when request is oversized")
		}),
	}

	oversized := strings.Repeat("a", maxMCPBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(oversized))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp := httptest.NewRecorder()

	server.ServeHTTP(resp, req)

	if resp.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized request, got %d body=%q", resp.Code, resp.Body.String())
	}
}

func TestServeHTTP_GETReturns405WithAllowHeader(t *testing.T) {
	t.Parallel()
	server := &Server{
		httpHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("delegate should not be called for GET")
		}),
	}

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	resp := httptest.NewRecorder()

	server.ServeHTTP(resp, req)

	if resp.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d body=%q", resp.Code, resp.Body.String())
	}
	allow := resp.Header().Get("Allow")
	if !strings.Contains(allow, "POST") || !strings.Contains(allow, "DELETE") {
		t.Fatalf("unexpected Allow header: %q", allow)
	}
}
