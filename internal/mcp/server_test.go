package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "pgregory.net/rapid"
)

func TestServeHTTP_RecoversPanicWith500(t *testing.T) {
	server := &Server{
		httpHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("simulated panic")
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"tools/list","id":1}`))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	server.ServeHTTP(resp, req)

	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d body=%q", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "Internal server error") {
		t.Fatalf("expected internal error body, got %q", resp.Body.String())
	}
}

func TestServeHTTP_NoWriteFromDelegateReturns500(t *testing.T) {
	server := &Server{
		httpHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			// Intentionally no response write to verify fallback behavior.
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"tools/list","id":1}`))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	server.ServeHTTP(resp, req)

	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d body=%q", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "MCP handler returned without writing response") {
		t.Fatalf("expected no-response fallback body, got %q", resp.Body.String())
	}
}
