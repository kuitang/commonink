package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "pgregory.net/rapid"
)

func TestServeHTTP_RecoversPanicWith500(t *testing.T) {
	t.Parallel()
	server := &Server{
		httpHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("simulated panic")
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"initialize","id":1}`))
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
	t.Parallel()
	server := &Server{
		httpHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			// Intentionally no response write to verify fallback behavior.
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"initialize","id":1}`))
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

func TestServeHTTP_NonInitializeMissingSessionIDAllowed(t *testing.T) {
	t.Parallel()
	called := false
	server := &Server{
		httpHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"tools/list","id":1}`))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	server.ServeHTTP(resp, req)

	if !called {
		t.Fatal("expected delegate handler to be called")
	}
	if resp.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%q", resp.Code, resp.Body.String())
	}
}

func TestServeHTTP_NonInitializeInvalidSessionIDReturns400(t *testing.T) {
	t.Parallel()
	server := &Server{
		httpHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("delegate handler should not be called")
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"tools/list","id":1}`))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Mcp-Session-Id", "bad\tvalue")
	resp := httptest.NewRecorder()

	server.ServeHTTP(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d body=%q", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "Invalid Mcp-Session-Id") {
		t.Fatalf("expected invalid session id message, got %q", resp.Body.String())
	}
}

func TestServeHTTP_InitializeAddsSessionIDHeader(t *testing.T) {
	t.Parallel()
	server := &Server{
		httpHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
		}),
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"initialize","id":1}`))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	server.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%q", resp.Code, resp.Body.String())
	}
	if strings.TrimSpace(resp.Header().Get("Mcp-Session-Id")) == "" {
		t.Fatalf("expected Mcp-Session-Id response header to be set")
	}
}
