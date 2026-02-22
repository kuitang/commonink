package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMountMCPRoute_RegistersStreamableMethods(t *testing.T) {
	mux := http.NewServeMux()
	callCount := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusNoContent)
	})

	mountMCPRoute(mux, "/mcp", handler)

	methods := []string{http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodOptions}
	for _, method := range methods {
		req := httptest.NewRequest(method, "/mcp", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected %s /mcp to reach handler with 204, got %d", method, rec.Code)
		}
	}

	if callCount != len(methods) {
		t.Fatalf("expected handler call count %d, got %d", len(methods), callCount)
	}
}

func TestMCPRouteGuard_RecoversPanicWith500(t *testing.T) {
	handler := mcpRouteGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("simulated panic")
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Internal server error") {
		t.Fatalf("expected internal error body, got %q", rec.Body.String())
	}
}

func TestMCPRouteGuard_NoWriteReturns500ForPost(t *testing.T) {
	handler := mcpRouteGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		// Intentionally write nothing to verify fallback behavior.
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "MCP route returned without writing response") {
		t.Fatalf("expected no-response fallback body, got %q", rec.Body.String())
	}
}
