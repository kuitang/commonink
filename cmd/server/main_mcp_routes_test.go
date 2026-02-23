package main

import (
	"net/http"
	"net/http/httptest"
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
