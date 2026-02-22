package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func drawServiceName(t *rapid.T) string {
	return strings.TrimSpace(rapid.StringMatching(`[a-z][a-z0-9-]{0,20}`).Draw(t, "service_name"))
}

func TestFirstServiceName_JSONList_Properties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := drawServiceName(t)
		payload, err := json.Marshal([]map[string]string{
			{"name": ""},
			{"name": name},
			{"name": "ignored-after-first"},
		})
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		got := firstServiceName(string(payload))
		if got != name {
			t.Fatalf("expected %q, got %q (payload=%s)", name, got, string(payload))
		}
	})
}

func TestFirstServiceName_JSONObject_Properties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := drawServiceName(t)
		payload, err := json.Marshal(map[string]string{"name": name})
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		got := firstServiceName(string(payload))
		if got != name {
			t.Fatalf("expected %q, got %q (payload=%s)", name, got, string(payload))
		}
	})
}

func TestFirstServiceName_BracketAndColumnFormats_Properties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := drawServiceName(t)

		bracketOutput := fmt.Sprintf("[name:%s] [status:running]", name)
		gotBracket := firstServiceName(bracketOutput)
		if gotBracket != name {
			t.Fatalf("bracket format expected %q, got %q", name, gotBracket)
		}

		columnOutput := fmt.Sprintf("%s running healthy", name)
		gotColumn := firstServiceName(columnOutput)
		if gotColumn != name {
			t.Fatalf("column format expected %q, got %q", name, gotColumn)
		}
	})
}

func TestFirstServiceName_NoServiceSignal_Properties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := rapid.StringMatching(`[\t ]{0,8}`).Draw(t, "prefix")
		suffix := rapid.StringMatching(`[\t ]{0,8}`).Draw(t, "suffix")
		output := prefix + "no services registered" + suffix

		got := firstServiceName(output)
		if got != "" {
			t.Fatalf("expected empty service name, got %q (output=%q)", got, output)
		}
	})
}

type noFlushResponseWriter struct {
	header http.Header
	status int
}

func (w *noFlushResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *noFlushResponseWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (w *noFlushResponseWriter) WriteHeader(code int) {
	w.status = code
}

func TestNewStatusRecorder_PreservesFlusher(t *testing.T) {
	raw := httptest.NewRecorder()
	wrapped, recorder := newStatusRecorder(raw)

	if _, ok := wrapped.(http.Flusher); !ok {
		t.Fatal("expected wrapped response writer to expose http.Flusher")
	}

	wrapped.WriteHeader(http.StatusNoContent)
	if recorder.statusCode != http.StatusNoContent {
		t.Fatalf("expected recorded status %d, got %d", http.StatusNoContent, recorder.statusCode)
	}

	wrapped.(http.Flusher).Flush()
}

func TestNewStatusRecorder_DoesNotInventFlusher(t *testing.T) {
	raw := &noFlushResponseWriter{}
	wrapped, _ := newStatusRecorder(raw)

	if _, ok := wrapped.(http.Flusher); ok {
		t.Fatal("expected wrapped response writer to not expose http.Flusher")
	}
}
