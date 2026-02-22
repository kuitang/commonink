package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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

func TestNewHTTPServer_HasNoRequestTimeoutsForLongLivedConnections(t *testing.T) {
	server := newHTTPServer("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	if server.ReadTimeout != 0 {
		t.Fatalf("expected ReadTimeout to be 0, got %s", server.ReadTimeout)
	}

	if server.WriteTimeout != 0 {
		t.Fatalf("expected WriteTimeout to be 0, got %s", server.WriteTimeout)
	}

	if server.IdleTimeout != 0 {
		t.Fatalf("expected IdleTimeout to be 0, got %s", server.IdleTimeout)
	}

	if server.ReadHeaderTimeout != HTTPReadHeaderTimeout {
		t.Fatalf("expected ReadHeaderTimeout=%s, got %s", HTTPReadHeaderTimeout, server.ReadHeaderTimeout)
	}

	if server.ConnContext == nil {
		t.Fatal("expected ConnContext to be set")
	}

	if server.ConnState == nil {
		t.Fatal("expected ConnState to be set")
	}
}

func TestConnectionIDForConn_IsStableAndUniqueForDifferentConns(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	first := connectionIDForConn(clientConn)
	second := connectionIDForConn(clientConn)
	if first != second {
		t.Fatalf("expected stable connection ID for same conn, got %q and %q", first, second)
	}

	other := connectionIDForConn(serverConn)
	if first == other {
		t.Fatalf("expected unique connection IDs for different conns, got same id %q", first)
	}
}

func TestConnectionIDFromContext(t *testing.T) {
	t.Run("MissingContext", func(t *testing.T) {
		if got := connectionIDFromContext(context.Background()); got != "unknown" {
			t.Fatalf("expected missing context connection id to be unknown, got %q", got)
		}
	})

	t.Run("SetContext", func(t *testing.T) {
		const expected = "conn-test-1"
		ctx := context.WithValue(context.Background(), connIDContextKey{}, expected)
		if got := connectionIDFromContext(ctx); got != expected {
			t.Fatalf("expected connection id %q, got %q", expected, got)
		}
	})
}

func TestRequestLogging_IncludesConnectionIDFor405OnMCP(t *testing.T) {
	var logs bytes.Buffer
	origOutput := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(origOutput)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := newHTTPServer("127.0.0.1:0", withRequestLogging(mux))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind listener: %v", err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Serve(listener)
	}()

	client := &http.Client{}
	resp, err := client.Get("http://" + listener.Addr().String() + "/mcp")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, resp.StatusCode)
	}

	if err := server.Shutdown(context.Background()); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("server shutdown failed: %v", err)
	}

	if err := <-serverErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("server exited with error: %v", err)
	}

	logOutput := logs.String()
	line := "conn=unknown"
	if strings.Contains(logOutput, line) {
		t.Fatalf("expected request log to include real connection id, got: %q", logOutput)
	}
	if !strings.Contains(logOutput, "[REQ]") {
		t.Fatalf("expected request log marker [REQ], got: %q", logOutput)
	}
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
