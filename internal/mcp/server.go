package mcp

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Server wraps a pre-built MCP server that is created once per toolset at
// startup. Per-request notes/apps services are injected via context values
// (see WithNotesSvc / WithAppsSvc) before dispatching to the underlying
// StreamableHTTPHandler.
type Server struct {
	mcpServer   *mcp.Server
	handler     *Handler
	httpHandler http.Handler
	registry    *mcpSessionRegistry
}

const (
	mcpDebugBodyLogLimitBytes = 8 * 1024

	// MaxSessionIDLength is the maximum allowed length for an Mcp-Session-Id
	// header value. Values exceeding this limit are rejected with 400.
	MaxSessionIDLength = 256

	// sessionSweepInterval is how often the background goroutine checks for
	// expired session entries.
	sessionSweepInterval = 5 * time.Minute

	// sessionMaxAge is how long an idle session entry is kept before the
	// sweeper removes it.
	sessionMaxAge = 30 * time.Minute
)

// mcpSessionEntry tracks a single remembered MCP session.
type mcpSessionEntry struct {
	id       string
	lastSeen time.Time
}

// mcpSessionRegistry provides application-level tracking of MCP session IDs
// that have been observed through the handler. A background goroutine sweeps
// expired entries on a ticker.
type mcpSessionRegistry struct {
	mu       sync.Mutex
	sessions map[string]*mcpSessionEntry
	done     chan struct{} // closed to stop the sweeper
}

func newMCPSessionRegistry() *mcpSessionRegistry {
	r := &mcpSessionRegistry{
		sessions: make(map[string]*mcpSessionEntry),
		done:     make(chan struct{}),
	}
	go r.sweepLoop()
	return r
}

// rememberMCPSession records or refreshes a session ID. Returns false if the
// ID exceeds MaxSessionIDLength.
func (r *mcpSessionRegistry) rememberMCPSession(id string) bool {
	if len(id) > MaxSessionIDLength {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.sessions[id]
	if !ok {
		entry = &mcpSessionEntry{id: id}
		r.sessions[id] = entry
	}
	entry.lastSeen = time.Now()
	return true
}

// sweepLoop runs until Stop is called, removing sessions older than
// sessionMaxAge every sessionSweepInterval.
func (r *mcpSessionRegistry) sweepLoop() {
	ticker := time.NewTicker(sessionSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.done:
			return
		case now := <-ticker.C:
			r.sweep(now)
		}
	}
}

func (r *mcpSessionRegistry) sweep(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, entry := range r.sessions {
		if now.Sub(entry.lastSeen) > sessionMaxAge {
			delete(r.sessions, id)
		}
	}
}

// Stop terminates the background sweeper goroutine.
func (r *mcpSessionRegistry) Stop() {
	select {
	case <-r.done:
		// already stopped
	default:
		close(r.done)
	}
}

// Len returns the current number of tracked sessions (for testing).
func (r *mcpSessionRegistry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

// ---------------------------------------------------------------------------
// Response logging helpers
// ---------------------------------------------------------------------------

type mcpResponseLogger struct {
	http.ResponseWriter
	statusCode int
	body       []byte
	truncated  bool
}

func newMCPResponseLogger(w http.ResponseWriter) *mcpResponseLogger {
	return &mcpResponseLogger{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		body:           make([]byte, 0, mcpDebugBodyLogLimitBytes),
	}
}

func (w *mcpResponseLogger) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *mcpResponseLogger) Write(p []byte) (int, error) {
	if len(w.body) < mcpDebugBodyLogLimitBytes {
		remaining := mcpDebugBodyLogLimitBytes - len(w.body)
		if len(p) <= remaining {
			w.body = append(w.body, p...)
		} else {
			w.body = append(w.body, p[:remaining]...)
			w.truncated = true
		}
	} else {
		w.truncated = true
	}
	return w.ResponseWriter.Write(p)
}

func (w *mcpResponseLogger) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func mcpDebugEnabled() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv("DEBUG")))
	switch v {
	case "1", "true", "yes", "on", "debug":
		return true
	default:
		return false
	}
}

func formatBodyForLog(b []byte, truncated bool) string {
	if len(b) == 0 {
		return ""
	}
	textBytes := b
	if len(textBytes) > mcpDebugBodyLogLimitBytes {
		textBytes = textBytes[:mcpDebugBodyLogLimitBytes]
		truncated = true
	}
	text := string(textBytes)
	if truncated {
		return text + " [truncated]"
	}
	return text
}

// ---------------------------------------------------------------------------
// Server construction
// ---------------------------------------------------------------------------

// NewServer creates a new MCP server for the selected toolset.
// The server is safe to reuse across requests; per-request state (notes/apps
// services) is resolved from context inside tool handler closures.
//
// Call Stop() when the server is no longer needed to release the session
// registry sweeper goroutine.
func NewServer(toolset Toolset) *Server {
	handler := NewHandler()

	// Create MCP server with metadata
	mcpServer := mcp.NewServer(
		&mcp.Implementation{
			Name:    "remote-notes",
			Version: "1.0.0",
		},
		nil, // Use default options
	)

	// Register requested toolset
	tools := ToolDefinitions(toolset)
	for _, tool := range tools {
		toolCopy := tool // avoid closure issues
		mcp.AddTool(mcpServer, toolCopy, handler.createToolHandler(toolCopy.Name))
	}
	registerPrompts(mcpServer, toolset)

	registry := newMCPSessionRegistry()

	// Create Streamable HTTP handler (MCP Spec 2025-03-26)
	httpHandler := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server {
			// Return the same shared server for all requests.
			return mcpServer
		},
		&mcp.StreamableHTTPOptions{
			JSONResponse: true,
			Stateless:    true,
		},
	)

	log.Printf("MCP server built for toolset %q (%d tools registered)", toolset, len(tools))

	return &Server{
		mcpServer:   mcpServer,
		handler:     handler,
		httpHandler: httpHandler,
		registry:    registry,
	}
}

// Stop releases background resources (session sweeper).
func (s *Server) Stop() {
	if s.registry != nil {
		s.registry.Stop()
	}
}

// ServeHTTP implements http.Handler for Streamable HTTP transport.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers for all requests
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, Mcp-Session-Id, Last-Event-ID, Authorization")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")

	// Handle CORS preflight
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Max-Age", "86400")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Enforce max session ID length
	sessionID := r.Header.Get("Mcp-Session-Id")
	if len(sessionID) > MaxSessionIDLength {
		http.Error(w, "Mcp-Session-Id exceeds maximum length", http.StatusBadRequest)
		return
	}
	if sessionID != "" {
		if !s.registry.rememberMCPSession(sessionID) {
			http.Error(w, "Mcp-Session-Id exceeds maximum length", http.StatusBadRequest)
			return
		}
	}

	debug := mcpDebugEnabled()

	var reqBody []byte
	var reqBodyReadErr error
	if debug && r.Body != nil && r.Method == http.MethodPost {
		reqBody, reqBodyReadErr = io.ReadAll(r.Body)
		if reqBodyReadErr == nil {
			r.Body = io.NopCloser(bytes.NewReader(reqBody))
		}
	}

	reqLogPrefix := "MCP:"
	if debug {
		reqLogPrefix = "MCP[debug]:"
	}
	log.Printf("%s %s %s from %s (ua=%q content_type=%q accept=%q mcp_session_id=%q)", reqLogPrefix, r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent(), r.Header.Get("Content-Type"), r.Header.Get("Accept"), r.Header.Get("Mcp-Session-Id"))
	if reqBodyReadErr != nil {
		log.Printf("[ERROR] MCP request body read failed: method=%s path=%s err=%v", r.Method, r.URL.Path, reqBodyReadErr)
	}
	if debug && len(reqBody) > 0 {
		log.Printf("MCP[debug]: request body: %s", formatBodyForLog(reqBody, false))
	}

	respLogger := newMCPResponseLogger(w)
	s.httpHandler.ServeHTTP(respLogger, r)

	if debug {
		log.Printf("MCP[debug]: response status=%d method=%s path=%s content_type=%q", respLogger.statusCode, r.Method, r.URL.Path, respLogger.Header().Get("Content-Type"))
		if len(respLogger.body) > 0 {
			log.Printf("MCP[debug]: response body: %s", formatBodyForLog(respLogger.body, respLogger.truncated))
		}
	}

	if respLogger.statusCode >= http.StatusBadRequest {
		responseBody := formatBodyForLog(respLogger.body, respLogger.truncated)
		if responseBody != "" {
			log.Printf("[ERROR] MCP request failed: method=%s path=%s status=%d remote=%s response=%q", r.Method, r.URL.Path, respLogger.statusCode, r.RemoteAddr, responseBody)
		} else {
			log.Printf("[ERROR] MCP request failed: method=%s path=%s status=%d remote=%s", r.Method, r.URL.Path, respLogger.statusCode, r.RemoteAddr)
		}
	}
}

// Start is a helper to run the MCP server standalone (for testing)
func (s *Server) Start(addr string) error {
	http.Handle("/mcp", s)
	log.Printf("MCP server listening on %s/mcp (Streamable HTTP transport)", addr)
	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return server.ListenAndServe()
}
