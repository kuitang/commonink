package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kuitang/agent-notes/internal/apps"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Server wraps the MCP server with notes handling
type Server struct {
	mcpServer   *mcp.Server
	handler     *Handler
	httpHandler http.Handler
}

const (
	mcpDebugBodyLogLimitBytes = 8 * 1024
	mcpGetNotSupportedMessage = "GET not supported for SSE on this stateless MCP endpoint"
)

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

func isSensitiveLogField(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.ReplaceAll(key, "-", "")
	key = strings.ReplaceAll(key, "_", "")

	switch {
	case key == "authorization":
		return true
	case strings.Contains(key, "token"):
		return true
	case strings.Contains(key, "secret"):
		return true
	case strings.Contains(key, "password"):
		return true
	case strings.Contains(key, "apikey"):
		return true
	case strings.Contains(key, "cookie"):
		return true
	case strings.Contains(key, "auth"):
		return true
	default:
		return false
	}
}

func redactHeaderValue(key, value string) string {
	if isSensitiveLogField(key) {
		return "[REDACTED]"
	}
	return value
}

func formatHeadersForLog(headers http.Header) string {
	if len(headers) == 0 {
		return "{}"
	}

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		values := headers.Values(k)
		if len(values) == 0 {
			parts = append(parts, fmt.Sprintf("%s=<empty>", strings.ToLower(k)))
			continue
		}

		redacted := make([]string, len(values))
		for i, v := range values {
			redacted[i] = redactHeaderValue(k, v)
		}
		parts = append(parts, fmt.Sprintf("%s=%q", strings.ToLower(k), strings.Join(redacted, ", ")))
	}
	return strings.Join(parts, "; ")
}

func redactBodyForLog(contentType string, body []byte) string {
	text := string(body)
	if !strings.Contains(strings.ToLower(contentType), "json") {
		return text
	}

	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return text
	}

	var redact func(v any)
	redact = func(v any) {
		switch typed := v.(type) {
		case map[string]any:
			for k, child := range typed {
				if isSensitiveLogField(k) {
					typed[k] = "[REDACTED]"
					continue
				}
				redact(child)
			}
		case []any:
			for _, child := range typed {
				redact(child)
			}
		}
	}

	redact(payload)
	safeJSON, err := json.Marshal(payload)
	if err != nil {
		return text
	}
	return string(safeJSON)
}

func formatBodyForLog(contentType string, b []byte, truncated bool) string {
	if len(b) == 0 {
		return ""
	}
	textBytes := b
	if len(textBytes) > mcpDebugBodyLogLimitBytes {
		textBytes = textBytes[:mcpDebugBodyLogLimitBytes]
		truncated = true
	}
	text := redactBodyForLog(contentType, textBytes)
	if truncated {
		return text + " [truncated]"
	}
	return text
}

func logMCPResponse(r *http.Request, respLogger *mcpResponseLogger, debug bool) {
	contentType := respLogger.Header().Get("Content-Type")
	if debug {
		log.Printf("MCP[debug]: response status=%d method=%s path=%s content_type=%q", respLogger.statusCode, r.Method, r.URL.Path, contentType)
		log.Printf("MCP[debug]: response headers: %s", formatHeadersForLog(respLogger.Header()))
		if len(respLogger.body) > 0 {
			log.Printf("MCP[debug]: response body: %s", formatBodyForLog(contentType, respLogger.body, respLogger.truncated))
		}
	}

	isExpectedGet405 := r.Method == http.MethodGet && respLogger.statusCode == http.StatusMethodNotAllowed
	if isExpectedGet405 {
		log.Printf("MCP: GET stream probe rejected with 405 (stateless mode)")
		return
	}

	if respLogger.statusCode >= http.StatusBadRequest {
		responseBody := formatBodyForLog(contentType, respLogger.body, respLogger.truncated)
		if responseBody != "" {
			log.Printf("[ERROR] MCP request failed: method=%s path=%s status=%d remote=%s response=%q", r.Method, r.URL.Path, respLogger.statusCode, r.RemoteAddr, responseBody)
		} else {
			log.Printf("[ERROR] MCP request failed: method=%s path=%s status=%d remote=%s", r.Method, r.URL.Path, respLogger.statusCode, r.RemoteAddr)
		}
	}
}

// NewServer creates a new MCP server for the selected toolset.
func NewServer(notesSvc *notes.Service, appsSvc *apps.Service, toolset Toolset) *Server {
	handler := NewHandler(notesSvc, appsSvc)

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

	// Create Streamable HTTP handler (MCP Spec 2025-03-26)
	// This creates a single endpoint that handles both POST and GET requests
	// per the Streamable HTTP transport specification
	httpHandler := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server {
			// Return the same server for all requests
			// In future, could return different servers based on auth context
			return mcpServer
		},
		&mcp.StreamableHTTPOptions{
			// JSONResponse: true returns application/json responses
			// This is simpler for clients that don't support SSE streaming
			// Per MCP spec §2.1.5, JSON responses are valid for all operations
			JSONResponse: true,

			// Stateless: true because each request is authenticated independently
			// via OAuth/API Key tokens. The server is created per-user per-request,
			// so session state doesn't need to persist across requests.
			// With stateless mode, initialize/initialized handshake is skipped.
			Stateless: true,
		},
	)

	return &Server{
		mcpServer:   mcpServer,
		handler:     handler,
		httpHandler: httpHandler,
	}
}

// ServeHTTP implements http.Handler for Streamable HTTP transport
// Per MCP spec 2025-03-26: https://modelcontextprotocol.io/specification/2025-03-26/basic/transports
//
// The Streamable HTTP transport provides:
// - Single endpoint for all MCP communication
// - POST for client messages (JSON-RPC requests, notifications, responses)
// - GET for server-initiated messages (optional SSE stream)
// - Session management via Mcp-Session-Id header
// - Optional resumability via event IDs
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

	debug := mcpDebugEnabled()

	var reqBody []byte
	var reqBodyReadErr error
	if debug && r.Body != nil && (r.Method == http.MethodPost || r.Method == http.MethodDelete) {
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
	if debug {
		log.Printf("MCP[debug]: request headers: %s", formatHeadersForLog(r.Header))
	}
	if reqBodyReadErr != nil {
		log.Printf("[ERROR] MCP request body read failed: method=%s path=%s err=%v", r.Method, r.URL.Path, reqBodyReadErr)
	}
	if debug && len(reqBody) > 0 {
		log.Printf("MCP[debug]: request body: %s", formatBodyForLog(r.Header.Get("Content-Type"), reqBody, false))
	}

	respLogger := newMCPResponseLogger(w)

	// In stateless mode we intentionally do not offer GET/SSE streams.
	// Return a clean 405 rather than surfacing SDK session-specific wording.
	if r.Method == http.MethodGet {
		respLogger.Header().Set("Allow", "POST, DELETE, OPTIONS")
		http.Error(respLogger, mcpGetNotSupportedMessage, http.StatusMethodNotAllowed)
		logMCPResponse(r, respLogger, debug)
		return
	}

	// Delegate to the SDK's Streamable HTTP handler
	// The handler manages:
	// - POST: Client messages (JSON-RPC) - responds with JSON or SSE
	// - GET: Server-initiated messages (SSE stream)
	// - Session management (Mcp-Session-Id header)
	// - Stream resumption (Last-Event-ID header)
	s.httpHandler.ServeHTTP(respLogger, r)
	logMCPResponse(r, respLogger, debug)
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
