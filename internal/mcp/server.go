package mcp

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"os"
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

	// Delegate to the SDK's Streamable HTTP handler
	// The handler manages:
	// - POST: Client messages (JSON-RPC) - responds with JSON or SSE
	// - GET: Server-initiated messages (SSE stream)
	// - Session management (Mcp-Session-Id header)
	// - Stream resumption (Last-Event-ID header)
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
