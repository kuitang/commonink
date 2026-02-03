package mcp

import (
	"log"
	"net/http"
	"time"

	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Server wraps the MCP server with notes handling
type Server struct {
	mcpServer   *mcp.Server
	handler     *Handler
	httpHandler http.Handler
}

// NewServer creates a new MCP server for notes
func NewServer(notesSvc *notes.Service) *Server {
	handler := NewHandler(notesSvc)

	// Create MCP server with metadata
	mcpServer := mcp.NewServer(
		&mcp.Implementation{
			Name:    "remote-notes",
			Version: "1.0.0",
		},
		nil, // Use default options
	)

	// Register all tools
	tools := ToolDefinitions()
	for _, tool := range tools {
		toolCopy := tool // avoid closure issues
		mcp.AddTool(mcpServer, toolCopy, handler.createToolHandler(toolCopy.Name))
	}

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
			// via OAuth/PAT tokens. The server is created per-user per-request,
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

	log.Printf("MCP: %s request from %s", r.Method, r.RemoteAddr)

	// Delegate to the SDK's Streamable HTTP handler
	// The handler manages:
	// - POST: Client messages (JSON-RPC) - responds with JSON or SSE
	// - GET: Server-initiated messages (SSE stream)
	// - Session management (Mcp-Session-Id header)
	// - Stream resumption (Last-Event-ID header)
	s.httpHandler.ServeHTTP(w, r)
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
