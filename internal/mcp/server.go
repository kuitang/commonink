package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kuitang/agent-notes/internal/obs"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Server wraps the MCP server with notes handling.
type Server struct {
	mcpServer   *mcp.Server
	handler     *Handler
	httpHandler http.Handler
}

const (
	maxMCPBodyBytes           = 1_000_000
	mcpGetNotSupportedMessage = "GET not supported for SSE on this stateless MCP endpoint"
	mcpSessionTTL             = 24 * time.Hour
	maxMCPSessionIDLength     = 256
)

var mcpSessionRegistry sync.Map

type rpcEnvelope struct {
	Method string          `json:"method"`
	ID     json.RawMessage `json:"id,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	Meta      json.RawMessage `json:"_meta,omitempty"`
}

// NewServer creates a new MCP server for the selected toolset.
// Services are NOT passed here -- they are injected per-request via ContextWithServices.
// Tool handlers pull services from context, so the Server instance is reusable across requests.
func NewServer(toolset Toolset) *Server {
	handler := NewHandler()

	mcpServer := mcp.NewServer(
		&mcp.Implementation{
			Name:    "remote-notes",
			Version: "1.0.0",
		},
		nil,
	)

	tools := ToolDefinitions(toolset)
	for _, tool := range tools {
		toolCopy := tool
		mcp.AddTool(mcpServer, toolCopy, handler.createToolHandler(toolCopy.Name))
	}
	registerPrompts(mcpServer, toolset)

	httpHandler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server {
			return mcpServer
		},
		&mcp.StreamableHTTPOptions{
			JSONResponse: true,
			Stateless:    true,
		},
	)

	return &Server{
		mcpServer:   mcpServer,
		handler:     handler,
		httpHandler: httpHandler,
	}
}

// ServeHTTP implements http.Handler for Streamable HTTP transport.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	baseLogger := obs.From(r.Context()).With("pkg", "internal/mcp")

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, Mcp-Session-Id, Last-Event-ID, Authorization")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Max-Age", "86400")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	baseLogger.Debug(
		"mcp_headers",
		"path", r.URL.Path,
		"method", r.Method,
		"headers", formatMCPHeadersForLog(r.Header),
	)

	wrapped, resp := obs.NewResponseRecorder(w)

	start := time.Now()
	rpcMethod := ""
	rpcID := ""
	toolName := ""
	argsBytes := 0
	metaBytes := 0
	reqBytes := int64(0)
	reqBodyForLog := ""
	logRequestBody := false

	defer func() {
		if recovered := recover(); recovered != nil {
			baseLogger.Debug(
				"mcp_panic_recovered",
				"path", r.URL.Path,
				"method", r.Method,
				"panic", fmt.Sprint(recovered),
			)
			if !resp.WroteHeader() {
				http.Error(wrapped, "Internal server error", http.StatusInternalServerError)
			}
		}

		if (r.Method == http.MethodPost || r.Method == http.MethodDelete) && !resp.WroteHeader() {
			baseLogger.Debug(
				"mcp_no_write_guard",
				"path", r.URL.Path,
				"method", r.Method,
			)
			http.Error(wrapped, "MCP handler returned without writing response", http.StatusInternalServerError)
		}

		attrs := []any{
			"rpc_method", rpcMethod,
			"req_bytes", reqBytes,
			"resp_bytes", resp.RespBytes(),
			"dur_ms", float64(time.Since(start).Microseconds()) / 1000.0,
		}
		if rpcID != "" {
			attrs = append(attrs, "rpc_id", rpcID)
		}
		if toolName != "" {
			attrs = append(attrs, "tool_name", toolName)
		}
		if argsBytes > 0 {
			attrs = append(attrs, "args_bytes", argsBytes)
		}
		if metaBytes > 0 {
			attrs = append(attrs, "meta_bytes", metaBytes)
		}
		if logRequestBody {
			attrs = append(attrs, "req_body", reqBodyForLog)
		}

		baseLogger.Debug("mcp_req", attrs...)
	}()

	if r.Method == http.MethodGet {
		wrapped.Header().Set("Allow", "POST, DELETE, OPTIONS")
		http.Error(wrapped, mcpGetNotSupportedMessage, http.StatusMethodNotAllowed)
		return
	}

	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(wrapped, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(wrapped, r.Body, maxMCPBodyBytes)
	body, readErr := io.ReadAll(r.Body)
	reqBytes = int64(len(body))
	if readErr != nil {
		var maxErr *http.MaxBytesError
		if errors.As(readErr, &maxErr) {
			http.Error(wrapped, "MCP request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(wrapped, "Failed to read MCP request body", http.StatusBadRequest)
		return
	}

	var envelope rpcEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		// SECURITY EXCEPTION: logging raw /mcp parse-failure body by explicit decision.
		logRequestBody = true
		reqBodyForLog = string(body)
		http.Error(wrapped, "Invalid MCP JSON-RPC request body", http.StatusBadRequest)
		return
	}

	rpcMethod = strings.TrimSpace(envelope.Method)
	if id, ok := rpcIDForLog(envelope.ID); ok {
		rpcID = id
	}

	sessionID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id"))
	if rpcMethod == "initialize" {
		if sessionID == "" {
			sessionID = uuid.NewString()
		}
		if !isASCII(sessionID) {
			http.Error(wrapped, "Invalid Mcp-Session-Id", http.StatusBadRequest)
			return
		}
		rememberMCPSession(sessionID)
		wrapped.Header().Set("Mcp-Session-Id", sessionID)
		r.Header.Set("Mcp-Session-Id", sessionID)
	} else {
		if sessionID != "" && !isASCII(sessionID) {
			http.Error(wrapped, "Invalid Mcp-Session-Id", http.StatusBadRequest)
			return
		}
		if sessionID != "" {
			rememberMCPSession(sessionID)
			wrapped.Header().Set("Mcp-Session-Id", sessionID)
		}
	}
	if sessionID != "" {
		r = r.WithContext(obs.WithCorrelation(r.Context(), obs.Correlation{MCPSessionID: sessionID}))
	}

	if rpcMethod == "tools/call" {
		var params toolCallParams
		if len(envelope.Params) > 0 && json.Unmarshal(envelope.Params, &params) == nil {
			toolName = strings.TrimSpace(params.Name)
			argsBytes = len(params.Arguments)
			metaBytes = len(params.Meta)
		}
	} else {
		logRequestBody = true
		reqBodyForLog = string(body)
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	s.httpHandler.ServeHTTP(wrapped, r)
}

// Start is a helper to run the MCP server standalone (for testing).
func (s *Server) Start(addr string) error {
	obs.Pkg("internal/mcp").Debug("mcp_server_start", "addr", addr, "path", "/mcp")
	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	http.Handle("/mcp", s)
	return server.ListenAndServe()
}

func formatMCPHeadersForLog(headers http.Header) string {
	if len(headers) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		values := headers.Values(k)
		if len(values) == 0 {
			parts = append(parts, strings.ToLower(k)+"=<empty>")
			continue
		}
		lowerKey := strings.ToLower(k)
		joined := strings.Join(values, ", ")
		if shouldRedactHeader(lowerKey) {
			joined = "[REDACTED]"
		}
		parts = append(parts, fmt.Sprintf("%s=%q", lowerKey, joined))
	}
	return strings.Join(parts, "; ")
}

func shouldRedactHeader(lowerKey string) bool {
	switch strings.ToLower(strings.TrimSpace(lowerKey)) {
	case "authorization", "proxy-authorization", "cookie", "set-cookie":
		return true
	default:
		return false
	}
}

func rpcIDForLog(raw json.RawMessage) (string, bool) {
	text := strings.TrimSpace(string(raw))
	if text == "" || text == "null" {
		return "", false
	}
	return text, true
}

func isASCII(value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch < 0x20 || ch > 0x7e {
			return false
		}
	}
	return true
}

func rememberMCPSession(sessionID string) {
	if strings.TrimSpace(sessionID) == "" {
		return
	}
	if len(sessionID) > maxMCPSessionIDLength {
		return
	}
	mcpSessionRegistry.Store(sessionID, time.Now().UTC())
}

// StartSessionSweeper launches a background goroutine that periodically removes
// expired entries from mcpSessionRegistry. It stops when ctx is cancelled.
func StartSessionSweeper(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				mcpSessionRegistry.Range(func(key, value any) bool {
					lastSeen, ok := value.(time.Time)
					if !ok || now.Sub(lastSeen) > mcpSessionTTL {
						mcpSessionRegistry.Delete(key)
					}
					return true
				})
			}
		}
	}()
}

func isKnownMCPSession(sessionID string) bool {
	raw, ok := mcpSessionRegistry.Load(sessionID)
	if !ok {
		return false
	}
	lastSeen, ok := raw.(time.Time)
	if !ok {
		mcpSessionRegistry.Delete(sessionID)
		return false
	}
	if time.Since(lastSeen) > mcpSessionTTL {
		mcpSessionRegistry.Delete(sessionID)
		return false
	}
	return true
}
