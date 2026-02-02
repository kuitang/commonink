# MCP Streamable HTTP Transport Specification

**Protocol Revision**: 2025-03-26
**Document Created**: 2026-02-02

This document provides a reference for the MCP Streamable HTTP transport specification, which is the current standard transport for remote MCP servers.

## Overview

Streamable HTTP replaces the deprecated HTTP+SSE transport from protocol version 2024-11-05. It provides:

- **Single endpoint** for all communication (e.g., `/mcp`)
- **Bidirectional** communication over standard HTTP
- **Optional streaming** via Server-Sent Events (SSE) within responses
- **Session management** via `Mcp-Session-Id` header
- **Resumability** via event IDs

## Key Differences from Deprecated SSE Transport

| Feature | Old HTTP+SSE (Deprecated) | Streamable HTTP (Current) |
|---------|---------------------------|---------------------------|
| Endpoints | Two: `/sse` + `/messages` | Single: `/mcp` |
| Connection model | Long-lived SSE + separate POST | Request-response based |
| Server push | Required SSE stream | Optional (GET for SSE) |
| Session management | None | `Mcp-Session-Id` header |
| Recovery | No mechanism | `Last-Event-ID` resumption |

## HTTP Methods

### POST - Client to Server Messages

Every JSON-RPC message from client MUST be sent via HTTP POST:

**Request Requirements:**
- `Content-Type: application/json`
- `Accept: application/json, text/event-stream` (MUST include both)
- Body: JSON-RPC request, notification, response, or batch

**Server Response:**
- For notifications/responses only: `202 Accepted` with no body
- For requests: Either:
  - `Content-Type: application/json` - single JSON response
  - `Content-Type: text/event-stream` - SSE stream with responses

**Example:**
```bash
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: abc123" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

### GET - Server to Client Messages (Optional)

Client MAY issue HTTP GET to receive server-initiated messages:

**Request Requirements:**
- `Accept: text/event-stream`
- `Mcp-Session-Id` header (if session established)
- `Last-Event-ID` header (for resumption)

**Server Response:**
- `Content-Type: text/event-stream` - SSE stream with server messages
- OR `405 Method Not Allowed` - if server doesn't support GET stream

**Example:**
```bash
curl -N http://localhost:8080/mcp \
  -H "Accept: text/event-stream" \
  -H "Mcp-Session-Id: abc123"
```

### DELETE - Session Termination (Optional)

Client SHOULD send DELETE to terminate a session:

**Request Requirements:**
- `Mcp-Session-Id` header (required)

**Server Response:**
- `200 OK` or `204 No Content` - session terminated
- `405 Method Not Allowed` - server doesn't allow client termination

## Session Management

1. **Initialization**: Server MAY return `Mcp-Session-Id` header in InitializeResult
2. **Subsequent Requests**: Client MUST include session ID in all requests
3. **Session Expiry**: Server returns `404 Not Found` for expired sessions
4. **Termination**: Client sends DELETE with session ID

**Session ID Requirements:**
- Globally unique
- Cryptographically secure (UUID, JWT, or cryptographic hash)
- Visible ASCII characters only (0x21-0x7E)

## Resumability

For connection recovery:

1. Server MAY attach `id` field to SSE events (per SSE spec)
2. IDs MUST be globally unique within the session
3. Client includes `Last-Event-ID` header when reconnecting
4. Server MAY replay messages from that point (same stream only)

## Security Considerations

1. **Origin Validation**: MUST validate Origin header to prevent DNS rebinding
2. **Localhost Binding**: SHOULD bind to 127.0.0.1, not 0.0.0.0 for local servers
3. **Authentication**: SHOULD implement proper auth for all connections

## Go SDK Implementation

Using the official `github.com/modelcontextprotocol/go-sdk`:

```go
package main

import (
    "net/http"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
    // Create MCP server
    server := mcp.NewServer(&mcp.Implementation{
        Name:    "my-server",
        Version: "1.0.0",
    }, nil)

    // Register tools
    mcp.AddTool(server, &mcp.Tool{
        Name:        "my_tool",
        Description: "Does something",
    }, myToolHandler)

    // Create Streamable HTTP handler
    handler := mcp.NewStreamableHTTPHandler(
        func(r *http.Request) *mcp.Server { return server },
        &mcp.StreamableHTTPOptions{
            JSONResponse: false, // Allow SSE streaming
        },
    )

    // Mount single endpoint
    http.Handle("/mcp", handler)
    http.ListenAndServe(":8080", nil)
}
```

## Testing

### MCP Conformance Suite

```bash
npx @modelcontextprotocol/conformance server --url http://localhost:8080/mcp
```

### Manual Testing

```bash
# Initialize session
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{}},"id":1}'

# List tools (with session ID from response)
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: <session-id-from-init>" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":2}'
```

## References

- [MCP Transports Specification 2025-03-26](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports)
- [Why MCP Deprecated SSE and Went with Streamable HTTP](https://blog.fka.dev/blog/2025-06-06-why-mcp-deprecated-sse-and-go-with-streamable-http/)
- [MCP Transport Future (December 2025)](http://blog.modelcontextprotocol.io/posts/2025-12-19-mcp-transport-future/)
- [Go SDK Documentation](https://pkg.go.dev/github.com/modelcontextprotocol/go-sdk/mcp)
