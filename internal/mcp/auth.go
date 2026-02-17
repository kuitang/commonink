// Package mcp provides MCP server functionality for the agent-notes application.
package mcp

import "fmt"

// MCPAuthTriggerResponse returns the MCP JSON-RPC response format for triggering
// the OAuth UI in ChatGPT. This should be returned when a tool requires authentication
// but no valid token is present.
//
// Per the MCP authorization flow documented in docs/AUTH.md, this response format
// triggers the tool-level OAuth flow in ChatGPT when combined with proper
// securitySchemes declarations.
//
// Parameters:
//   - resourceMetadataURL: URL to the protected resource metadata
//     (e.g., "https://your-mcp.example.com/.well-known/oauth-protected-resource")
//   - errorDesc: Human-readable description shown to the user
//
// Example response:
//
//	{
//	  "jsonrpc": "2.0",
//	  "result": {
//	    "content": [{"type": "text", "text": "Authentication required: ..."}],
//	    "_meta": {
//	      "mcp/www_authenticate": ["Bearer resource_metadata=\"...\", error=\"insufficient_scope\", error_description=\"...\""]
//	    },
//	    "isError": true
//	  }
//	}
func MCPAuthTriggerResponse(resourceMetadataURL, errorDesc string) map[string]any {
	wwwAuthHeader := fmt.Sprintf(`Bearer resource_metadata="%s", error="insufficient_scope", error_description="%s"`,
		resourceMetadataURL, errorDesc)

	return map[string]any{
		"jsonrpc": "2.0",
		"result": map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": errorDesc},
			},
			"_meta": map[string]any{
				"mcp/www_authenticate": []string{wwwAuthHeader},
			},
			"isError": true,
		},
	}
}

// MCPAuthTriggerResponseWithID returns the MCP JSON-RPC response format for
// triggering the OAuth UI, with a specific request ID.
// Use this when responding to a specific JSON-RPC request.
func MCPAuthTriggerResponseWithID(id any, resourceMetadataURL, errorDesc string) map[string]any {
	resp := MCPAuthTriggerResponse(resourceMetadataURL, errorDesc)
	resp["id"] = id
	return resp
}

// MCPErrorResponse returns a standard MCP error response.
// Use this for non-auth errors (e.g., invalid input, server errors).
func MCPErrorResponse(id any, code int, message string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	}
}

// Standard JSON-RPC error codes.
const (
	ErrorCodeParseError     = -32700
	ErrorCodeInvalidRequest = -32600
	ErrorCodeMethodNotFound = -32601
	ErrorCodeInvalidParams  = -32602
	ErrorCodeInternalError  = -32603
)
