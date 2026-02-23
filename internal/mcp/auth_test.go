package mcp

import (
	"encoding/json"
	"testing"

	"pgregory.net/rapid"
)

func testMCPAuthTriggerResponseShape(t *rapid.T) {
	resource := rapid.StringMatching(`https://[a-z0-9.-]{3,40}/[a-z0-9./_-]{1,40}`).Draw(t, "resource")
	desc := rapid.StringMatching(`[a-zA-Z0-9 _:/.-]{1,80}`).Draw(t, "desc")

	resp := MCPAuthTriggerResponse(resource, desc)

	if got, _ := resp["jsonrpc"].(string); got != "2.0" {
		t.Fatalf("jsonrpc mismatch: got=%q want=2.0", got)
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("missing result payload: %#v", resp)
	}
	if isErr, _ := result["isError"].(bool); !isErr {
		t.Fatalf("expected isError=true, got=%v", result["isError"])
	}

	meta, ok := result["_meta"].(map[string]any)
	if !ok {
		t.Fatalf("missing _meta in result: %#v", result)
	}
	challenges, ok := meta["mcp/www_authenticate"].([]string)
	if !ok || len(challenges) != 1 {
		t.Fatalf("unexpected mcp/www_authenticate payload: %#v", meta["mcp/www_authenticate"])
	}
	if challenges[0] == "" {
		t.Fatal("expected non-empty auth challenge")
	}
}

func TestMCPAuthTriggerResponseShape(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testMCPAuthTriggerResponseShape)
}

func testMCPAuthTriggerResponseWithIDIncludesID(t *rapid.T) {
	id := rapid.Int64().Draw(t, "id")
	resource := "https://example.com/.well-known/oauth-protected-resource"
	desc := "Authentication required"

	resp := MCPAuthTriggerResponseWithID(id, resource, desc)
	if got := resp["id"]; got != id {
		t.Fatalf("id mismatch: got=%v want=%v", got, id)
	}
}

func TestMCPAuthTriggerResponseWithIDIncludesID(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testMCPAuthTriggerResponseWithIDIncludesID)
}

func testMCPErrorResponseShape(t *rapid.T) {
	id := rapid.Int64().Draw(t, "id")
	code := rapid.IntRange(-32768, -32000).Draw(t, "code")
	message := rapid.StringMatching(`[a-zA-Z0-9 _:/.-]{1,80}`).Draw(t, "message")

	resp := MCPErrorResponse(id, code, message)
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal MCPErrorResponse failed: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal MCPErrorResponse failed: %v", err)
	}

	if got, _ := decoded["jsonrpc"].(string); got != "2.0" {
		t.Fatalf("jsonrpc mismatch: got=%q want=2.0", got)
	}
	if got := decoded["id"]; got != float64(id) {
		t.Fatalf("id mismatch: got=%v want=%v", got, id)
	}
	errObj, ok := decoded["error"].(map[string]any)
	if !ok {
		t.Fatalf("missing error object: %#v", decoded)
	}
	if got := int(errObj["code"].(float64)); got != code {
		t.Fatalf("code mismatch: got=%d want=%d", got, code)
	}
	if got, _ := errObj["message"].(string); got != message {
		t.Fatalf("message mismatch: got=%q want=%q", got, message)
	}
}

func TestMCPErrorResponseShape(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testMCPErrorResponseShape)
}
