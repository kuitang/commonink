//go:build sprite
// +build sprite

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kuitang/agent-notes/tests/e2e/testutil"
)

// spriteTokenIsReal returns true if the SPRITE_TOKEN env var looks like
// a real Fly Sprites token (non-empty and does not start with "test-").
func spriteTokenIsReal() bool {
	token := strings.TrimSpace(os.Getenv("SPRITE_TOKEN"))
	if token == "" {
		return false
	}
	if strings.HasPrefix(token, "test-") {
		return false
	}
	return true
}

// deleteAppViaMCP is a best-effort cleanup helper that deletes an app via MCP.
func (e *appsAPIEnv) deleteAppViaMCP(appName string) error {
	_, err := e.mcpCallTool("app_delete", map[string]any{
		"app": appName,
	})
	return err
}

// Roundtrip Create-Get-Delete Test (single happy path).
// Creates one app via MCP app_create, verifies it via REST API, deletes it,
// then verifies it returns 404.
func TestAppsAPI_Roundtrip_CreateGetDelete(t *testing.T) {
	if !spriteTokenIsReal() {
		t.Skip("SPRITE_TOKEN is not set or looks like a dummy token; skipping roundtrip test")
	}
	env := getAppsAPIEnv(t)
	appName := fmt.Sprintf("%s-%d", testutil.PrefixWithRunID("e2e-rt"), time.Now().UnixMilli()%100000)

	defer func() {
		_ = env.deleteAppViaMCP(appName)
	}()

	result, err := env.mcpCallTool("app_create", map[string]any{
		"names": []any{appName},
	})
	if err != nil {
		t.Fatalf("app_create MCP call failed: %v", err)
	}

	var toolResult struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(result, &toolResult); err != nil {
		t.Fatalf("failed to parse MCP result: %v (%s)", err, string(result))
	}
	if toolResult.IsError {
		t.Fatalf("app_create returned isError=true: %s", string(result))
	}

	var createPayloadText string
	for _, c := range toolResult.Content {
		if c.Type == "text" {
			createPayloadText = c.Text
			break
		}
	}
	if createPayloadText == "" {
		t.Fatalf("app_create returned no text content: %s", string(result))
	}

	var createResult struct {
		Created bool   `json:"created"`
		Name    string `json:"name"`
	}
	if err := json.Unmarshal([]byte(createPayloadText), &createResult); err != nil {
		t.Fatalf("failed to parse app_create payload: %v (%s)", err, createPayloadText)
	}
	if !createResult.Created || createResult.Name != appName {
		t.Fatalf("app_create: created=%v name=%q, want true/%q", createResult.Created, createResult.Name, appName)
	}

	listStatus, _, listBody, err := env.doRequest(http.MethodGet, "/api/apps", env.accessToken)
	if err != nil {
		t.Fatalf("list request failed: %v", err)
	}
	if listStatus != http.StatusOK {
		t.Fatalf("expected 200 from list, got %d: %s", listStatus, string(listBody))
	}
	if !strings.Contains(string(listBody), appName) {
		t.Fatalf("app %q not found in list response", appName)
	}

	getStatus, _, getBody, err := env.doRequest(http.MethodGet, "/api/apps/"+appName, env.accessToken)
	if err != nil {
		t.Fatalf("get request failed: %v", err)
	}
	if getStatus != http.StatusOK {
		t.Fatalf("expected 200 from get, got %d: %s", getStatus, string(getBody))
	}
	var getPayload struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(getBody, &getPayload); err != nil {
		t.Fatalf("failed to decode get response: %v (%s)", err, string(getBody))
	}
	if getPayload.Name != appName || strings.TrimSpace(getPayload.Status) == "" {
		t.Fatalf("get: name=%q status=%q", getPayload.Name, getPayload.Status)
	}

	delStatus, _, delBody, err := env.doRequest(http.MethodDelete, "/api/apps/"+appName, env.accessToken)
	if err != nil {
		t.Fatalf("delete request failed: %v", err)
	}
	if delStatus != http.StatusOK {
		t.Fatalf("expected 200 from delete, got %d: %s", delStatus, string(delBody))
	}

	goneStatus, _, goneBody, err := env.doRequest(http.MethodGet, "/api/apps/"+appName, env.accessToken)
	if err != nil {
		t.Fatalf("get-after-delete request failed: %v", err)
	}
	if goneStatus != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d: %s", goneStatus, string(goneBody))
	}
}
