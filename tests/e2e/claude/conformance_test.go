// Package claude provides E2E tests using Claude CLI with streaming JSON.
// Uses bidirectional stdin/stdout streaming for multi-turn conversation.
// Tests run against a subprocess server (built and started once).
//
// ARCHITECTURE:
// 1. Server binary is built and started as subprocess (once for all tests)
// 2. Claude CLI connects to server's /mcp endpoint via MCP HTTP transport
// 3. Tests verify CRUD operations via Claude's tool calls
package claude

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kuitang/agent-notes/tests/e2e/testutil"
)

// =============================================================================
// Test Main: Start server once for all tests
// =============================================================================

func TestMain(m *testing.M) {
	code := m.Run()
	testutil.Cleanup()
	os.Exit(code)
}

// =============================================================================
// MCP Config Generation
// =============================================================================

// getAuthenticatedMCPConfig creates an MCP config with OAuth bearer token authentication.
// This is required because our MCP server requires OAuth 2.1 authentication.
// Claude Code supports bearer tokens via the "headers" field in MCP config.
func getAuthenticatedMCPConfig(t testing.TB, accessToken string) string {
	t.Helper()
	srv := testutil.GetServer(t)
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, ".mcp.json")
	config := map[string]any{
		"mcpServers": map[string]any{
			"agent-notes": map[string]any{
				"type": "http",
				"url":  srv.BaseURL + "/mcp",
				"headers": map[string]string{
					"Authorization": "Bearer " + accessToken,
				},
			},
		},
	}
	configBytes, _ := json.MarshalIndent(config, "", "  ")
	if err := os.WriteFile(configPath, configBytes, 0644); err != nil {
		t.Fatalf("Failed to write MCP config: %v", err)
	}
	return configPath
}

// =============================================================================
// Streaming Message Types
// =============================================================================

// StreamMessage represents a message in Claude's streaming JSON format
type StreamMessage struct {
	Type      string            `json:"type"`
	Subtype   string            `json:"subtype,omitempty"`
	SessionID string            `json:"session_id,omitempty"`
	Result    string            `json:"result,omitempty"`
	IsError   bool              `json:"is_error,omitempty"`
	Message   *AssistantMessage `json:"message,omitempty"`
}

// AssistantMessage represents the assistant message within a StreamMessage
type AssistantMessage struct {
	ID      string         `json:"id"`
	Role    string         `json:"role"`
	Content []ContentBlock `json:"content"`
}

// ContentBlock represents a content block in assistant messages
type ContentBlock struct {
	Type      string `json:"type"`
	Text      string `json:"text,omitempty"`
	ToolUseID string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	Input     any    `json:"input,omitempty"`
	ServerID  string `json:"server_id,omitempty"`
}

// ToolCall represents an MCP tool call
type ToolCall struct {
	Name     string
	ToolID   string
	ServerID string
}

// =============================================================================
// Conversation: Bidirectional streaming with Claude CLI
// =============================================================================

// Conversation manages a streaming conversation with Claude CLI
type Conversation struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	scanner *bufio.Scanner
	mu      sync.Mutex
	closed  bool
}

// NewConversation starts a new streaming conversation with Claude
func NewConversation(t *testing.T, mcpConfig string) *Conversation {
	t.Helper()

	if _, err := exec.LookPath("claude"); err != nil {
		t.Fatal("claude CLI not found")
	}

	cmd := exec.Command("claude",
		"-p",
		"--verbose",
		"--input-format", "stream-json",
		"--output-format", "stream-json",
		"--mcp-config", mcpConfig,
		"--dangerously-skip-permissions",
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("Failed to get stdin pipe: %v", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Failed to get stdout pipe: %v", err)
	}

	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start claude: %v", err)
	}

	return &Conversation{
		cmd:     cmd,
		stdin:   stdin,
		stdout:  stdout,
		scanner: bufio.NewScanner(stdout),
	}
}

// SendMessage sends a user message and collects the response
func (c *Conversation) SendMessage(t *testing.T, message string) (string, []ToolCall) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		t.Fatal("Conversation is closed")
	}

	userMsg := map[string]any{
		"type": "user",
		"message": map[string]string{
			"role":    "user",
			"content": message,
		},
	}
	msgBytes, _ := json.Marshal(userMsg)
	t.Logf("Sending: %s", string(msgBytes))

	if _, err := c.stdin.Write(append(msgBytes, '\n')); err != nil {
		t.Fatalf("Failed to write to stdin: %v", err)
	}

	var toolCalls []ToolCall
	var responseText strings.Builder
	var sessionID string

	for c.scanner.Scan() {
		line := c.scanner.Text()
		if line == "" {
			continue
		}

		t.Logf("Received: %s", line)

		var msg StreamMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}

		if msg.SessionID != "" {
			if sessionID == "" {
				sessionID = msg.SessionID
				t.Logf("Session ID: %s", sessionID)
			}
		}

		switch msg.Type {
		case "system":
			continue

		case "assistant":
			if msg.Message != nil {
				for _, block := range msg.Message.Content {
					switch block.Type {
					case "text":
						responseText.WriteString(block.Text)
					case "tool_use":
						toolCalls = append(toolCalls, ToolCall{
							Name:     block.Name,
							ToolID:   block.ToolUseID,
							ServerID: block.ServerID,
						})
						t.Logf("Tool call: %s (ID: %s)", block.Name, block.ToolUseID)
					}
				}
			}

		case "result":
			if msg.Result != "" && responseText.Len() == 0 {
				responseText.WriteString(msg.Result)
			}
			return responseText.String(), toolCalls

		case "error":
			t.Logf("Error from Claude: %v", msg)
		}
	}

	if err := c.scanner.Err(); err != nil {
		t.Logf("Scanner error: %v", err)
	}

	return responseText.String(), toolCalls
}

// Close terminates the conversation
func (c *Conversation) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	c.stdin.Close()
	c.stdout.Close()
	return c.cmd.Wait()
}

// =============================================================================
// One-shot Claude execution
// =============================================================================

func runOneShotClaude(t *testing.T, mcpConfig, prompt string) (string, []ToolCall) {
	t.Helper()

	if _, err := exec.LookPath("claude"); err != nil {
		t.Fatal("claude CLI not found")
	}

	cmd := exec.Command("claude", "-p", prompt,
		"--verbose",
		"--output-format", "stream-json",
		"--mcp-config", mcpConfig,
		"--dangerously-skip-permissions")

	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("claude failed: %v", err)
	}

	var toolCalls []ToolCall
	var responseText strings.Builder

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var msg StreamMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}

		switch msg.Type {
		case "assistant":
			if msg.Message != nil {
				for _, block := range msg.Message.Content {
					switch block.Type {
					case "text":
						responseText.WriteString(block.Text)
					case "tool_use":
						toolCalls = append(toolCalls, ToolCall{
							Name:     block.Name,
							ToolID:   block.ToolUseID,
							ServerID: block.ServerID,
						})
					}
				}
			}
		case "result":
			if msg.Result != "" && responseText.Len() == 0 {
				responseText.WriteString(msg.Result)
			}
		}
	}

	return responseText.String(), toolCalls
}

// =============================================================================
// Multi-turn Streaming Tests
// =============================================================================

func TestClaude_MultiTurn_Streaming(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	srv := testutil.GetServer(t)

	// Perform OAuth flow to get access token for MCP authentication
	creds := testutil.PerformOAuthFlow(t, srv.BaseURL, "MultiTurnTest")

	// Create authenticated MCP config with bearer token in headers
	// (Claude Code supports OAuth via headers in MCP config)
	mcpConfig := getAuthenticatedMCPConfig(t, creds.AccessToken)

	// Create authenticated MCP client for verification
	mcpClient := testutil.NewMCPClient(srv.BaseURL, creds.AccessToken)

	conv := NewConversation(t, mcpConfig)
	defer conv.Close()

	var noteID string

	// Turn 1: Create a note
	t.Run("Turn1_Create", func(t *testing.T) {
		resp, toolCalls := conv.SendMessage(t,
			"Create a note titled 'Team Meeting Notes' with content 'Discussed Q1 roadmap and assigned action items.'")

		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))

		// Verify via MCP
		listResp, err := mcpClient.CallTool("note_list", map[string]interface{}{})
		if err != nil {
			t.Fatalf("MCP list failed: %v", err)
		}
		result, _ := testutil.ParseToolResult(listResp)
		t.Logf("Notes after create: %s", result)

		if !strings.Contains(strings.ToLower(result), "meeting") {
			t.Fatal("Note not created")
		}
	})

	// Turn 2: List notes
	t.Run("Turn2_List", func(t *testing.T) {
		resp, toolCalls := conv.SendMessage(t,
			"List all my notes and tell me how many there are.")

		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))
	})

	// Turn 3: Search notes
	t.Run("Turn3_Search", func(t *testing.T) {
		resp, toolCalls := conv.SendMessage(t,
			"Search for notes containing 'meeting'.")

		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))
	})

	// Turn 4: Update note (get ID first)
	t.Run("Turn4_Update", func(t *testing.T) {
		// First get the note ID via MCP
		listResp, err := mcpClient.CallTool("note_list", map[string]interface{}{})
		if err != nil {
			t.Fatalf("MCP list failed: %v", err)
		}
		result, _ := testutil.ParseToolResult(listResp)

		// Parse to find ID
		var listData struct {
			Notes []struct {
				ID    string `json:"id"`
				Title string `json:"title"`
			} `json:"notes"`
		}
		json.Unmarshal([]byte(result), &listData)
		for _, n := range listData.Notes {
			if strings.Contains(strings.ToLower(n.Title), "meeting") {
				noteID = n.ID
				break
			}
		}

		if noteID == "" {
			t.Skip("No note ID found")
		}

		prompt := fmt.Sprintf("Update the note with ID '%s' to add 'Follow-up: Monday' to the content.", noteID)
		resp, toolCalls := conv.SendMessage(t, prompt)

		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))
	})

	// Turn 5: Delete note
	t.Run("Turn5_Delete", func(t *testing.T) {
		if noteID == "" {
			t.Skip("No note ID")
		}
		prompt := fmt.Sprintf("Delete the note with ID '%s'.", noteID)
		resp, toolCalls := conv.SendMessage(t, prompt)

		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))

		// Verify deletion via MCP
		readResp, err := mcpClient.CallTool("note_view", map[string]interface{}{"id": noteID})
		if err == nil && readResp.Error == nil {
			t.Fatal("Note still exists after delete")
		}
		t.Log("Note deleted successfully")
	})
}

// =============================================================================
// One-shot Tests
// =============================================================================

func TestClaude_OneShot_CRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	srv := testutil.GetServer(t)

	// Perform OAuth flow to get access token for MCP authentication
	creds := testutil.PerformOAuthFlow(t, srv.BaseURL, "OneShotTest")

	// Create authenticated MCP config with bearer token in headers
	mcpConfig := getAuthenticatedMCPConfig(t, creds.AccessToken)
	mcpClient := testutil.NewMCPClient(srv.BaseURL, creds.AccessToken)

	var noteID string

	t.Run("Create", func(t *testing.T) {
		resp, toolCalls := runOneShotClaude(t, mcpConfig,
			"Create a note titled 'One Shot Test' with content 'Testing one-shot mode.'")
		t.Logf("Response: %s, Tools: %d", resp, len(toolCalls))

		// Verify via MCP
		listResp, err := mcpClient.CallTool("note_list", map[string]interface{}{})
		if err != nil {
			t.Fatalf("MCP list failed: %v", err)
		}
		result, _ := testutil.ParseToolResult(listResp)
		if !strings.Contains(result, "One Shot") {
			t.Fatal("Note not created")
		}

		// Get ID for later tests
		var listData struct {
			Notes []struct {
				ID    string `json:"id"`
				Title string `json:"title"`
			} `json:"notes"`
		}
		json.Unmarshal([]byte(result), &listData)
		for _, n := range listData.Notes {
			if strings.Contains(n.Title, "One Shot") {
				noteID = n.ID
				break
			}
		}
	})

	t.Run("List", func(t *testing.T) {
		resp, toolCalls := runOneShotClaude(t, mcpConfig, "List all my notes.")
		t.Logf("Response: %s, Tools: %d", resp, len(toolCalls))
	})

	t.Run("Search", func(t *testing.T) {
		resp, toolCalls := runOneShotClaude(t, mcpConfig, "Search for notes about 'shot'.")
		t.Logf("Response: %s, Tools: %d", resp, len(toolCalls))
	})

	t.Run("Update", func(t *testing.T) {
		if noteID == "" {
			t.Skip("No note")
		}
		resp, toolCalls := runOneShotClaude(t, mcpConfig,
			fmt.Sprintf("Update note %s to add 'Updated content'.", noteID))
		t.Logf("Response: %s, Tools: %d", resp, len(toolCalls))
	})

	t.Run("Delete", func(t *testing.T) {
		if noteID == "" {
			t.Skip("No note")
		}
		resp, toolCalls := runOneShotClaude(t, mcpConfig,
			fmt.Sprintf("Delete the note with ID %s.", noteID))
		t.Logf("Response: %s, Tools: %d", resp, len(toolCalls))

		// Verify deletion
		readResp, err := mcpClient.CallTool("note_view", map[string]interface{}{"id": noteID})
		if err == nil && readResp.Error == nil {
			t.Fatal("Note still exists")
		}
	})
}

// =============================================================================
// OAuth Integration Tests
// =============================================================================

func TestClaude_OAuth_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	srv := testutil.GetServer(t)

	// Get OAuth credentials
	creds := testutil.PerformOAuthFlow(t, srv.BaseURL, "ClaudeOAuthTest")

	t.Logf("[OAuth Integration] Access token obtained")
	t.Logf("[OAuth Integration] User ID: %s", creds.UserID)

	// Test 1: Authenticated MCP request
	t.Run("OAuthMCPCreate", func(t *testing.T) {
		mcpReq := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "note_create",
				"arguments": map[string]string{
					"title":   "OAuth Integration Test Note",
					"content": "Testing OAuth authentication for Claude",
				},
			},
			"id": 1,
		}
		body, _ := json.Marshal(mcpReq)

		req, _ := http.NewRequest("POST", srv.BaseURL+"/mcp", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+creds.AccessToken)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("MCP request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected 200, got %d: %s", resp.StatusCode, string(respBody))
		}

		t.Log("OAuth MCP create succeeded")
	})

	// Test 2: Unauthorized request should fail
	t.Run("UnauthorizedMCPFails", func(t *testing.T) {
		mcpReq := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "tools/list",
			"id":      1,
		}
		body, _ := json.Marshal(mcpReq)

		req, _ := http.NewRequest("POST", srv.BaseURL+"/mcp", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		// No Authorization header

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Expected 401, got %d", resp.StatusCode)
		}

		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if !strings.Contains(wwwAuth, "Bearer") {
			t.Fatalf("Expected Bearer challenge, got: %s", wwwAuth)
		}

		t.Logf("Correctly returned 401 with WWW-Authenticate: %s", wwwAuth)
	})

	// Test 3: OAuth metadata endpoints
	t.Run("OAuthMetadataEndpoints", func(t *testing.T) {
		client := &http.Client{}

		// Protected Resource Metadata
		prmResp, err := client.Get(srv.BaseURL + "/.well-known/oauth-protected-resource")
		if err != nil {
			t.Fatalf("Failed to fetch protected resource metadata: %v", err)
		}
		defer prmResp.Body.Close()

		if prmResp.StatusCode != http.StatusOK {
			t.Fatalf("Expected 200, got %d", prmResp.StatusCode)
		}

		// Authorization Server Metadata
		asmResp, err := client.Get(srv.BaseURL + "/.well-known/oauth-authorization-server")
		if err != nil {
			t.Fatalf("Failed to fetch auth server metadata: %v", err)
		}
		defer asmResp.Body.Close()

		if asmResp.StatusCode != http.StatusOK {
			t.Fatalf("Expected 200, got %d", asmResp.StatusCode)
		}

		var asm map[string]interface{}
		json.NewDecoder(asmResp.Body).Decode(&asm)

		// Verify S256 is supported
		challengeMethods, ok := asm["code_challenge_methods_supported"].([]interface{})
		if !ok {
			t.Fatal("Missing code_challenge_methods_supported")
		}

		hasS256 := false
		for _, method := range challengeMethods {
			if method == "S256" {
				hasS256 = true
				break
			}
		}
		if !hasS256 {
			t.Fatal("S256 not in code_challenge_methods_supported")
		}

		t.Log("OAuth metadata endpoints verified")
	})
}
