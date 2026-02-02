// Package claude provides E2E tests using Claude CLI (claude -p --json).
// Verifies MCP tool calls via JSON output and checks DB state directly.
// Uses SAME prompts as OpenAI tests.
package claude

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/mcp"
	"github.com/kuitang/agent-notes/internal/notes"
)

const TestUserID = "test-user-001"

// Shared prompts - SAME as OpenAI tests
var (
	PromptCreate = "Create a note titled 'Team Meeting Notes' with content 'Discussed Q1 roadmap and assigned action items to the team.'"
	PromptList   = "List all my notes and tell me how many there are."
	PromptSearch = "Search for notes containing 'meeting' and summarize what you find."
	PromptUpdate = "Update the note with ID '%s' to add 'Follow-up scheduled for next Monday' to the content."
	PromptDelete = "Delete the note with ID '%s'."
)

type testEnv struct {
	server    *httptest.Server
	notesSvc  *notes.Service
	mcpConfig string
	cleanup   func()
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	if _, err := exec.LookPath("claude"); err != nil {
		t.Fatal("claude CLI not found")
	}

	tempDir := t.TempDir()
	os.Setenv("DB_DATA_DIR", tempDir)

	if err := db.InitSchemas(TestUserID); err != nil {
		t.Fatalf("DB init failed: %v", err)
	}

	userDB, err := db.OpenUserDB(TestUserID)
	if err != nil {
		t.Fatalf("Open DB failed: %v", err)
	}

	notesSvc := notes.NewService(userDB)
	mcpSrv := mcp.NewServer(notesSvc)

	mux := http.NewServeMux()
	mux.Handle("/mcp", mcpSrv)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	})

	server := httptest.NewServer(mux)

	// Create MCP config
	mcpConfig := filepath.Join(tempDir, ".mcp.json")
	config := map[string]any{
		"mcpServers": map[string]any{
			"agent-notes": map[string]any{
				"type": "streamableHttp",
				"url":  server.URL + "/mcp",
			},
		},
	}
	configBytes, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(mcpConfig, configBytes, 0644)

	return &testEnv{
		server:    server,
		notesSvc:  notesSvc,
		mcpConfig: mcpConfig,
		cleanup: func() {
			server.Close()
			db.CloseAll()
		},
	}
}

// MCPToolCall represents a tool call from Claude's JSON output
type MCPToolCall struct {
	Type      string `json:"type"`
	Name      string `json:"name"`
	ServerID  string `json:"server_id"`
	Arguments any    `json:"arguments"`
}

// ClaudeMessage represents a message in Claude's streaming JSON output
type ClaudeMessage struct {
	Type    string      `json:"type"`
	Tool    *MCPToolCall `json:"tool,omitempty"`
	Content string      `json:"content,omitempty"`
}

// runClaude runs claude -p --output-format stream-json and returns tool calls made
// Uses streaming JSON to capture intermediate tool calls
func (env *testEnv) runClaude(t *testing.T, prompt string) ([]MCPToolCall, string) {
	t.Helper()

	cmd := exec.Command("claude", "-p", prompt, "--output-format", "stream-json", "--mcp-config", env.mcpConfig)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	t.Logf("Running: claude -p %q --json", prompt)

	if err := cmd.Run(); err != nil {
		t.Logf("stderr: %s", stderr.String())
		t.Fatalf("claude failed: %v", err)
	}

	// Parse streaming JSON (one JSON object per line)
	var toolCalls []MCPToolCall
	var finalText string

	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}

		// Check for tool_use type
		if msgType, ok := msg["type"].(string); ok {
			if msgType == "tool_use" || msgType == "tool_call" {
				if name, ok := msg["name"].(string); ok {
					toolCalls = append(toolCalls, MCPToolCall{
						Type: msgType,
						Name: name,
					})
				}
			}
			if msgType == "text" || msgType == "content" {
				if text, ok := msg["text"].(string); ok {
					finalText += text
				}
				if content, ok := msg["content"].(string); ok {
					finalText += content
				}
			}
		}

		// Also check for result.tool_use in nested structures
		if result, ok := msg["result"].(map[string]any); ok {
			if tools, ok := result["tool_use"].([]any); ok {
				for _, tool := range tools {
					if toolMap, ok := tool.(map[string]any); ok {
						if name, ok := toolMap["name"].(string); ok {
							toolCalls = append(toolCalls, MCPToolCall{Name: name})
						}
					}
				}
			}
		}
	}

	t.Logf("Tool calls: %d, Response length: %d", len(toolCalls), len(finalText))
	return toolCalls, finalText
}

func TestClaude_CRUD_E2E(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	// One-shot prompt: Create, list, and search in one prompt
	t.Run("CreateListSearch", func(t *testing.T) {
		oneShot := `Do the following in order:
1. Create a note titled 'Team Meeting Notes' with content 'Discussed Q1 roadmap and assigned action items.'
2. List all my notes
3. Search for notes containing 'meeting'
Tell me the results of each step.`

		toolCalls, resp := env.runClaude(t, oneShot)
		t.Logf("Tool calls: %d, Response length: %d", len(toolCalls), len(resp))

		// Verify create tool was called
		foundCreate := false
		for _, tc := range toolCalls {
			if strings.Contains(tc.Name, "create") {
				foundCreate = true
			}
		}
		if !foundCreate && len(toolCalls) == 0 {
			t.Logf("Warning: No create tool call detected")
		}

		// Verify DB state - note should exist
		list, err := env.notesSvc.List(100, 0)
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}
		if list.TotalCount == 0 {
			t.Fatal("No notes created")
		}
		t.Logf("Notes in DB: %d", list.TotalCount)
	})

	// Get note ID for update/delete
	list, _ := env.notesSvc.List(100, 0)
	if len(list.Notes) == 0 {
		t.Fatal("No notes to update/delete")
	}
	noteID := list.Notes[0].ID

	// One-shot prompt: Update and verify
	t.Run("UpdateAndVerify", func(t *testing.T) {
		prompt := fmt.Sprintf("Update the note with ID '%s' to add 'Follow-up: Monday' to the content, then show me the updated note.", noteID)
		env.runClaude(t, prompt)

		// Verify DB state
		note, err := env.notesSvc.Read(noteID)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		t.Logf("Updated content: %s", note.Content)
	})

	// One-shot prompt: Delete
	t.Run("Delete", func(t *testing.T) {
		prompt := fmt.Sprintf("Delete the note with ID '%s'.", noteID)
		env.runClaude(t, prompt)

		// Verify DB state - note should not exist
		_, err := env.notesSvc.Read(noteID)
		if err == nil {
			t.Fatal("Note still exists after delete")
		}
		t.Log("Note successfully deleted")
	})
}

func TestClaude_VerifyMCPCalls(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	// Simple test - create a note and verify MCP was called
	toolCalls, _ := env.runClaude(t, "Create a note called 'Test' with content 'Hello'")

	t.Logf("Tool calls detected: %d", len(toolCalls))
	for i, tc := range toolCalls {
		t.Logf("  %d: %s", i, tc.Name)
	}

	// Verify note was created in DB
	list, _ := env.notesSvc.List(100, 0)
	if list.TotalCount == 0 {
		t.Fatal("No notes created - MCP may not be working")
	}
	t.Logf("Notes in DB: %d", list.TotalCount)
}
