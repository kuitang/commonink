// Package claude provides E2E tests using Claude CLI with streaming JSON.
// Uses bidirectional stdin/stdout streaming for multi-turn conversation.
// Uses SAME prompts as OpenAI tests for parity.
package claude

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/mcp"
	"github.com/kuitang/agent-notes/internal/notes"
)

const TestUserID = "test-user-001"

// testEnv holds the test environment
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

	// Create MCP config - use "http" transport for streamable HTTP
	// See: https://code.claude.com/docs/en/mcp
	mcpConfig := filepath.Join(tempDir, ".mcp.json")
	config := map[string]any{
		"mcpServers": map[string]any{
			"agent-notes": map[string]any{
				"type": "http",
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

// StreamMessage represents a message in Claude's streaming JSON format
type StreamMessage struct {
	Type      string `json:"type"`
	Subtype   string `json:"subtype,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Result    string `json:"result,omitempty"`
	IsError   bool   `json:"is_error,omitempty"`
	// For assistant messages
	Message *AssistantMessage `json:"message,omitempty"`
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
	ToolUseID string `json:"id,omitempty"`    // For tool_use blocks
	Name      string `json:"name,omitempty"`  // Tool name
	Input     any    `json:"input,omitempty"` // Tool input
	ServerID  string `json:"server_id,omitempty"`
}

// ToolCall represents an MCP tool call
type ToolCall struct {
	Name     string
	ToolID   string
	ServerID string
}

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

	cmd := exec.Command("claude",
		"-p",
		"--verbose", // Required for stream-json output
		"--input-format", "stream-json",
		"--output-format", "stream-json",
		"--mcp-config", mcpConfig,
		"--dangerously-skip-permissions", // Allow MCP tool calls without prompts
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
// Returns the final text response and tool calls made
func (c *Conversation) SendMessage(t *testing.T, message string) (string, []ToolCall) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		t.Fatal("Conversation is closed")
	}

	// Send user message as JSON in the correct format:
	// {"type":"user","message":{"role":"user","content":"..."}}
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

	// Collect response
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
			t.Logf("Failed to parse JSON: %v", err)
			continue
		}

		// Track session ID to prove conversation continuity
		if msg.SessionID != "" {
			if sessionID == "" {
				sessionID = msg.SessionID
				t.Logf("Session ID (proves multi-turn): %s", sessionID)
			} else if sessionID != msg.SessionID {
				t.Logf("WARNING: Session ID changed from %s to %s", sessionID, msg.SessionID)
			}
		}

		switch msg.Type {
		case "system":
			// Init or other system message - continue
			continue

		case "assistant":
			// Parse content blocks from the assistant message
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
			// End of response - use the result field if present
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

// runOneShotClaude runs a one-shot prompt (fallback if streaming doesn't work)
func (env *testEnv) runOneShotClaude(t *testing.T, prompt string) (string, []ToolCall) {
	t.Helper()

	cmd := exec.Command("claude", "-p", prompt,
		"--verbose", // Required for stream-json output
		"--output-format", "stream-json",
		"--mcp-config", env.mcpConfig,
		"--dangerously-skip-permissions") // Allow MCP tool calls without prompts

	output, err := cmd.Output()
	if err != nil {
		t.Logf("claude error: %v", err)
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
			// Parse content blocks from the assistant message
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
			// Use the result field if present and we have no text yet
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

	env := setupTestEnv(t)
	defer env.cleanup()

	// Start streaming conversation
	conv := NewConversation(t, env.mcpConfig)
	defer conv.Close()

	var noteID string

	// Turn 1: Create a note
	t.Run("Turn1_Create", func(t *testing.T) {
		resp, toolCalls := conv.SendMessage(t,
			"Create a note titled 'Team Meeting Notes' with content 'Discussed Q1 roadmap and assigned action items.'")

		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))

		// Verify in DB
		list, err := env.notesSvc.List(100, 0)
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}
		for _, n := range list.Notes {
			if strings.Contains(strings.ToLower(n.Title), "meeting") {
				noteID = n.ID
				break
			}
		}
		if noteID == "" {
			t.Fatal("Note not created")
		}
		t.Logf("Created note: %s", noteID)
	})

	// Turn 2: List notes (same conversation)
	t.Run("Turn2_List", func(t *testing.T) {
		resp, toolCalls := conv.SendMessage(t,
			"List all my notes and tell me how many there are.")

		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))
	})

	// Turn 3: Search notes (same conversation)
	t.Run("Turn3_Search", func(t *testing.T) {
		resp, toolCalls := conv.SendMessage(t,
			"Search for notes containing 'meeting'.")

		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))
	})

	// Turn 4: Update note (same conversation)
	t.Run("Turn4_Update", func(t *testing.T) {
		if noteID == "" {
			t.Skip("No note ID")
		}
		prompt := fmt.Sprintf("Update the note with ID '%s' to add 'Follow-up: Monday' to the content.", noteID)
		resp, toolCalls := conv.SendMessage(t, prompt)

		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))

		// Verify in DB
		note, err := env.notesSvc.Read(noteID)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		t.Logf("Updated content: %s", note.Content)
	})

	// Turn 5: Delete note (same conversation)
	t.Run("Turn5_Delete", func(t *testing.T) {
		if noteID == "" {
			t.Skip("No note ID")
		}
		prompt := fmt.Sprintf("Delete the note with ID '%s'.", noteID)
		resp, toolCalls := conv.SendMessage(t, prompt)

		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))

		// Verify deletion in DB
		_, err := env.notesSvc.Read(noteID)
		if err == nil {
			t.Fatal("Note still exists")
		}
		t.Log("Note deleted successfully")
	})
}

// =============================================================================
// One-shot Tests (fallback)
// =============================================================================

func TestClaude_OneShot_CRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	var noteID string

	// Create
	t.Run("Create", func(t *testing.T) {
		resp, toolCalls := env.runOneShotClaude(t,
			"Create a note titled 'Team Meeting Notes' with content 'Discussed Q1 roadmap.'")
		t.Logf("Response: %s, Tools: %d", resp, len(toolCalls))

		list, _ := env.notesSvc.List(100, 0)
		for _, n := range list.Notes {
			if strings.Contains(strings.ToLower(n.Title), "meeting") {
				noteID = n.ID
				break
			}
		}
		if noteID == "" {
			t.Fatal("Note not created")
		}
	})

	// List
	t.Run("List", func(t *testing.T) {
		resp, toolCalls := env.runOneShotClaude(t, "List all my notes.")
		t.Logf("Response: %s, Tools: %d", resp, len(toolCalls))
	})

	// Search
	t.Run("Search", func(t *testing.T) {
		resp, toolCalls := env.runOneShotClaude(t, "Search for notes about meeting.")
		t.Logf("Response: %s, Tools: %d", resp, len(toolCalls))
	})

	// Update
	t.Run("Update", func(t *testing.T) {
		if noteID == "" {
			t.Skip("No note")
		}
		resp, toolCalls := env.runOneShotClaude(t,
			fmt.Sprintf("Update note %s to add 'Follow-up Monday'.", noteID))
		t.Logf("Response: %s, Tools: %d", resp, len(toolCalls))
	})

	// Delete
	t.Run("Delete", func(t *testing.T) {
		if noteID == "" {
			t.Skip("No note")
		}
		resp, toolCalls := env.runOneShotClaude(t,
			fmt.Sprintf("Delete the note with ID %s.", noteID))
		t.Logf("Response: %s, Tools: %d", resp, len(toolCalls))

		_, err := env.notesSvc.Read(noteID)
		if err == nil {
			t.Fatal("Note still exists")
		}
	})
}
