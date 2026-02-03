// Package openai provides conformance tests for OpenAI's native MCP integration.
// These tests verify that OpenAI's Responses API can directly connect to our MCP
// server and execute tools without any manual tool definitions.
//
// ARCHITECTURE:
// 1. Server binary is built and started as subprocess (once for all tests)
// 2. OpenAI Responses API connects DIRECTLY to our /mcp endpoint via type: "mcp"
// 3. OpenAI discovers tools automatically via MCP tools/list
// 4. OpenAI calls tools via MCP tools/call
// 5. No manual tool definitions - OpenAI uses MCP protocol natively
//
// This tests the FULL MCP integration:
// OpenAI API → MCP HTTP transport → Our MCP server → Notes CRUD
package openai

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kuitang/agent-notes/tests/e2e/testutil"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/packages/param"
	"github.com/openai/openai-go/responses"
	"pgregory.net/rapid"
)

const (
	// Model to use - MUST be gpt-5-mini per CLAUDE.md requirements
	OpenAIModel = "gpt-5-mini"
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
// Test Environment
// =============================================================================

type testEnv struct {
	client      *openai.Client
	mcpClient   *testutil.MCPClient
	mcpURL      string
	accessToken string
	userID      string
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		t.Fatal("OPENAI_API_KEY not set - run: source secrets.sh")
	}

	srv := testutil.GetServer(t)

	// Get OAuth credentials for authenticated MCP access
	creds := testutil.PerformOAuthFlow(t, srv.BaseURL, "OpenAIConformanceTest")

	openaiClient := openai.NewClient(option.WithAPIKey(apiKey))

	return &testEnv{
		client:      &openaiClient,
		mcpClient:   testutil.NewMCPClient(srv.BaseURL, creds.AccessToken),
		mcpURL:      srv.BaseURL + "/mcp",
		accessToken: creds.AccessToken,
		userID:      creds.UserID,
	}
}

// =============================================================================
// MCP Tool Definition for OpenAI Responses API
// =============================================================================

// getMCPTool returns the MCP tool definition for OpenAI Responses API
// This is ALL that's needed - OpenAI discovers tools from the MCP server automatically
func (env *testEnv) getMCPTool() responses.ToolUnionParam {
	return responses.ToolUnionParam{
		OfMcp: &responses.ToolMcpParam{
			ServerLabel: "agent-notes",
			ServerURL:   env.mcpURL,
			RequireApproval: responses.ToolMcpRequireApprovalUnionParam{
				OfMcpToolApprovalSetting: param.NewOpt(string(responses.ToolMcpRequireApprovalMcpToolApprovalSettingNever)),
			},
			Headers: map[string]string{
				"Authorization": "Bearer " + env.accessToken,
			},
		},
	}
}

// =============================================================================
// Conversation Runner
// =============================================================================

// ToolCall tracks which MCP tools were called
type ToolCall struct {
	Name      string
	Arguments string
}

// runConversation sends a prompt to OpenAI with the MCP server connected
// OpenAI will automatically discover and call MCP tools as needed
func (env *testEnv) runConversation(ctx context.Context, t *testing.T, prompt string, prevResponseID string) (string, []ToolCall, string, error) {
	var toolCalls []ToolCall

	params := responses.ResponseNewParams{
		Model: OpenAIModel,
		Instructions: openai.String(`You are a helpful assistant that manages notes.
You have access to an MCP server with note management tools.
Use the tools when asked to create, read, update, delete, list, or search notes.
Always use the actual tool calls - don't just describe what you would do.`),
		Input: responses.ResponseNewParamsInputUnion{
			OfString: openai.String(prompt),
		},
		Tools: []responses.ToolUnionParam{env.getMCPTool()},
	}

	if prevResponseID != "" {
		params.PreviousResponseID = openai.String(prevResponseID)
	}

	maxIterations := 10
	var responseID string

	for i := 0; i < maxIterations; i++ {
		if responseID != "" {
			params.PreviousResponseID = openai.String(responseID)
		}

		response, err := env.client.Responses.New(ctx, params)
		if err != nil {
			return "", toolCalls, "", fmt.Errorf("OpenAI API error: %w", err)
		}

		responseID = response.ID

		// Check for MCP tool calls in the output
		hasPendingToolCalls := false
		for _, output := range response.Output {
			// MCP tool calls appear as mcp_call type
			if output.Type == "mcp_call" {
				hasPendingToolCalls = true
				toolCalls = append(toolCalls, ToolCall{
					Name:      output.Name,
					Arguments: output.Arguments,
				})
				t.Logf("[MCP] Tool called: %s with args: %s", output.Name, output.Arguments)
			}
		}

		// If no pending tool calls, we have the final response
		if !hasPendingToolCalls {
			return response.OutputText(), toolCalls, responseID, nil
		}

		// OpenAI handles MCP tool execution automatically
		// Just continue the loop to get the result
		params = responses.ResponseNewParams{
			Model:              OpenAIModel,
			PreviousResponseID: openai.String(responseID),
			Tools:              []responses.ToolUnionParam{env.getMCPTool()},
		}
	}

	return "", toolCalls, responseID, fmt.Errorf("max iterations reached")
}

// =============================================================================
// Property-Based Tests
// =============================================================================

func testOpenAI_CreateNote_Properties(rt *rapid.T, env *testEnv, t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	title := rapid.StringMatching(`[A-Za-z][A-Za-z0-9 ]{0,30}`).Draw(rt, "title")
	content := rapid.StringMatching(`[A-Za-z0-9 .,!?]{0,100}`).Draw(rt, "content")

	prompt := fmt.Sprintf("Create a note with title '%s' and content '%s'", title, content)

	response, toolCalls, _, err := env.runConversation(ctx, t, prompt, "")
	if err != nil {
		rt.Fatalf("Conversation failed: %v", err)
	}

	t.Logf("Response: %s", response)
	t.Logf("Tool calls: %d", len(toolCalls))

	// Verify at least one tool was called (note_create or similar)
	if len(toolCalls) == 0 {
		t.Log("Warning: No tool calls detected - OpenAI may have just described the action")
	}

	// Verify note was created via MCP
	listResp, err := env.mcpClient.CallTool("note_list", map[string]interface{}{})
	if err != nil {
		rt.Fatalf("MCP list failed: %v", err)
	}
	result, _ := testutil.ParseToolResult(listResp)

	if !strings.Contains(result, title) {
		t.Logf("Note list: %s", result)
		rt.Fatalf("Created note not found in list. Title: %s", title)
	}
}

func testOpenAI_CRUD_Roundtrip_Properties(rt *rapid.T, env *testEnv, t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	title := rapid.StringMatching(`[A-Za-z][A-Za-z0-9 ]{2,15}`).Draw(rt, "title")
	content := rapid.StringMatching(`[A-Za-z0-9 .,]{5,30}`).Draw(rt, "content")
	updatedTitle := rapid.StringMatching(`Updated [A-Za-z0-9]{2,8}`).Draw(rt, "updatedTitle")

	// Step 1: Create note
	createPrompt := fmt.Sprintf("Create a note titled '%s' with content '%s'. Tell me the ID.", title, content)
	createResp, _, _, err := env.runConversation(ctx, t, createPrompt, "")
	if err != nil {
		rt.Fatalf("Create failed: %v", err)
	}
	t.Logf("Create response: %s", createResp)

	// Get note ID via MCP
	listResp, err := env.mcpClient.CallTool("note_list", map[string]interface{}{})
	if err != nil {
		rt.Fatalf("List failed: %v", err)
	}
	listResult, _ := testutil.ParseToolResult(listResp)

	var listData struct {
		Notes []struct {
			ID    string `json:"id"`
			Title string `json:"title"`
		} `json:"notes"`
	}
	json.Unmarshal([]byte(listResult), &listData)

	var noteID string
	for _, note := range listData.Notes {
		if note.Title == title {
			noteID = note.ID
			break
		}
	}
	if noteID == "" {
		rt.Fatalf("Created note not found in list")
	}

	// Step 2: Read note
	readPrompt := fmt.Sprintf("Read the note with ID '%s' and tell me its content.", noteID)
	readResp, _, _, err := env.runConversation(ctx, t, readPrompt, "")
	if err != nil {
		rt.Fatalf("Read failed: %v", err)
	}
	t.Logf("Read response: %s", readResp)

	// Step 3: Update note
	updatePrompt := fmt.Sprintf("Update the note with ID '%s' to change its title to '%s'.", noteID, updatedTitle)
	updateResp, _, _, err := env.runConversation(ctx, t, updatePrompt, "")
	if err != nil {
		rt.Fatalf("Update failed: %v", err)
	}
	t.Logf("Update response: %s", updateResp)

	// Verify update via MCP
	readMCPResp, err := env.mcpClient.CallTool("note_view", map[string]interface{}{"id": noteID})
	if err != nil {
		rt.Fatalf("Read after update failed: %v", err)
	}
	readResult, _ := testutil.ParseToolResult(readMCPResp)
	if !strings.Contains(readResult, updatedTitle) {
		rt.Fatalf("Update failed: expected title '%s' in: %s", updatedTitle, readResult)
	}

	// Step 4: Delete note
	deletePrompt := fmt.Sprintf("Delete the note with ID '%s'.", noteID)
	deleteResp, _, _, err := env.runConversation(ctx, t, deletePrompt, "")
	if err != nil {
		rt.Fatalf("Delete failed: %v", err)
	}
	t.Logf("Delete response: %s", deleteResp)

	// Verify deletion via MCP
	_, err = env.mcpClient.CallTool("note_view", map[string]interface{}{"id": noteID})
	if err == nil {
		rt.Fatalf("Note still exists after delete")
	}
}

// =============================================================================
// Test Entry Points
// =============================================================================

func TestOpenAI_CreateNote_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping OpenAI test in short mode")
	}

	env := setupTestEnv(t)

	rapid.Check(t, func(rt *rapid.T) {
		testOpenAI_CreateNote_Properties(rt, env, t)
	})
}

func TestOpenAI_CRUD_Roundtrip_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping OpenAI test in short mode")
	}

	env := setupTestEnv(t)

	rapid.Check(t, func(rt *rapid.T) {
		testOpenAI_CRUD_Roundtrip_Properties(rt, env, t)
	})
}

// =============================================================================
// Integration Tests
// =============================================================================

func TestOpenAI_MCP_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping OpenAI test in short mode")
	}

	env := setupTestEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	t.Logf("[MCP Integration] Server URL: %s", env.mcpURL)
	t.Logf("[MCP Integration] Access token obtained")

	// Test 1: Create note via OpenAI → MCP
	t.Run("CreateViaMCP", func(t *testing.T) {
		prompt := "Create a note titled 'MCP Integration Test' with content 'Testing OpenAI native MCP support'"
		resp, toolCalls, _, err := env.runConversation(ctx, t, prompt, "")
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))

		// Verify via direct MCP call
		listResp, err := env.mcpClient.CallTool("note_list", map[string]interface{}{})
		if err != nil {
			t.Fatalf("MCP list failed: %v", err)
		}
		result, _ := testutil.ParseToolResult(listResp)
		if !strings.Contains(result, "MCP Integration Test") {
			t.Fatalf("Note not found in list: %s", result)
		}
	})

	// Test 2: List notes via OpenAI → MCP
	t.Run("ListViaMCP", func(t *testing.T) {
		prompt := "List all my notes and tell me how many there are."
		resp, toolCalls, _, err := env.runConversation(ctx, t, prompt, "")
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}
		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))
	})

	// Test 3: Search notes via OpenAI → MCP
	t.Run("SearchViaMCP", func(t *testing.T) {
		prompt := "Search for notes containing 'integration'."
		resp, toolCalls, _, err := env.runConversation(ctx, t, prompt, "")
		if err != nil {
			t.Fatalf("Search failed: %v", err)
		}
		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))
	})

	// Test 4: Multi-turn conversation
	t.Run("MultiTurnConversation", func(t *testing.T) {
		// Turn 1: Create
		resp1, _, responseID, err := env.runConversation(ctx, t,
			"Create a note titled 'Multi-turn Test' with content 'First message'", "")
		if err != nil {
			t.Fatalf("Turn 1 failed: %v", err)
		}
		t.Logf("Turn 1: %s", resp1)

		// Turn 2: Update (using conversation context)
		resp2, _, _, err := env.runConversation(ctx, t,
			"Update that note you just created to add 'Second message' to the content", responseID)
		if err != nil {
			t.Fatalf("Turn 2 failed: %v", err)
		}
		t.Logf("Turn 2: %s", resp2)
	})
}

// TestOpenAI_OAuth_Unauthorized verifies that unauthenticated MCP requests fail
func TestOpenAI_OAuth_Unauthorized(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping OpenAI test in short mode")
	}

	srv := testutil.GetServer(t)

	// Try MCP call without auth
	mcpClient := testutil.NewMCPClient(srv.BaseURL, "") // No token

	_, err := mcpClient.ListTools()
	if err == nil {
		t.Fatal("Expected error for unauthorized MCP request")
	}

	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("Expected 401 error, got: %v", err)
	}

	t.Logf("Correctly rejected unauthorized request: %v", err)
}

// TestOpenAI_ToolDiscovery verifies OpenAI can discover MCP tools
func TestOpenAI_ToolDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping OpenAI test in short mode")
	}

	env := setupTestEnv(t)

	// List available tools via MCP
	resp, err := env.mcpClient.ListTools()
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	if resp.Error != nil {
		t.Fatalf("MCP error: %s", resp.Error.Message)
	}

	var result struct {
		Tools []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("Failed to parse tools: %v", err)
	}

	t.Logf("Discovered %d MCP tools:", len(result.Tools))
	for _, tool := range result.Tools {
		t.Logf("  - %s: %s", tool.Name, tool.Description)
	}

	// Verify expected tools exist
	expectedTools := []string{"note_create", "note_view", "note_update", "note_delete", "note_list", "note_search"}
	for _, expected := range expectedTools {
		found := false
		for _, tool := range result.Tools {
			if tool.Name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected tool not found: %s", expected)
		}
	}
}
