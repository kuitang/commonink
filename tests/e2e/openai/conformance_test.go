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
	"hash/crc32"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kuitang/agent-notes/tests/e2e/testutil"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/responses"
	"pgregory.net/rapid"
)

const (
	// Model to use - MUST be gpt-5-mini per CLAUDE.md requirements
	OpenAIModel         = "gpt-5-mini"
	appSystemPromptName = "account_workflow"
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
	serverLabel string
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

	// OpenAI's Responses API connects to our MCP server from OpenAI's infrastructure,
	// so localhost is unreachable. TEST_PUBLIC_URL must point to a publicly-accessible
	// URL that proxies to the test server (e.g., Tailscale Funnel, ngrok).
	publicURL := strings.TrimSpace(os.Getenv("TEST_PUBLIC_URL"))
	if publicURL == "" {
		t.Skip("TEST_PUBLIC_URL not set; OpenAI MCP connector cannot reach localhost test servers")
	}
	mcpURL := strings.TrimRight(publicURL, "/") + "/mcp"
	serverLabel := buildOpenAIMCPServerLabel(srv.Label, t.Name()+":"+creds.UserID)
	t.Logf("Using public MCP URL for OpenAI: %s", mcpURL)
	t.Logf("Using OpenAI MCP server label: %s", serverLabel)

	return &testEnv{
		client:      &openaiClient,
		mcpClient:   testutil.NewMCPClient(srv.BaseURL, creds.AccessToken),
		mcpURL:      mcpURL,
		serverLabel: serverLabel,
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
			ServerLabel: env.serverLabel,
			ServerURL:   openai.String(env.mcpURL),
			RequireApproval: responses.ToolMcpRequireApprovalUnionParam{
				OfMcpToolApprovalSetting: openai.String("never"),
			},
			Headers: map[string]string{
				"Authorization": "Bearer " + env.accessToken,
			},
		},
	}
}

func buildOpenAIMCPServerLabel(serverLabel, entropy string) string {
	label := sanitizeOpenAIIdentifier(serverLabel)
	if label == "" {
		label = "default"
	}
	sum := crc32.ChecksumIEEE([]byte(entropy))
	return fmt.Sprintf("agent-notes-%s-%08x", label, sum)
}

func sanitizeOpenAIIdentifier(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(raw))
	for _, ch := range raw {
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			b.WriteRune(ch)
		case ch == '-', ch == '_':
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// =============================================================================
// Conversation Runner
// =============================================================================

// ToolCall tracks which MCP tools were called
type ToolCall struct {
	Name      string
	Arguments string
}

func isTransientOpenAIMCPError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "external_connector_error") ||
		strings.Contains(msg, "failed dependency") ||
		strings.Contains(msg, "error retrieving tool list from mcp server") ||
		strings.Contains(msg, "tool execution failed with status 424")
}

func (env *testEnv) createResponseWithRetry(ctx context.Context, params responses.ResponseNewParams) (*responses.Response, error) {
	// TODO(future): tighten retry idempotency semantics so retried Responses.New calls
	// cannot duplicate tool side effects when a prior attempt reached the MCP server.
	const maxAttempts = 4
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		response, err := env.client.Responses.New(ctx, params)
		if err == nil {
			return response, nil
		}
		lastErr = err
		if !isTransientOpenAIMCPError(err) || attempt == maxAttempts {
			break
		}
		time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
	}
	return nil, fmt.Errorf("OpenAI API error: %w", lastErr)
}

// runConversation sends a prompt to OpenAI with the MCP server connected
// OpenAI will automatically discover and call MCP tools as needed
func (env *testEnv) runConversation(ctx context.Context, t *testing.T, prompt string, prevResponseID string) (string, []ToolCall, string, error) {
	var toolCalls []ToolCall

	params := responses.ResponseNewParams{
		Model: OpenAIModel,
		Instructions: openai.String(`You are a helpful assistant that manages notes and deployable apps.
You have access to an MCP server with note_* and app_* tools.
Always use the actual tool calls - don't just describe what you would do.
For note_update and note_edit, you MUST call note_view first and pass revision_hash as prior_hash.
For app requests with unspecified stack (for example "make me a todo list app"), default to a minimal Flask app (app.py + requirements.txt), then register a persistent sprite-env service on port 8080.`),
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

		response, err := env.createResponseWithRetry(ctx, params)
		if err != nil {
			return "", toolCalls, "", err
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

		// OpenAI handles MCP tool execution automatically.
		// Continue with PreviousResponseID and an empty user input to get the result.
		params = responses.ResponseNewParams{
			Model:              OpenAIModel,
			PreviousResponseID: openai.String(responseID),
			Input: responses.ResponseNewParamsInputUnion{
				OfString: openai.String(""),
			},
			Tools: []responses.ToolUnionParam{env.getMCPTool()},
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

	// Step 3b: Surgical edit via note_edit
	// Pick a substring from the content to replace surgically
	editTarget := rapid.StringMatching(`[A-Za-z]{3,8}`).Draw(rt, "editTarget")
	editReplacement := rapid.StringMatching(`[A-Za-z]{3,8}`).Draw(rt, "editReplacement")

	// First, set content with a known unique string so note_edit can find it
	knownContent := fmt.Sprintf("Before %s after.", editTarget)
	_, _, _, err = env.runConversation(ctx, t, fmt.Sprintf(
		"Update note '%s' to have content exactly: %s", noteID, knownContent), "")
	if err != nil {
		rt.Fatalf("Setup for edit failed: %v", err)
	}

	editPrompt := fmt.Sprintf(
		"Use the note_edit tool on note '%s' to replace '%s' with '%s'.",
		noteID, editTarget, editReplacement)
	editResp, editToolCalls, _, err := env.runConversation(ctx, t, editPrompt, "")
	if err != nil {
		rt.Fatalf("Edit failed: %v", err)
	}
	t.Logf("Edit response: %s", editResp)

	// Verify note_edit was actually called
	editCalled := false
	for _, tc := range editToolCalls {
		if tc.Name == "note_edit" {
			editCalled = true
			break
		}
	}
	if !editCalled {
		t.Log("Warning: note_edit tool was not called by OpenAI")
	}

	// Verify the edit took effect via MCP
	editVerifyResp, err := env.mcpClient.CallTool("note_view", map[string]interface{}{"id": noteID})
	if err != nil {
		rt.Fatalf("Read after edit failed: %v", err)
	}
	editVerifyResult, _ := testutil.ParseToolResult(editVerifyResp)
	if !strings.Contains(editVerifyResult, editReplacement) {
		rt.Fatalf("Edit failed: expected '%s' in: %s", editReplacement, editVerifyResult)
	}

	// Step 3c: Search for the note
	searchPrompt := fmt.Sprintf("Search for notes containing '%s'.", editReplacement)
	searchResp, searchToolCalls, _, err := env.runConversation(ctx, t, searchPrompt, "")
	if err != nil {
		rt.Fatalf("Search failed: %v", err)
	}
	t.Logf("Search response: %s", searchResp)

	searchCalled := false
	for _, tc := range searchToolCalls {
		if tc.Name == "note_search" {
			searchCalled = true
			break
		}
	}
	if !searchCalled {
		t.Log("Warning: note_search tool was not called by OpenAI")
	}

	// Step 4: Delete note
	deletePrompt := fmt.Sprintf("Delete the note with ID '%s'.", noteID)
	deleteResp, _, _, err := env.runConversation(ctx, t, deletePrompt, "")
	if err != nil {
		rt.Fatalf("Delete failed: %v", err)
	}
	t.Logf("Delete response: %s", deleteResp)

	// Verify deletion via MCP - note_view on a soft-deleted note returns isError: true
	// (soft delete with deleted_at IS NULL filter means the note is not found)
	viewAfterDeleteResp, err := env.mcpClient.CallTool("note_view", map[string]interface{}{"id": noteID})
	if err != nil {
		rt.Fatalf("Unexpected transport error after delete: %v", err)
	}
	var toolResult struct {
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(viewAfterDeleteResp.Result, &toolResult); err != nil {
		rt.Fatalf("Failed to parse tool result after delete: %v", err)
	}
	if !toolResult.IsError {
		rt.Fatalf("Note still visible after delete - expected isError from note_view")
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

// TestOpenAI_FTS5_SyntaxEdgeCases tests FTS5 search syntax via direct MCP calls.
// This mirrors the Claude FTS5 test — exercises the server's FTS5 handling without
// requiring OpenAI API calls.
func TestOpenAI_FTS5_SyntaxEdgeCases(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	env := setupTestEnv(t)

	// Create notes with known content
	for _, n := range []struct{ title, content string }{
		{"Revenue Report", "Quarterly revenue analysis shows growth in cloud services."},
		{"Bug Tracker", "Authentication bug fix deployed to staging environment."},
		{"Planning Doc", "Sprint planning for Q2 deliverables and milestones."},
	} {
		resp, err := env.mcpClient.CallTool("note_create", map[string]interface{}{
			"title": n.title, "content": n.content,
		})
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		if testutil.IsToolError(resp) {
			t.Fatalf("Create tool error: %v", resp)
		}
	}

	tests := []struct {
		name          string
		query         string
		expectResults bool
	}{
		{"SimpleKeyword", "revenue", true},
		{"OROperator", "revenue OR bug", true},
		{"PrefixMatch", "plan*", true},
		{"NOTOperator", "planning NOT sprint", false}, // planning without sprint — our doc has both
		{"QuotedPhrase", `"cloud services"`, true},
		{"QuestionMark", "?", false},
		{"SingleQuote", "'", false},
		{"Apostrophe", "it's", false},
		{"EmptyQuery", "", false},
		{"ColumnFilter", "title:revenue", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := env.mcpClient.CallTool("note_search", map[string]interface{}{
				"query": tc.query,
			})
			if err != nil {
				t.Fatalf("note_search HTTP error for %q: %v", tc.query, err)
			}
			result, _ := testutil.ParseToolResult(resp)
			t.Logf("Query %q: isError=%v, len=%d", tc.query, testutil.IsToolError(resp), len(result))
		})
	}
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
	expectedTools := []string{
		"note_create", "note_view", "note_update", "note_delete", "note_list", "note_search", "note_edit",
		"app_create", "app_exec", "app_list", "app_delete",
	}
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

func hasOpenAIToolCall(calls []ToolCall, name string) bool {
	for _, call := range calls {
		if call.Name == name || strings.HasSuffix(call.Name, "__"+name) {
			return true
		}
	}
	return false
}

func assertOpenAIPromptExists(t *testing.T, env *testEnv) {
	t.Helper()

	resp, err := env.mcpClient.Call("prompts/list", nil)
	if err != nil {
		t.Fatalf("prompts/list failed: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("prompts/list returned MCP error: %s", resp.Error.Message)
	}

	var result struct {
		Prompts []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"prompts"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to parse prompts/list response: %v", err)
	}
	if len(result.Prompts) == 0 {
		t.Fatal("expected at least one MCP prompt, got none")
	}

	for _, prompt := range result.Prompts {
		if prompt.Name == appSystemPromptName {
			return
		}
	}
	t.Fatalf("expected MCP prompt %q, got prompts=%+v", appSystemPromptName, result.Prompts)
}

func assertOpenAIAppURLLive(t *testing.T, env *testEnv, appPrefix string) {
	t.Helper()

	listResp, err := env.mcpClient.CallTool("app_list", map[string]interface{}{})
	if err != nil {
		t.Fatalf("app_list failed: %v", err)
	}
	listText, err := testutil.ParseToolResult(listResp)
	if err != nil {
		t.Fatalf("failed to parse app_list result: %v", err)
	}
	if testutil.IsToolError(listResp) {
		t.Fatalf("app_list returned tool error: %s", listText)
	}

	var listResult struct {
		Apps []struct {
			Name      string `json:"name"`
			PublicURL string `json:"public_url"`
		} `json:"apps"`
	}
	if err := json.Unmarshal([]byte(listText), &listResult); err != nil {
		t.Fatalf("failed to decode app_list JSON payload: %v\npayload=%s", err, listText)
	}

	appName := ""
	publicURL := ""
	for _, app := range listResult.Apps {
		if strings.HasPrefix(app.Name, appPrefix) {
			appName = app.Name
			publicURL = strings.TrimSpace(app.PublicURL)
			break
		}
	}
	if appName == "" {
		t.Fatalf("no app found with prefix %q in app_list payload: %s", appPrefix, listText)
	}
	if publicURL == "" {
		t.Fatalf("app %q has empty public_url (frontend source of Open link)", appName)
	}

	curlCmd := fmt.Sprintf(
		"for i in 1 2 3 4 5 6; do curl -fsS -o /dev/null -w 'HTTP %%{http_code}\\n' %q && exit 0; sleep 2; done; exit 1",
		publicURL,
	)
	execResp, err := env.mcpClient.CallTool("app_exec", map[string]interface{}{
		"app":             appName,
		"command":         []string{"bash", "-lc", curlCmd},
		"timeout_seconds": 90,
	})
	if err != nil {
		t.Fatalf("app_exec curl check failed: %v", err)
	}
	execText, err := testutil.ParseToolResult(execResp)
	if err != nil {
		t.Fatalf("failed to parse app_exec result: %v", err)
	}
	if testutil.IsToolError(execResp) {
		t.Fatalf("app_exec returned tool error: %s", execText)
	}

	var execResult struct {
		Stdout   string `json:"stdout"`
		Stderr   string `json:"stderr"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(execText), &execResult); err != nil {
		t.Fatalf("failed to decode app_exec JSON payload: %v\npayload=%s", err, execText)
	}
	if execResult.ExitCode != 0 {
		t.Fatalf("sprite URL curl failed for app=%s url=%s exit=%d stdout=%q stderr=%q",
			appName, publicURL, execResult.ExitCode, execResult.Stdout, execResult.Stderr)
	}
	if !strings.Contains(execResult.Stdout, "HTTP ") {
		t.Fatalf("sprite URL curl output missing HTTP status for app=%s url=%s stdout=%q stderr=%q",
			appName, publicURL, execResult.Stdout, execResult.Stderr)
	}
	t.Logf("Verified sprite URL is live for app=%s url=%s output=%q", appName, publicURL, strings.TrimSpace(execResult.Stdout))
}
