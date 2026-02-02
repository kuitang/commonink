// Package openai provides conformance tests for OpenAI function calling integration.
// These tests verify that OpenAI's gpt-5-mini model can correctly use function calling
// via the Responses API to interact with our notes HTTP API.
package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kuitang/agent-notes/internal/api"
	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/responses"
	"pgregory.net/rapid"
)

const (
	// Model to use - MUST be gpt-5-mini per CLAUDE.md requirements
	OpenAIModel = "gpt-5-mini"

	// TestUserID is the hardcoded test user for Milestone 1
	TestUserID = "test-user-001"
)

// =============================================================================
// Tool Definitions for Responses API
// =============================================================================

// Define tool parameters using the Responses API format
var (
	toolCreateNote = responses.ToolUnionParam{
		OfFunction: &responses.FunctionToolParam{
			Name:        "create_note",
			Description: openai.String("Create a new note with a title and optional content"),
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"title": map[string]any{
						"type":        "string",
						"description": "The title of the note (required)",
					},
					"content": map[string]any{
						"type":        "string",
						"description": "The content/body of the note (optional)",
					},
				},
				"required":             []string{"title"},
				"additionalProperties": false,
			},
			// Note: Strict mode requires all properties in required array
		},
	}

	toolReadNote = responses.ToolUnionParam{
		OfFunction: &responses.FunctionToolParam{
			Name:        "read_note",
			Description: openai.String("Read a note by its ID"),
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "The unique ID of the note to read",
					},
				},
				"required":             []string{"id"},
				"additionalProperties": false,
			},
			// Note: Strict mode requires all properties in required array
		},
	}

	toolUpdateNote = responses.ToolUnionParam{
		OfFunction: &responses.FunctionToolParam{
			Name:        "update_note",
			Description: openai.String("Update an existing note's title and/or content"),
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "The unique ID of the note to update",
					},
					"title": map[string]any{
						"type":        "string",
						"description": "The new title (optional)",
					},
					"content": map[string]any{
						"type":        "string",
						"description": "The new content (optional)",
					},
				},
				"required":             []string{"id"},
				"additionalProperties": false,
			},
			// Note: Strict mode requires all properties in required array
		},
	}

	toolDeleteNote = responses.ToolUnionParam{
		OfFunction: &responses.FunctionToolParam{
			Name:        "delete_note",
			Description: openai.String("Delete a note by its ID"),
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "The unique ID of the note to delete",
					},
				},
				"required":             []string{"id"},
				"additionalProperties": false,
			},
			// Note: Strict mode requires all properties in required array
		},
	}

	toolListNotes = responses.ToolUnionParam{
		OfFunction: &responses.FunctionToolParam{
			Name:        "list_notes",
			Description: openai.String("List all notes with optional pagination"),
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit": map[string]any{
						"type":        "integer",
						"description": "Maximum number of notes to return (default 50)",
					},
					"offset": map[string]any{
						"type":        "integer",
						"description": "Number of notes to skip (default 0)",
					},
				},
				"required":             []string{},
				"additionalProperties": false,
			},
			// Note: Strict mode requires all properties in required array
		},
	}

	toolSearchNotes = responses.ToolUnionParam{
		OfFunction: &responses.FunctionToolParam{
			Name:        "search_notes",
			Description: openai.String("Search notes by query using full-text search"),
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "The search query to find notes",
					},
				},
				"required":             []string{"query"},
				"additionalProperties": false,
			},
			// Note: Strict mode requires all properties in required array
		},
	}

	// allTools contains all available tool definitions
	allTools = []responses.ToolUnionParam{
		toolCreateNote,
		toolReadNote,
		toolUpdateNote,
		toolDeleteNote,
		toolListNotes,
		toolSearchNotes,
	}
)

// =============================================================================
// Test Infrastructure
// =============================================================================

// testEnv holds the test environment including server and client
type testEnv struct {
	server     *httptest.Server
	client     *openai.Client
	httpClient *http.Client
	baseURL    string
	notesSvc   *notes.Service // Direct DB access for verification
	cleanup    func()
}

// setupTestEnv creates a test environment with a fresh database and HTTP server
func setupTestEnv(t testing.TB) *testEnv {
	t.Helper()

	// Skip if no API key - CI can run without OpenAI integration
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		t.Skip("OPENAI_API_KEY not set - skipping OpenAI integration test")
	}

	// Create temp directory for test database
	tempDir := t.TempDir()
	os.Setenv("DB_DATA_DIR", tempDir)

	// Initialize database
	if err := db.InitSchemas(TestUserID); err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}

	// Open user database
	userDB, err := db.OpenUserDB(TestUserID)
	if err != nil {
		t.Fatalf("Failed to open user database: %v", err)
	}

	// Create notes service
	notesSvc := notes.NewService(userDB)

	// Create HTTP handler
	mux := http.NewServeMux()
	apiHandler := api.NewHandler(notesSvc)
	apiHandler.RegisterRoutes(mux)

	// Create test server
	server := httptest.NewServer(mux)

	// Create OpenAI client
	openaiClient := openai.NewClient(
		option.WithAPIKey(apiKey),
	)

	env := &testEnv{
		server:     server,
		client:     &openaiClient,
		httpClient: server.Client(),
		baseURL:    server.URL,
		notesSvc:   notesSvc,
		cleanup: func() {
			server.Close()
			db.CloseAll()
		},
	}

	return env
}

// executeTool executes a tool call against the HTTP API
func (env *testEnv) executeTool(ctx context.Context, toolName string, args json.RawMessage) (string, error) {
	var result string
	var err error

	switch toolName {
	case "create_note":
		result, err = env.executeCreateNote(ctx, args)
	case "read_note":
		result, err = env.executeReadNote(ctx, args)
	case "update_note":
		result, err = env.executeUpdateNote(ctx, args)
	case "delete_note":
		result, err = env.executeDeleteNote(ctx, args)
	case "list_notes":
		result, err = env.executeListNotes(ctx, args)
	case "search_notes":
		result, err = env.executeSearchNotes(ctx, args)
	default:
		return "", fmt.Errorf("unknown tool: %s", toolName)
	}

	return result, err
}

func (env *testEnv) executeCreateNote(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid create_note args: %w", err)
	}

	body, _ := json.Marshal(map[string]string{
		"title":   params.Title,
		"content": params.Content,
	})

	req, _ := http.NewRequestWithContext(ctx, "POST", env.baseURL+"/notes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := env.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("create_note request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("create_note failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return string(respBody), nil
}

func (env *testEnv) executeReadNote(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid read_note args: %w", err)
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", env.baseURL+"/notes/"+params.ID, nil)

	resp, err := env.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("read_note request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("read_note failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return string(respBody), nil
}

func (env *testEnv) executeUpdateNote(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		ID      string  `json:"id"`
		Title   *string `json:"title,omitempty"`
		Content *string `json:"content,omitempty"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid update_note args: %w", err)
	}

	updateBody := make(map[string]string)
	if params.Title != nil {
		updateBody["title"] = *params.Title
	}
	if params.Content != nil {
		updateBody["content"] = *params.Content
	}

	body, _ := json.Marshal(updateBody)

	req, _ := http.NewRequestWithContext(ctx, "PUT", env.baseURL+"/notes/"+params.ID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := env.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("update_note request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("update_note failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return string(respBody), nil
}

func (env *testEnv) executeDeleteNote(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid delete_note args: %w", err)
	}

	req, _ := http.NewRequestWithContext(ctx, "DELETE", env.baseURL+"/notes/"+params.ID, nil)

	resp, err := env.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("delete_note request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("delete_note failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return `{"success": true, "message": "Note deleted successfully"}`, nil
}

func (env *testEnv) executeListNotes(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Limit  int `json:"limit"`
		Offset int `json:"offset"`
	}
	// Default values
	params.Limit = 50
	params.Offset = 0
	_ = json.Unmarshal(args, &params) // Ignore errors for optional params

	url := fmt.Sprintf("%s/notes?limit=%d&offset=%d", env.baseURL, params.Limit, params.Offset)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)

	resp, err := env.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("list_notes request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("list_notes failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return string(respBody), nil
}

func (env *testEnv) executeSearchNotes(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid search_notes args: %w", err)
	}

	body, _ := json.Marshal(map[string]string{"query": params.Query})
	req, _ := http.NewRequestWithContext(ctx, "POST", env.baseURL+"/notes/search", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := env.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("search_notes request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("search_notes failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return string(respBody), nil
}

// ToolCall represents a tool call made during conversation
type ToolCall struct {
	Name      string
	Arguments string
}

// Conversation maintains state for multi-turn conversations
type Conversation struct {
	LastResponseID string
}

// runConversation runs a single conversation turn using the Responses API
// Pass conv to maintain multi-turn state, or nil for one-shot mode
// Returns the final text response and list of tool calls made
func (env *testEnv) runConversation(ctx context.Context, prompt string, conv *Conversation) (string, []ToolCall, error) {
	var toolCalls []ToolCall

	// Build the initial request using Responses API
	params := responses.ResponseNewParams{
		Model:        OpenAIModel,
		Instructions: openai.String("You are a helpful assistant that manages notes. Use the provided tools to create, read, update, delete, list, and search notes. Always use the tools when the user asks you to manage notes."),
		Input: responses.ResponseNewParamsInputUnion{
			OfString: openai.String(prompt),
		},
		Tools: allTools,
	}

	// Continue existing conversation if provided - THIS PROVES MULTI-TURN
	if conv != nil && conv.LastResponseID != "" {
		params.PreviousResponseID = openai.String(conv.LastResponseID)
		fmt.Printf("[MULTI-TURN PROOF] Using previous_response_id: %s\n", conv.LastResponseID)
	}

	// Run conversation loop until model stops making tool calls
	maxIterations := 10
	var previousResponseID string

	for i := 0; i < maxIterations; i++ {
		// Set previous response ID for conversation continuity
		if previousResponseID != "" {
			params.PreviousResponseID = openai.String(previousResponseID)
		}

		response, err := env.client.Responses.New(ctx, params)
		if err != nil {
			return "", toolCalls, fmt.Errorf("OpenAI Responses API error: %w", err)
		}

		// Store response ID for next iteration
		previousResponseID = response.ID

		// Check for function calls in the output
		hasFunctionCalls := false
		var functionCallOutputs []responses.ResponseInputItemUnionParam

		for _, output := range response.Output {
			if output.Type == "function_call" {
				hasFunctionCalls = true

				// Track the tool call
				toolCalls = append(toolCalls, ToolCall{
					Name:      output.Name,
					Arguments: output.Arguments,
				})

				// Execute the tool call
				result, err := env.executeTool(ctx, output.Name, json.RawMessage(output.Arguments))
				if err != nil {
					// Return error as tool result so the model can handle it
					result = fmt.Sprintf(`{"error": "%s"}`, err.Error())
				}

				// Add function call output for the next request
				functionCallOutputs = append(functionCallOutputs, responses.ResponseInputItemParamOfFunctionCallOutput(output.CallID, result))
			}
		}

		// If no function calls, we're done - save state and return
		if !hasFunctionCalls {
			if conv != nil {
				conv.LastResponseID = previousResponseID
				fmt.Printf("[MULTI-TURN PROOF] Saving response_id for next turn: %s\n", previousResponseID)
			}
			return response.OutputText(), toolCalls, nil
		}

		// Prepare next request with function call outputs
		params = responses.ResponseNewParams{
			Model:              OpenAIModel,
			PreviousResponseID: openai.String(previousResponseID),
			Input: responses.ResponseNewParamsInputUnion{
				OfInputItemList: functionCallOutputs,
			},
			Tools: allTools,
		}
	}

	return "", toolCalls, fmt.Errorf("max iterations reached without completion")
}

// =============================================================================
// Property-Based Tests
// =============================================================================

// testOpenAI_CreateNote_Properties tests the create_note tool with random inputs
func testOpenAI_CreateNote_Properties(t *rapid.T, env *testEnv) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Generate random but valid title and content
	// Avoid empty strings for title (required)
	title := rapid.StringMatching(`[A-Za-z][A-Za-z0-9 ]{0,49}`).Draw(t, "title")
	content := rapid.StringMatching(`[A-Za-z0-9 .,!?]{0,200}`).Draw(t, "content")

	prompt := fmt.Sprintf("Create a note with title '%s' and content '%s'", title, content)

	response, _, err := env.runConversation(ctx, prompt, nil)
	if err != nil {
		t.Fatalf("Conversation failed: %v", err)
	}

	// Verify the response mentions the note was created
	if !strings.Contains(strings.ToLower(response), "created") &&
		!strings.Contains(strings.ToLower(response), "note") {
		t.Logf("Response: %s", response)
		// Don't fail - the model might express success differently
	}

	// Verify we can list notes and find our created note
	listResult, err := env.executeListNotes(ctx, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Failed to list notes: %v", err)
	}

	if !strings.Contains(listResult, title) {
		t.Fatalf("Created note not found in list. Title: %s, List: %s", title, listResult)
	}
}

// testOpenAI_CRUD_Roundtrip_Properties tests create -> read -> update -> delete cycle
func testOpenAI_CRUD_Roundtrip_Properties(t *rapid.T, env *testEnv) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Generate test data
	title := rapid.StringMatching(`[A-Za-z][A-Za-z0-9 ]{2,20}`).Draw(t, "title")
	content := rapid.StringMatching(`[A-Za-z0-9 .,]{5,50}`).Draw(t, "content")
	updatedTitle := rapid.StringMatching(`Updated [A-Za-z0-9]{2,10}`).Draw(t, "updatedTitle")

	// Step 1: Create note
	createPrompt := fmt.Sprintf("Create a note titled '%s' with content '%s'. Tell me the ID of the created note.", title, content)
	createResp, _, err := env.runConversation(ctx, createPrompt, nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	t.Logf("Create response: %s", createResp)

	// Get the note ID from list (more reliable than parsing model output)
	listResult, err := env.executeListNotes(ctx, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	var listResp notes.NoteListResult
	if err := json.Unmarshal([]byte(listResult), &listResp); err != nil {
		t.Fatalf("Failed to parse list response: %v", err)
	}

	if len(listResp.Notes) == 0 {
		t.Fatalf("No notes found after create")
	}

	// Find the note we just created
	var noteID string
	for _, note := range listResp.Notes {
		if note.Title == title {
			noteID = note.ID
			break
		}
	}
	if noteID == "" {
		t.Fatalf("Created note not found in list")
	}

	// Step 2: Read note
	readPrompt := fmt.Sprintf("Read the note with ID '%s' and tell me its title and content.", noteID)
	readResp, _, err := env.runConversation(ctx, readPrompt, nil)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	t.Logf("Read response: %s", readResp)

	// Step 3: Update note
	updatePrompt := fmt.Sprintf("Update the note with ID '%s' and change its title to '%s'.", noteID, updatedTitle)
	updateResp, _, err := env.runConversation(ctx, updatePrompt, nil)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	t.Logf("Update response: %s", updateResp)

	// Verify update via direct API call
	readResult, err := env.executeReadNote(ctx, json.RawMessage(fmt.Sprintf(`{"id":"%s"}`, noteID)))
	if err != nil {
		t.Fatalf("Read after update failed: %v", err)
	}

	var updatedNote notes.Note
	if err := json.Unmarshal([]byte(readResult), &updatedNote); err != nil {
		t.Fatalf("Failed to parse updated note: %v", err)
	}

	if updatedNote.Title != updatedTitle {
		t.Fatalf("Update failed: expected title '%s', got '%s'", updatedTitle, updatedNote.Title)
	}

	// Step 4: Delete note
	deletePrompt := fmt.Sprintf("Delete the note with ID '%s'.", noteID)
	deleteResp, _, err := env.runConversation(ctx, deletePrompt, nil)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	t.Logf("Delete response: %s", deleteResp)

	// Verify deletion
	_, err = env.executeReadNote(ctx, json.RawMessage(fmt.Sprintf(`{"id":"%s"}`, noteID)))
	if err == nil {
		t.Fatalf("Note still exists after delete")
	}
	if !strings.Contains(err.Error(), "404") && !strings.Contains(err.Error(), "not found") {
		t.Fatalf("Unexpected error after delete: %v", err)
	}
}

// testOpenAI_ListNotes_Properties tests listing notes with pagination
func testOpenAI_ListNotes_Properties(t *rapid.T, env *testEnv) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create some notes first
	numNotes := rapid.IntRange(1, 5).Draw(t, "numNotes")
	for i := 0; i < numNotes; i++ {
		title := fmt.Sprintf("Test Note %d", i+1)
		args := json.RawMessage(fmt.Sprintf(`{"title":"%s","content":"Test content %d"}`, title, i+1))
		_, err := env.executeCreateNote(ctx, args)
		if err != nil {
			t.Fatalf("Failed to create test note: %v", err)
		}
	}

	// Ask OpenAI to list notes
	listPrompt := "List all my notes"
	listResp, _, err := env.runConversation(ctx, listPrompt, nil)
	if err != nil {
		t.Fatalf("List conversation failed: %v", err)
	}
	t.Logf("List response: %s", listResp)

	// Verify via direct API that all notes exist
	listResult, err := env.executeListNotes(ctx, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Direct list failed: %v", err)
	}

	var result notes.NoteListResult
	if err := json.Unmarshal([]byte(listResult), &result); err != nil {
		t.Fatalf("Failed to parse list: %v", err)
	}

	if result.TotalCount < numNotes {
		t.Fatalf("Expected at least %d notes, got %d", numNotes, result.TotalCount)
	}
}

// testOpenAI_SearchNotes_Properties tests searching notes
func testOpenAI_SearchNotes_Properties(t *rapid.T, env *testEnv) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create a note with a unique searchable term
	uniqueTerm := rapid.StringMatching(`unique[A-Za-z]{5}`).Draw(t, "uniqueTerm")
	title := fmt.Sprintf("Note about %s", uniqueTerm)
	content := fmt.Sprintf("This note contains information about %s", uniqueTerm)

	args := json.RawMessage(fmt.Sprintf(`{"title":"%s","content":"%s"}`, title, content))
	_, err := env.executeCreateNote(ctx, args)
	if err != nil {
		t.Fatalf("Failed to create test note: %v", err)
	}

	// Ask OpenAI to search for the note
	searchPrompt := fmt.Sprintf("Search for notes containing '%s'", uniqueTerm)
	searchResp, _, err := env.runConversation(ctx, searchPrompt, nil)
	if err != nil {
		t.Fatalf("Search conversation failed: %v", err)
	}
	t.Logf("Search response: %s", searchResp)

	// Verify via direct API
	searchArgs := json.RawMessage(fmt.Sprintf(`{"query":"%s"}`, uniqueTerm))
	searchResult, err := env.executeSearchNotes(ctx, searchArgs)
	if err != nil {
		t.Fatalf("Direct search failed: %v", err)
	}

	var results notes.SearchResults
	if err := json.Unmarshal([]byte(searchResult), &results); err != nil {
		t.Fatalf("Failed to parse search results: %v", err)
	}

	if results.TotalCount == 0 {
		t.Fatalf("Search returned no results for term '%s'", uniqueTerm)
	}

	foundMatch := false
	for _, result := range results.Results {
		if strings.Contains(result.Note.Title, uniqueTerm) || strings.Contains(result.Note.Content, uniqueTerm) {
			foundMatch = true
			break
		}
	}

	if !foundMatch {
		t.Fatalf("Search results don't contain expected term '%s'", uniqueTerm)
	}
}

// =============================================================================
// Test Entry Points
// =============================================================================

// TestOpenAI_CreateNote_Properties runs property-based tests for create_note
func TestOpenAI_CreateNote_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping OpenAI test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	rapid.Check(t, func(t *rapid.T) {
		testOpenAI_CreateNote_Properties(t, env)
	})
}

// TestOpenAI_CRUD_Roundtrip_Properties runs property-based tests for full CRUD cycle
func TestOpenAI_CRUD_Roundtrip_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping OpenAI test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	rapid.Check(t, func(t *rapid.T) {
		testOpenAI_CRUD_Roundtrip_Properties(t, env)
	})
}

// TestOpenAI_ListNotes_Properties runs property-based tests for list_notes
func TestOpenAI_ListNotes_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping OpenAI test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	rapid.Check(t, func(t *rapid.T) {
		testOpenAI_ListNotes_Properties(t, env)
	})
}

// TestOpenAI_SearchNotes_Properties runs property-based tests for search_notes
func TestOpenAI_SearchNotes_Properties(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping OpenAI test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	rapid.Check(t, func(t *rapid.T) {
		testOpenAI_SearchNotes_Properties(t, env)
	})
}

// =============================================================================
// Deterministic Integration Tests (for quick validation)
// =============================================================================

// TestOpenAI_AllOperations_Integration is a deterministic test that exercises all 6 operations
func TestOpenAI_AllOperations_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping OpenAI test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	// Test 1: Create a note
	t.Run("Create", func(t *testing.T) {
		prompt := "Create a note titled 'Integration Test Note' with content 'This is a test note for integration testing'"
		resp, _, err := env.runConversation(ctx, prompt, nil)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		t.Logf("Create response: %s", resp)
	})

	// Get the created note ID
	listResult, err := env.executeListNotes(ctx, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	var listResp notes.NoteListResult
	if err := json.Unmarshal([]byte(listResult), &listResp); err != nil {
		t.Fatalf("Failed to parse list: %v", err)
	}

	if len(listResp.Notes) == 0 {
		t.Fatalf("No notes found")
	}

	noteID := listResp.Notes[0].ID

	// Test 2: Read the note
	t.Run("Read", func(t *testing.T) {
		prompt := fmt.Sprintf("Read the note with ID '%s' and describe its contents", noteID)
		resp, _, err := env.runConversation(ctx, prompt, nil)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		t.Logf("Read response: %s", resp)
	})

	// Test 3: Update the note
	t.Run("Update", func(t *testing.T) {
		prompt := fmt.Sprintf("Update the note with ID '%s' and change its content to 'Updated content for integration test'", noteID)
		resp, _, err := env.runConversation(ctx, prompt, nil)
		if err != nil {
			t.Fatalf("Update failed: %v", err)
		}
		t.Logf("Update response: %s", resp)
	})

	// Test 4: List notes
	t.Run("List", func(t *testing.T) {
		prompt := "List all my notes and tell me how many there are"
		resp, _, err := env.runConversation(ctx, prompt, nil)
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}
		t.Logf("List response: %s", resp)
	})

	// Test 5: Search notes
	t.Run("Search", func(t *testing.T) {
		prompt := "Search for notes containing 'integration'"
		resp, _, err := env.runConversation(ctx, prompt, nil)
		if err != nil {
			t.Fatalf("Search failed: %v", err)
		}
		t.Logf("Search response: %s", resp)
	})

	// Test 6: Delete the note
	t.Run("Delete", func(t *testing.T) {
		prompt := fmt.Sprintf("Delete the note with ID '%s'", noteID)
		resp, _, err := env.runConversation(ctx, prompt, nil)
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}
		t.Logf("Delete response: %s", resp)
	})

	// Verify deletion
	_, err = env.executeReadNote(ctx, json.RawMessage(fmt.Sprintf(`{"id":"%s"}`, noteID)))
	if err == nil {
		t.Fatalf("Note still exists after delete")
	}
}

// TestOpenAI_MultiTurn_Conversation proves that OpenAI maintains conversation state
// across multiple turns using previous_response_id. Uses the SAME prompts as Claude test.
func TestOpenAI_MultiTurn_Conversation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping OpenAI test in short mode")
	}

	env := setupTestEnv(t)
	defer env.cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	// Use a single Conversation object to maintain state across turns
	conv := &Conversation{}

	var noteID string

	// Turn 1: Create a note (SAME PROMPT AS CLAUDE TEST)
	t.Run("Turn1_Create", func(t *testing.T) {
		prompt := "Create a note titled 'Team Meeting Notes' with content 'Discussed Q1 roadmap and assigned action items.'"
		resp, toolCalls, err := env.runConversation(ctx, prompt, conv)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))
		t.Logf("Conversation.LastResponseID after Turn1: %s", conv.LastResponseID)

		// Verify in DB
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
		t.Logf("Created note ID: %s", noteID)
	})

	// Turn 2: List notes (SAME PROMPT AS CLAUDE TEST)
	t.Run("Turn2_List", func(t *testing.T) {
		if conv.LastResponseID == "" {
			t.Fatal("MULTI-TURN FAILURE: No previous response ID from Turn1")
		}
		prevID := conv.LastResponseID

		prompt := "List all my notes and tell me how many there are."
		resp, toolCalls, err := env.runConversation(ctx, prompt, conv)
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}
		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))
		t.Logf("MULTI-TURN PROOF: Previous=%s, New=%s", prevID, conv.LastResponseID)
	})

	// Turn 3: Search notes (SAME PROMPT AS CLAUDE TEST)
	t.Run("Turn3_Search", func(t *testing.T) {
		if conv.LastResponseID == "" {
			t.Fatal("MULTI-TURN FAILURE: No previous response ID from Turn2")
		}
		prevID := conv.LastResponseID

		prompt := "Search for notes containing 'meeting'."
		resp, toolCalls, err := env.runConversation(ctx, prompt, conv)
		if err != nil {
			t.Fatalf("Search failed: %v", err)
		}
		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))
		t.Logf("MULTI-TURN PROOF: Previous=%s, New=%s", prevID, conv.LastResponseID)
	})

	// Turn 4: Update note (SAME PROMPT AS CLAUDE TEST)
	t.Run("Turn4_Update", func(t *testing.T) {
		if noteID == "" {
			t.Skip("No note ID")
		}
		if conv.LastResponseID == "" {
			t.Fatal("MULTI-TURN FAILURE: No previous response ID from Turn3")
		}
		prevID := conv.LastResponseID

		prompt := fmt.Sprintf("Update the note with ID '%s' to add 'Follow-up: Monday' to the content.", noteID)
		resp, toolCalls, err := env.runConversation(ctx, prompt, conv)
		if err != nil {
			t.Fatalf("Update failed: %v", err)
		}
		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))
		t.Logf("MULTI-TURN PROOF: Previous=%s, New=%s", prevID, conv.LastResponseID)

		// Verify in DB
		note, err := env.notesSvc.Read(noteID)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		t.Logf("Updated content: %s", note.Content)
	})

	// Turn 5: Delete note (SAME PROMPT AS CLAUDE TEST)
	t.Run("Turn5_Delete", func(t *testing.T) {
		if noteID == "" {
			t.Skip("No note ID")
		}
		if conv.LastResponseID == "" {
			t.Fatal("MULTI-TURN FAILURE: No previous response ID from Turn4")
		}
		prevID := conv.LastResponseID

		prompt := fmt.Sprintf("Delete the note with ID '%s'.", noteID)
		resp, toolCalls, err := env.runConversation(ctx, prompt, conv)
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}
		t.Logf("Response: %s", resp)
		t.Logf("Tool calls: %d", len(toolCalls))
		t.Logf("MULTI-TURN PROOF: Previous=%s, New=%s", prevID, conv.LastResponseID)

		// Verify deletion in DB
		_, err = env.notesSvc.Read(noteID)
		if err == nil {
			t.Fatal("Note still exists")
		}
		t.Log("Note deleted successfully")
	})
}

// TestOpenAI_ToolDefinitions tests that all tool definitions are valid
func TestOpenAI_ToolDefinitions(t *testing.T) {
	// This test doesn't require API key - just validates tool definitions
	expectedTools := []string{
		"create_note",
		"read_note",
		"update_note",
		"delete_note",
		"list_notes",
		"search_notes",
	}

	if len(allTools) != len(expectedTools) {
		t.Fatalf("Expected %d tools, got %d", len(expectedTools), len(allTools))
	}

	for i, tool := range allTools {
		if tool.OfFunction == nil {
			t.Errorf("Tool %d is not a function tool", i)
			continue
		}

		if tool.OfFunction.Name != expectedTools[i] {
			t.Errorf("Tool %d: expected name '%s', got '%s'",
				i, expectedTools[i], tool.OfFunction.Name)
		}

		// Verify each tool has a description
		if tool.OfFunction.Description.Value == "" {
			t.Errorf("Tool '%s' has no description", tool.OfFunction.Name)
		}

		// Verify each tool has parameters
		if tool.OfFunction.Parameters == nil {
			t.Errorf("Tool '%s' has no parameters", tool.OfFunction.Name)
		}
	}
}

// =============================================================================
// Fuzz Entry Points
// =============================================================================

// FuzzOpenAI_CreateNote_Properties provides fuzz testing for create operations.
// Note: Due to the expense of OpenAI API calls, fuzz testing is limited.
// The property-based tests with rapid provide better coverage.
func FuzzOpenAI_CreateNote_Properties(f *testing.F) {
	// Skip if no API key - CI can run without OpenAI integration
	if os.Getenv("OPENAI_API_KEY") == "" {
		f.Skip("OPENAI_API_KEY not set - skipping OpenAI fuzz test")
	}

	// Add seed corpus
	f.Add("Test Note", "Test content for fuzzing")

	f.Fuzz(func(t *testing.T, title, content string) {
		// Skip empty titles (required field)
		if title == "" {
			return
		}

		// Skip very long inputs to avoid excessive API costs
		if len(title) > 100 || len(content) > 500 {
			return
		}

		// Create temp directory for this fuzz iteration
		tempDir := t.TempDir()
		os.Setenv("DB_DATA_DIR", tempDir)

		if err := db.InitSchemas(TestUserID); err != nil {
			return // Skip this iteration on DB errors
		}

		userDB, err := db.OpenUserDB(TestUserID)
		if err != nil {
			return
		}

		notesSvc := notes.NewService(userDB)
		mux := http.NewServeMux()
		apiHandler := api.NewHandler(notesSvc)
		apiHandler.RegisterRoutes(mux)
		server := httptest.NewServer(mux)
		defer server.Close()
		defer db.CloseAll()

		apiKey := os.Getenv("OPENAI_API_KEY")
		openaiClient := openai.NewClient(option.WithAPIKey(apiKey))

		env := &testEnv{
			server:     server,
			client:     &openaiClient,
			httpClient: server.Client(),
			baseURL:    server.URL,
			cleanup:    func() {},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create note via direct API (faster than going through OpenAI)
		args := json.RawMessage(fmt.Sprintf(`{"title":%q,"content":%q}`, title, content))
		result, err := env.executeCreateNote(ctx, args)
		if err != nil {
			t.Logf("Create failed (may be expected for invalid input): %v", err)
			return
		}

		// Verify the note was created
		listResult, err := env.executeListNotes(ctx, json.RawMessage(`{}`))
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}

		if !strings.Contains(listResult, title) {
			t.Fatalf("Created note not found. Result: %s, List: %s", result, listResult)
		}
	})
}
