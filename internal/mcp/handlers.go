package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Handler implements MCP tool call handling
type Handler struct {
	notesSvc *notes.Service
}

// NewHandler creates a new MCP handler with the notes service
func NewHandler(notesSvc *notes.Service) *Handler {
	return &Handler{
		notesSvc: notesSvc,
	}
}

// createToolHandler returns a tool handler function for the given tool name
// This matches the signature expected by mcp.AddTool
func (h *Handler) createToolHandler(name string) func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
		result, err := h.HandleToolCall(name, args)
		return result, nil, err
	}
}

// HandleToolCall routes tool calls to appropriate handlers
func (h *Handler) HandleToolCall(name string, arguments map[string]any) (*mcp.CallToolResult, error) {
	switch name {
	case "note_view":
		return h.handleNoteView(arguments)
	case "note_create":
		return h.handleNoteCreate(arguments)
	case "note_update":
		return h.handleNoteUpdate(arguments)
	case "note_search":
		return h.handleNoteSearch(arguments)
	case "note_list":
		return h.handleNoteList(arguments)
	case "note_delete":
		return h.handleNoteDelete(arguments)
	default:
		return newToolResultError(fmt.Sprintf("unknown tool: %s", name)), nil
	}
}

// newToolResultText creates a successful tool result with text content
func newToolResultText(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
		},
	}
}

// newToolResultError creates a tool result indicating an error
func newToolResultError(message string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: message},
		},
		IsError: true,
	}
}

func (h *Handler) handleNoteView(args map[string]any) (*mcp.CallToolResult, error) {
	id, ok := args["id"].(string)
	if !ok {
		return newToolResultError("id must be a string"), nil
	}

	note, err := h.notesSvc.Read(id)
	if err != nil {
		return newToolResultError(fmt.Sprintf("failed to read note: %v", err)), nil
	}

	// Format note as JSON for the response
	noteJSON, err := json.MarshalIndent(note, "", "  ")
	if err != nil {
		return newToolResultError(fmt.Sprintf("failed to format note: %v", err)), nil
	}

	return newToolResultText(string(noteJSON)), nil
}

func (h *Handler) handleNoteCreate(args map[string]any) (*mcp.CallToolResult, error) {
	title, ok := args["title"].(string)
	if !ok {
		return newToolResultError("title must be a string"), nil
	}

	content := ""
	if c, ok := args["content"].(string); ok {
		content = c
	}

	note, err := h.notesSvc.Create(notes.CreateNoteParams{
		Title:   title,
		Content: content,
	})
	if err != nil {
		return newToolResultError(fmt.Sprintf("failed to create note: %v", err)), nil
	}

	noteJSON, err := json.MarshalIndent(note, "", "  ")
	if err != nil {
		return newToolResultError(fmt.Sprintf("failed to format note: %v", err)), nil
	}

	return newToolResultText(string(noteJSON)), nil
}

func (h *Handler) handleNoteUpdate(args map[string]any) (*mcp.CallToolResult, error) {
	id, ok := args["id"].(string)
	if !ok {
		return newToolResultError("id must be a string"), nil
	}

	params := notes.UpdateNoteParams{}

	if title, ok := args["title"].(string); ok {
		params.Title = &title
	}

	if content, ok := args["content"].(string); ok {
		params.Content = &content
	}

	note, err := h.notesSvc.Update(id, params)
	if err != nil {
		return newToolResultError(fmt.Sprintf("failed to update note: %v", err)), nil
	}

	noteJSON, err := json.MarshalIndent(note, "", "  ")
	if err != nil {
		return newToolResultError(fmt.Sprintf("failed to format note: %v", err)), nil
	}

	return newToolResultText(string(noteJSON)), nil
}

func (h *Handler) handleNoteSearch(args map[string]any) (*mcp.CallToolResult, error) {
	query, ok := args["query"].(string)
	if !ok {
		return newToolResultError("query must be a string"), nil
	}

	results, err := h.notesSvc.Search(query)
	if err != nil {
		return newToolResultError(fmt.Sprintf("failed to search notes: %v", err)), nil
	}

	resultsJSON, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return newToolResultError(fmt.Sprintf("failed to format search results: %v", err)), nil
	}

	return newToolResultText(string(resultsJSON)), nil
}

func (h *Handler) handleNoteList(args map[string]any) (*mcp.CallToolResult, error) {
	limit := 50 // default
	offset := 0 // default

	if l, ok := args["limit"].(float64); ok {
		limit = int(l)
	}

	if o, ok := args["offset"].(float64); ok {
		offset = int(o)
	}

	results, err := h.notesSvc.List(limit, offset)
	if err != nil {
		return newToolResultError(fmt.Sprintf("failed to list notes: %v", err)), nil
	}

	resultsJSON, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return newToolResultError(fmt.Sprintf("failed to format note list: %v", err)), nil
	}

	return newToolResultText(string(resultsJSON)), nil
}

func (h *Handler) handleNoteDelete(args map[string]any) (*mcp.CallToolResult, error) {
	id, ok := args["id"].(string)
	if !ok {
		return newToolResultError("id must be a string"), nil
	}

	err := h.notesSvc.Delete(id)
	if err != nil {
		return newToolResultError(fmt.Sprintf("failed to delete note: %v", err)), nil
	}

	return newToolResultText(fmt.Sprintf("Note %s deleted successfully", id)), nil
}
