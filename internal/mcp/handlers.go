package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kuitang/agent-notes/internal/apps"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Handler implements MCP tool call handling.
type Handler struct {
	notesSvc *notes.Service
	appsSvc  *apps.Service
}

// NewHandler creates a new MCP handler with notes/apps services.
func NewHandler(notesSvc *notes.Service, appsSvc *apps.Service) *Handler {
	return &Handler{
		notesSvc: notesSvc,
		appsSvc:  appsSvc,
	}
}

// createToolHandler returns a tool handler function for the given tool name.
func (h *Handler) createToolHandler(name string) func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
		result, err := h.HandleToolCall(ctx, name, args)
		return result, nil, err
	}
}

// HandleToolCall routes tool calls to appropriate handlers.
func (h *Handler) HandleToolCall(ctx context.Context, name string, arguments map[string]any) (*mcp.CallToolResult, error) {
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
	case "note_edit":
		return h.handleNoteEdit(arguments)
	case "app_create":
		return h.handleAppCreate(ctx, arguments)
	case "app_write":
		return h.handleAppWrite(ctx, arguments)
	case "app_read":
		return h.handleAppRead(ctx, arguments)
	case "app_bash":
		return h.handleAppBash(ctx, arguments)
	case "app_list":
		return h.handleAppList(ctx)
	case "app_delete":
		return h.handleAppDelete(ctx, arguments)
	default:
		return newToolResultError(fmt.Sprintf("unknown tool: %s", name)), nil
	}
}

func (h *Handler) requireNotes() error {
	if h.notesSvc == nil {
		return errors.New("notes tools are unavailable on this MCP endpoint")
	}
	return nil
}

func (h *Handler) requireApps() error {
	if h.appsSvc == nil {
		return errors.New("app tools are unavailable on this MCP endpoint")
	}
	return nil
}

// newToolResultText creates a successful tool result with text content.
func newToolResultText(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
		},
	}
}

// newToolResultError creates a tool result indicating an error.
func newToolResultError(message string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: message},
		},
		IsError: true,
	}
}

func marshalToolJSON(value any) string {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error":"failed to marshal response","detail":%q}`, err.Error())
	}
	return string(data)
}

func (h *Handler) handleNoteView(args map[string]any) (*mcp.CallToolResult, error) {
	if err := h.requireNotes(); err != nil {
		return newToolResultError(err.Error()), nil
	}

	id, ok := args["id"].(string)
	if !ok {
		return newToolResultError("id must be a string"), nil
	}

	note, err := h.notesSvc.Read(id)
	if err != nil {
		return newToolResultError(fmt.Sprintf("failed to read note: %v", err)), nil
	}
	if note.RevisionHash == "" {
		return newToolResultError("failed to read note revision_hash"), nil
	}

	start, end := 0, -1
	if lr, ok := args["line_range"].([]any); ok && len(lr) == 2 {
		if s, ok := lr[0].(float64); ok {
			start = int(s)
		}
		if e, ok := lr[1].(float64); ok {
			end = int(e)
		}
	}

	formatted, totalLines := notes.FormatWithLineNumbers(note.Content, start, end)
	result := notes.NoteViewResult{
		ID:           note.ID,
		Title:        note.Title,
		Content:      formatted,
		TotalLines:   totalLines,
		IsPublic:     note.Visibility.IsPublic(),
		CreatedAt:    note.CreatedAt,
		UpdatedAt:    note.UpdatedAt,
		RevisionHash: note.RevisionHash,
	}
	if start > 0 || end > 0 {
		result.LineRange = [2]int{start, end}
	}

	return newToolResultText(marshalToolJSON(result)), nil
}

func (h *Handler) handleNoteCreate(args map[string]any) (*mcp.CallToolResult, error) {
	if err := h.requireNotes(); err != nil {
		return newToolResultError(err.Error()), nil
	}

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
		if errors.Is(err, notes.ErrStorageLimitExceeded) {
			return newToolResultError(fmt.Sprintf("storage limit exceeded: %v", err)), nil
		}
		return newToolResultError(fmt.Sprintf("failed to create note: %v", err)), nil
	}
	if note.RevisionHash == "" {
		return newToolResultError("failed to read created note revision_hash"), nil
	}

	result := notes.NoteCreateResult{
		ID:           note.ID,
		Title:        note.Title,
		TotalLines:   notes.CountLines(note.Content),
		IsPublic:     note.Visibility.IsPublic(),
		CreatedAt:    note.CreatedAt,
		RevisionHash: note.RevisionHash,
	}

	return newToolResultText(marshalToolJSON(result)), nil
}

func (h *Handler) handleNoteUpdate(args map[string]any) (*mcp.CallToolResult, error) {
	if err := h.requireNotes(); err != nil {
		return newToolResultError(err.Error()), nil
	}

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

	priorHashRaw, exists := args["prior_hash"]
	if !exists {
		return newToolResultError("prior_hash is required; call note_view first and pass revision_hash"), nil
	}
	priorHash, ok := priorHashRaw.(string)
	if !ok {
		return newToolResultError("prior_hash must be a string"), nil
	}
	params.PriorHash = &priorHash

	note, err := h.notesSvc.Update(id, params)
	if err != nil {
		if errors.Is(err, notes.ErrPriorHashRequired) || errors.Is(err, notes.ErrInvalidPriorHash) || errors.Is(err, notes.ErrRevisionConflict) {
			return newToolResultError(err.Error()), nil
		}
		if errors.Is(err, notes.ErrStorageLimitExceeded) {
			return newToolResultError(fmt.Sprintf("storage limit exceeded: %v", err)), nil
		}
		return newToolResultError(fmt.Sprintf("failed to update note: %v", err)), nil
	}
	if note.RevisionHash == "" {
		return newToolResultError("failed to read updated note revision_hash"), nil
	}

	result := notes.NoteUpdateResult{
		ID:           note.ID,
		Title:        note.Title,
		TotalLines:   notes.CountLines(note.Content),
		IsPublic:     note.Visibility.IsPublic(),
		UpdatedAt:    note.UpdatedAt,
		RevisionHash: note.RevisionHash,
	}

	return newToolResultText(marshalToolJSON(result)), nil
}

func (h *Handler) handleNoteSearch(args map[string]any) (*mcp.CallToolResult, error) {
	if err := h.requireNotes(); err != nil {
		return newToolResultError(err.Error()), nil
	}

	query, ok := args["query"].(string)
	if !ok {
		return newToolResultError("query must be a string"), nil
	}

	results, err := h.notesSvc.SearchWithSnippets(query)
	if err != nil {
		return newToolResultError(fmt.Sprintf("failed to search notes: %v", err)), nil
	}

	return newToolResultText(marshalToolJSON(results)), nil
}

func (h *Handler) handleNoteList(args map[string]any) (*mcp.CallToolResult, error) {
	if err := h.requireNotes(); err != nil {
		return newToolResultError(err.Error()), nil
	}

	limit := 50
	offset := 0
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

	items := make([]notes.NoteListItem, 0, len(results.Notes))
	for _, n := range results.Notes {
		items = append(items, notes.NoteListItem{
			ID:         n.ID,
			Title:      n.Title,
			Preview:    notes.ContentPreview(n.Content, 2),
			TotalLines: notes.CountLines(n.Content),
			IsPublic:   n.Visibility.IsPublic(),
			CreatedAt:  n.CreatedAt,
			UpdatedAt:  n.UpdatedAt,
		})
	}

	response := struct {
		Notes      []notes.NoteListItem `json:"notes"`
		TotalCount int                  `json:"total_count"`
		Limit      int                  `json:"limit"`
		Offset     int                  `json:"offset"`
	}{
		Notes:      items,
		TotalCount: results.TotalCount,
		Limit:      results.Limit,
		Offset:     results.Offset,
	}

	return newToolResultText(marshalToolJSON(response)), nil
}

func (h *Handler) handleNoteDelete(args map[string]any) (*mcp.CallToolResult, error) {
	if err := h.requireNotes(); err != nil {
		return newToolResultError(err.Error()), nil
	}

	id, ok := args["id"].(string)
	if !ok {
		return newToolResultError("id must be a string"), nil
	}
	if err := h.notesSvc.Delete(id); err != nil {
		return newToolResultError(fmt.Sprintf("failed to delete note: %v", err)), nil
	}

	return newToolResultText(fmt.Sprintf("Note %s moved to trash. It will be permanently deleted after 30 days.", id)), nil
}

func (h *Handler) handleNoteEdit(args map[string]any) (*mcp.CallToolResult, error) {
	if err := h.requireNotes(); err != nil {
		return newToolResultError(err.Error()), nil
	}

	id, ok := args["id"].(string)
	if !ok {
		return newToolResultError("id must be a string"), nil
	}
	oldStr, ok := args["old_string"].(string)
	if !ok {
		return newToolResultError("old_string must be a string"), nil
	}
	newStr, ok := args["new_string"].(string)
	if !ok {
		return newToolResultError("new_string must be a string"), nil
	}

	replaceAll := false
	if replaceAllRaw, exists := args["replace_all"]; exists {
		parsed, ok := replaceAllRaw.(bool)
		if !ok {
			return newToolResultError("replace_all must be a boolean"), nil
		}
		replaceAll = parsed
	}

	priorHashRaw, exists := args["prior_hash"]
	if !exists {
		return newToolResultError("prior_hash is required; call note_view first and pass revision_hash"), nil
	}
	parsed, ok := priorHashRaw.(string)
	if !ok {
		return newToolResultError("prior_hash must be a string"), nil
	}
	priorHash := &parsed

	note, meta, err := h.notesSvc.StrReplace(id, oldStr, newStr, replaceAll, priorHash)
	if err != nil {
		if errors.Is(err, notes.ErrNoMatch) || errors.Is(err, notes.ErrAmbiguousMatch) ||
			errors.Is(err, notes.ErrPriorHashRequired) || errors.Is(err, notes.ErrInvalidPriorHash) || errors.Is(err, notes.ErrRevisionConflict) {
			return newToolResultError(err.Error()), nil
		}
		if errors.Is(err, notes.ErrStorageLimitExceeded) {
			return newToolResultError(fmt.Sprintf("storage limit exceeded: %v", err)), nil
		}
		return newToolResultError(fmt.Sprintf("failed to edit note: %v", err)), nil
	}
	if note.RevisionHash == "" {
		return newToolResultError("failed to read edited note revision_hash"), nil
	}

	totalLines := notes.CountLines(note.Content)
	snippet, startLine, endLine := notes.SnippetAroundByteOffset(note.Content, meta.FirstMatchByteOffset, 4)
	result := notes.NoteEditResult{
		ID:               note.ID,
		Title:            note.Title,
		TotalLines:       totalLines,
		Snippet:          snippet,
		SnippetLineRange: [2]int{startLine, endLine},
		ReplacementsMade: meta.ReplacementsMade,
		IsPublic:         note.Visibility.IsPublic(),
		UpdatedAt:        note.UpdatedAt,
		RevisionHash:     note.RevisionHash,
	}

	return newToolResultText(marshalToolJSON(result)), nil
}

func (h *Handler) handleAppCreate(ctx context.Context, args map[string]any) (*mcp.CallToolResult, error) {
	if err := h.requireApps(); err != nil {
		return newToolResultError(err.Error()), nil
	}

	namesRaw, ok := args["names"].([]any)
	if !ok || len(namesRaw) == 0 {
		return newToolResultError("names must be a non-empty array of strings"), nil
	}
	names := make([]string, 0, len(namesRaw))
	for _, item := range namesRaw {
		name, ok := item.(string)
		if !ok {
			return newToolResultError("names must be a non-empty array of strings"), nil
		}
		names = append(names, name)
	}

	result, err := h.appsSvc.Create(ctx, names)
	if err != nil {
		return newToolResultError(fmt.Sprintf("failed to create app: %v", err)), nil
	}
	payload := marshalToolJSON(result)
	if !result.Created {
		return newToolResultError(payload), nil
	}
	return newToolResultText(payload), nil
}

func (h *Handler) handleAppWrite(ctx context.Context, args map[string]any) (*mcp.CallToolResult, error) {
	if err := h.requireApps(); err != nil {
		return newToolResultError(err.Error()), nil
	}

	appName, ok := args["app"].(string)
	if !ok {
		return newToolResultError("app must be a string"), nil
	}
	filePath, ok := args["path"].(string)
	if !ok {
		return newToolResultError("path must be a string"), nil
	}
	content, ok := args["content"].(string)
	if !ok {
		return newToolResultError("content must be a string"), nil
	}

	result, err := h.appsSvc.WriteFile(ctx, appName, filePath, content)
	if err != nil {
		return newToolResultError(fmt.Sprintf("failed to write file: %v", err)), nil
	}
	return newToolResultText(marshalToolJSON(result)), nil
}

func (h *Handler) handleAppRead(ctx context.Context, args map[string]any) (*mcp.CallToolResult, error) {
	if err := h.requireApps(); err != nil {
		return newToolResultError(err.Error()), nil
	}

	appName, ok := args["app"].(string)
	if !ok {
		return newToolResultError("app must be a string"), nil
	}
	filePath, ok := args["path"].(string)
	if !ok {
		return newToolResultError("path must be a string"), nil
	}

	result, err := h.appsSvc.ReadFile(ctx, appName, filePath)
	if err != nil {
		return newToolResultError(fmt.Sprintf("failed to read file: %v", err)), nil
	}
	return newToolResultText(marshalToolJSON(result)), nil
}

func (h *Handler) handleAppBash(ctx context.Context, args map[string]any) (*mcp.CallToolResult, error) {
	if err := h.requireApps(); err != nil {
		return newToolResultError(err.Error()), nil
	}

	appName, ok := args["app"].(string)
	if !ok {
		return newToolResultError("app must be a string"), nil
	}
	command, ok := args["command"].(string)
	if !ok {
		return newToolResultError("command must be a string"), nil
	}

	timeoutSeconds := 0
	if raw, exists := args["timeout_seconds"]; exists {
		parsed, ok := raw.(float64)
		if !ok {
			return newToolResultError("timeout_seconds must be an integer"), nil
		}
		timeoutSeconds = int(parsed)
	}

	result, err := h.appsSvc.RunBash(ctx, appName, command, timeoutSeconds)
	if err != nil {
		return newToolResultError(fmt.Sprintf("failed to run command: %v", err)), nil
	}
	return newToolResultText(marshalToolJSON(result)), nil
}

func (h *Handler) handleAppList(ctx context.Context) (*mcp.CallToolResult, error) {
	if err := h.requireApps(); err != nil {
		return newToolResultError(err.Error()), nil
	}

	items, err := h.appsSvc.List(ctx)
	if err != nil {
		return newToolResultError(fmt.Sprintf("failed to list apps: %v", err)), nil
	}
	response := struct {
		Apps       []apps.AppMetadata `json:"apps"`
		TotalCount int                `json:"total_count"`
	}{
		Apps:       items,
		TotalCount: len(items),
	}

	return newToolResultText(marshalToolJSON(response)), nil
}

func (h *Handler) handleAppDelete(ctx context.Context, args map[string]any) (*mcp.CallToolResult, error) {
	if err := h.requireApps(); err != nil {
		return newToolResultError(err.Error()), nil
	}

	appName, ok := args["app"].(string)
	if !ok {
		return newToolResultError("app must be a string"), nil
	}
	result, err := h.appsSvc.Delete(ctx, appName)
	if err != nil {
		return newToolResultError(fmt.Sprintf("failed to delete app: %v", err)), nil
	}
	return newToolResultText(marshalToolJSON(result)), nil
}
