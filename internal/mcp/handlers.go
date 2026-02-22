package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"strings"

	"github.com/kuitang/agent-notes/internal/apps"
	"github.com/kuitang/agent-notes/internal/logutil"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	maxAppWriteFilesInput       = 64
	maxAppWritePathBytesInput   = 1024
	maxAppWriteFileBytesInput   = 1 << 20
	maxAppWriteTotalBytesInput  = 8 << 20
	maxAppBashCommandBytesInput = 32768
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
	return func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) (result *mcp.CallToolResult, extra any, err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf("[ERROR] MCP tool %s panic recovered: %v", name, recovered)
				result = newToolResultError("internal tool panic")
				extra = nil
				err = nil
			}
		}()

		result, err = h.HandleToolCall(ctx, name, args)
		if err != nil {
			log.Printf("[ERROR] MCP tool %s failed: %v", name, err)
		} else if result != nil && result.IsError {
			log.Printf("[ERROR] MCP tool %s returned error result: %s", name, toolErrorSummary(result))
		}
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

func toolErrorSummary(result *mcp.CallToolResult) string {
	if result == nil {
		return ""
	}
	for _, content := range result.Content {
		text, ok := content.(*mcp.TextContent)
		if !ok {
			continue
		}
		message := strings.TrimSpace(text.Text)
		if message == "" {
			continue
		}
		if len(message) > 512 {
			return message[:512] + "... [truncated]"
		}
		return message
	}
	return "tool returned isError=true without text content"
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
	log.Printf("[MCP][APPS] tool=app_create stage=start")
	if err := h.requireApps(); err != nil {
		log.Printf("[MCP][APPS] tool=app_create stage=reject reason=%q", err.Error())
		return newToolResultError(err.Error()), nil
	}

	namesRaw, ok := args["names"].([]any)
	if !ok || len(namesRaw) == 0 {
		log.Printf("[MCP][APPS] tool=app_create stage=validate status=invalid reason=%q", "names must be a non-empty array of strings")
		return newToolResultError("names must be a non-empty array of strings"), nil
	}
	names := make([]string, 0, len(namesRaw))
	for _, item := range namesRaw {
		name, ok := item.(string)
		if !ok {
			log.Printf("[MCP][APPS] tool=app_create stage=validate status=invalid reason=%q", "names must be a non-empty array of strings")
			return newToolResultError("names must be a non-empty array of strings"), nil
		}
		names = append(names, name)
	}
	log.Printf("[MCP][APPS] tool=app_create stage=validated names_count=%d", len(names))

	log.Printf("[MCP][APPS] tool=app_create stage=service_call")
	result, err := h.appsSvc.Create(ctx, names)
	if err != nil {
		log.Printf("[MCP][APPS] tool=app_create stage=service_call status=error err=%v", err)
		return newToolResultError(fmt.Sprintf("failed to create app: %v", err)), nil
	}
	log.Printf("[MCP][APPS] tool=app_create stage=service_call status=ok created=%t app=%q attempts=%d", result.Created, result.Name, len(result.Attempts))
	payload := marshalToolJSON(result)
	if !result.Created {
		log.Printf("[MCP][APPS] tool=app_create stage=response status=is_error payload=%q", logutil.TruncateForLog(payload, 512))
		return newToolResultError(payload), nil
	}
	log.Printf("[MCP][APPS] tool=app_create stage=response status=ok app=%q", result.Name)
	return newToolResultText(payload), nil
}

func (h *Handler) handleAppWrite(ctx context.Context, args map[string]any) (*mcp.CallToolResult, error) {
	log.Printf("[MCP][APPS] tool=app_write stage=start")
	if err := h.requireApps(); err != nil {
		log.Printf("[MCP][APPS] tool=app_write stage=reject reason=%q", err.Error())
		return newToolResultError(err.Error()), nil
	}

	appName, ok := args["app"].(string)
	if !ok {
		log.Printf("[MCP][APPS] tool=app_write stage=validate status=invalid reason=%q", "app must be a string")
		return newToolResultError("app must be a string"), nil
	}
	rawFiles, ok := args["files"].([]any)
	if !ok {
		log.Printf("[MCP][APPS] tool=app_write stage=validate status=invalid app=%q reason=%q", appName, "files must be an array")
		return newToolResultError("files must be an array"), nil
	}
	if len(rawFiles) == 0 {
		log.Printf("[MCP][APPS] tool=app_write stage=validate status=invalid app=%q reason=%q", appName, "files must not be empty")
		return newToolResultError("files must not be empty"), nil
	}
	if len(rawFiles) > maxAppWriteFilesInput {
		log.Printf("[MCP][APPS] tool=app_write stage=validate status=invalid app=%q reason=%q files=%d", appName, "too many files", len(rawFiles))
		return newToolResultError(fmt.Sprintf("files must contain <= %d items", maxAppWriteFilesInput)), nil
	}

	files := make([]apps.AppWriteFileInput, 0, len(rawFiles))
	totalBytes := 0
	for i, rawFile := range rawFiles {
		fileObj, ok := rawFile.(map[string]any)
		if !ok {
			log.Printf("[MCP][APPS] tool=app_write stage=validate status=invalid app=%q reason=%q index=%d", appName, "each files item must be an object", i)
			return newToolResultError(fmt.Sprintf("files[%d] must be an object", i)), nil
		}
		filePath, ok := fileObj["path"].(string)
		if !ok {
			log.Printf("[MCP][APPS] tool=app_write stage=validate status=invalid app=%q reason=%q index=%d", appName, "path must be a string", i)
			return newToolResultError(fmt.Sprintf("files[%d].path must be a string", i)), nil
		}
		content, ok := fileObj["content"].(string)
		if !ok {
			log.Printf("[MCP][APPS] tool=app_write stage=validate status=invalid app=%q reason=%q index=%d path=%q", appName, "content must be a string", i, filePath)
			return newToolResultError(fmt.Sprintf("files[%d].content must be a string", i)), nil
		}
		if len(filePath) > maxAppWritePathBytesInput {
			log.Printf("[MCP][APPS] tool=app_write stage=validate status=invalid app=%q reason=%q index=%d path=%q", appName, "path too long", i, filePath)
			return newToolResultError(fmt.Sprintf("files[%d].path must be <= %d bytes", i, maxAppWritePathBytesInput)), nil
		}
		contentBytes := len(content)
		if contentBytes > maxAppWriteFileBytesInput {
			log.Printf("[MCP][APPS] tool=app_write stage=validate status=invalid app=%q reason=%q index=%d path=%q bytes=%d", appName, "file too large", i, filePath, contentBytes)
			return newToolResultError(fmt.Sprintf("files[%d].content must be <= %d bytes", i, maxAppWriteFileBytesInput)), nil
		}
		totalBytes += contentBytes
		if totalBytes > maxAppWriteTotalBytesInput {
			log.Printf("[MCP][APPS] tool=app_write stage=validate status=invalid app=%q reason=%q total_bytes=%d", appName, "aggregate content too large", totalBytes)
			return newToolResultError(fmt.Sprintf("total file content must be <= %d bytes", maxAppWriteTotalBytesInput)), nil
		}

		files = append(files, apps.AppWriteFileInput{
			Path:    filePath,
			Content: content,
		})
	}
	log.Printf("[MCP][APPS] tool=app_write stage=validated app=%q files=%d total_bytes=%d", appName, len(files), totalBytes)

	log.Printf("[MCP][APPS] tool=app_write stage=service_call app=%q files=%d", appName, len(files))
	result, err := h.appsSvc.WriteFiles(ctx, appName, files)
	if err != nil {
		log.Printf("[MCP][APPS] tool=app_write stage=service_call status=error app=%q files=%d err=%v", appName, len(files), err)
		return newToolResultError(fmt.Sprintf("failed to write files: %v", err)), nil
	}
	log.Printf("[MCP][APPS] tool=app_write stage=response status=ok app=%q files=%d total_bytes=%d", result.App, result.TotalFilesWritten, result.TotalBytesWritten)
	return newToolResultText(marshalToolJSON(result)), nil
}

func (h *Handler) handleAppRead(ctx context.Context, args map[string]any) (*mcp.CallToolResult, error) {
	log.Printf("[MCP][APPS] tool=app_read stage=start")
	if err := h.requireApps(); err != nil {
		log.Printf("[MCP][APPS] tool=app_read stage=reject reason=%q", err.Error())
		return newToolResultError(err.Error()), nil
	}

	appName, ok := args["app"].(string)
	if !ok {
		log.Printf("[MCP][APPS] tool=app_read stage=validate status=invalid reason=%q", "app must be a string")
		return newToolResultError("app must be a string"), nil
	}
	rawFiles, ok := args["files"].([]any)
	if !ok {
		log.Printf("[MCP][APPS] tool=app_read stage=validate status=invalid app=%q reason=%q", appName, "files must be an array")
		return newToolResultError("files must be an array"), nil
	}
	if len(rawFiles) == 0 {
		log.Printf("[MCP][APPS] tool=app_read stage=validate status=invalid app=%q reason=%q", appName, "files must not be empty")
		return newToolResultError("files must not be empty"), nil
	}
	if len(rawFiles) > maxAppWriteFilesInput {
		log.Printf("[MCP][APPS] tool=app_read stage=validate status=invalid app=%q reason=%q files=%d", appName, "too many files", len(rawFiles))
		return newToolResultError(fmt.Sprintf("files must contain <= %d items", maxAppWriteFilesInput)), nil
	}

	paths := make([]string, 0, len(rawFiles))
	for i, rawFile := range rawFiles {
		fileObj, ok := rawFile.(map[string]any)
		if !ok {
			log.Printf("[MCP][APPS] tool=app_read stage=validate status=invalid app=%q reason=%q index=%d", appName, "each files item must be an object", i)
			return newToolResultError(fmt.Sprintf("files[%d] must be an object", i)), nil
		}
		filePath, ok := fileObj["path"].(string)
		if !ok {
			log.Printf("[MCP][APPS] tool=app_read stage=validate status=invalid app=%q reason=%q index=%d", appName, "path must be a string", i)
			return newToolResultError(fmt.Sprintf("files[%d].path must be a string", i)), nil
		}
		if len(filePath) > maxAppWritePathBytesInput {
			log.Printf("[MCP][APPS] tool=app_read stage=validate status=invalid app=%q reason=%q index=%d path=%q", appName, "path too long", i, filePath)
			return newToolResultError(fmt.Sprintf("files[%d].path must be <= %d bytes", i, maxAppWritePathBytesInput)), nil
		}
		paths = append(paths, filePath)
	}
	log.Printf("[MCP][APPS] tool=app_read stage=validated app=%q files=%d", appName, len(paths))

	log.Printf("[MCP][APPS] tool=app_read stage=service_call app=%q files=%d", appName, len(paths))
	result, err := h.appsSvc.ReadFiles(ctx, appName, paths)
	if err != nil {
		log.Printf("[MCP][APPS] tool=app_read stage=service_call status=error app=%q files=%d err=%v", appName, len(paths), err)
		return newToolResultError(fmt.Sprintf("failed to read files: %v", err)), nil
	}
	log.Printf("[MCP][APPS] tool=app_read stage=response status=ok app=%q files=%d", result.App, len(result.Files))
	return newToolResultText(marshalToolJSON(result)), nil
}

func (h *Handler) handleAppBash(ctx context.Context, args map[string]any) (*mcp.CallToolResult, error) {
	log.Printf("[MCP][APPS] tool=app_bash stage=start")
	if err := h.requireApps(); err != nil {
		log.Printf("[MCP][APPS] tool=app_bash stage=reject reason=%q", err.Error())
		return newToolResultError(err.Error()), nil
	}

	appName, ok := args["app"].(string)
	if !ok {
		log.Printf("[MCP][APPS] tool=app_bash stage=validate status=invalid reason=%q", "app must be a string")
		return newToolResultError("app must be a string"), nil
	}
	command, ok := args["command"].(string)
	if !ok {
		log.Printf("[MCP][APPS] tool=app_bash stage=validate status=invalid app=%q reason=%q", appName, "command must be a string")
		return newToolResultError("command must be a string"), nil
	}
	if len(command) > maxAppBashCommandBytesInput {
		log.Printf("[MCP][APPS] tool=app_bash stage=validate status=invalid app=%q reason=%q command_bytes=%d", appName, "command too long", len(command))
		return newToolResultError(fmt.Sprintf("command must be <= %d bytes", maxAppBashCommandBytesInput)), nil
	}

	timeoutSeconds := 0
	if raw, exists := args["timeout_seconds"]; exists {
		parsed, ok := raw.(float64)
		if !ok {
			log.Printf("[MCP][APPS] tool=app_bash stage=validate status=invalid app=%q reason=%q", appName, "timeout_seconds must be an integer")
			return newToolResultError("timeout_seconds must be an integer"), nil
		}
		if parsed != math.Trunc(parsed) {
			log.Printf("[MCP][APPS] tool=app_bash stage=validate status=invalid app=%q reason=%q value=%v", appName, "timeout_seconds must be a whole number", parsed)
			return newToolResultError("timeout_seconds must be an integer"), nil
		}
		timeoutSeconds = int(parsed)
		if timeoutSeconds < 0 {
			log.Printf("[MCP][APPS] tool=app_bash stage=validate status=invalid app=%q reason=%q value=%d", appName, "timeout_seconds must be >= 0", timeoutSeconds)
			return newToolResultError("timeout_seconds must be >= 0"), nil
		}
	}
	log.Printf("[MCP][APPS] tool=app_bash stage=validated app=%q timeout_seconds=%d command=%q", appName, timeoutSeconds, summarizeCommandForLog(command))

	log.Printf("[MCP][APPS] tool=app_bash stage=service_call app=%q", appName)
	result, err := h.appsSvc.RunBash(ctx, appName, command, timeoutSeconds)
	if err != nil {
		log.Printf("[MCP][APPS] tool=app_bash stage=service_call status=error app=%q err=%v", appName, err)
		return newToolResultError(fmt.Sprintf("failed to run command: %v", err)), nil
	}
	log.Printf("[MCP][APPS] tool=app_bash stage=response status=ok app=%q exit_code=%d runtime_ms=%d port_status=%q stdout_bytes=%d stderr_bytes=%d", appName, result.ExitCode, result.RuntimeMS, result.PortStatus, len(result.Stdout), len(result.Stderr))
	return newToolResultText(marshalToolJSON(result)), nil
}

func (h *Handler) handleAppList(ctx context.Context) (*mcp.CallToolResult, error) {
	log.Printf("[MCP][APPS] tool=app_list stage=start")
	if err := h.requireApps(); err != nil {
		log.Printf("[MCP][APPS] tool=app_list stage=reject reason=%q", err.Error())
		return newToolResultError(err.Error()), nil
	}

	log.Printf("[MCP][APPS] tool=app_list stage=service_call")
	items, err := h.appsSvc.List(ctx)
	if err != nil {
		log.Printf("[MCP][APPS] tool=app_list stage=service_call status=error err=%v", err)
		return newToolResultError(fmt.Sprintf("failed to list apps: %v", err)), nil
	}
	response := struct {
		Apps       []apps.AppMetadata `json:"apps"`
		TotalCount int                `json:"total_count"`
	}{
		Apps:       items,
		TotalCount: len(items),
	}
	log.Printf("[MCP][APPS] tool=app_list stage=response status=ok total_count=%d", response.TotalCount)

	return newToolResultText(marshalToolJSON(response)), nil
}

func (h *Handler) handleAppDelete(ctx context.Context, args map[string]any) (*mcp.CallToolResult, error) {
	log.Printf("[MCP][APPS] tool=app_delete stage=start")
	if err := h.requireApps(); err != nil {
		log.Printf("[MCP][APPS] tool=app_delete stage=reject reason=%q", err.Error())
		return newToolResultError(err.Error()), nil
	}

	appName, ok := args["app"].(string)
	if !ok {
		log.Printf("[MCP][APPS] tool=app_delete stage=validate status=invalid reason=%q", "app must be a string")
		return newToolResultError("app must be a string"), nil
	}
	log.Printf("[MCP][APPS] tool=app_delete stage=validated app=%q", appName)
	log.Printf("[MCP][APPS] tool=app_delete stage=service_call app=%q", appName)
	result, err := h.appsSvc.Delete(ctx, appName)
	if err != nil {
		log.Printf("[MCP][APPS] tool=app_delete stage=service_call status=error app=%q err=%v", appName, err)
		return newToolResultError(fmt.Sprintf("failed to delete app: %v", err)), nil
	}
	log.Printf("[MCP][APPS] tool=app_delete stage=response status=ok app=%q deleted=%t", result.App, result.Deleted)
	return newToolResultText(marshalToolJSON(result)), nil
}

func summarizeCommandForLog(command string) string {
	sum := sha256.Sum256([]byte(command))
	return fmt.Sprintf("len=%d sha256=%x", len(command), sum[:6])
}
