package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/kuitang/agent-notes/internal/apps"
	"github.com/kuitang/agent-notes/internal/errs"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/kuitang/agent-notes/internal/obs"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	ffclient "github.com/thomaspoignant/go-feature-flag"
	"github.com/thomaspoignant/go-feature-flag/ffcontext"
)

const (
	maxAppWriteFilesInput      = 64
	maxAppWritePathBytesInput  = 1024
	maxAppWriteFileBytesInput  = 1 << 20
	maxAppWriteTotalBytesInput = 8 << 20
	maxAppExecArgvBytesInput   = 1 << 20 // 1 MiB — heredocs carry file content in argv now
)

// mcpContextKey is a type for MCP-specific context keys.
type mcpContextKey string

const (
	notesServiceKey mcpContextKey = "notesSvc"
	appsServiceKey  mcpContextKey = "appsSvc"
)

// ContextWithServices returns a context with the per-user notes and apps services injected.
// Tool handlers retrieve these via notesFromContext/appsFromContext.
func ContextWithServices(ctx context.Context, notesSvc *notes.Service, appsSvc *apps.Service) context.Context {
	ctx = context.WithValue(ctx, notesServiceKey, notesSvc)
	ctx = context.WithValue(ctx, appsServiceKey, appsSvc)
	return ctx
}

func notesFromContext(ctx context.Context) *notes.Service {
	svc, _ := ctx.Value(notesServiceKey).(*notes.Service)
	return svc
}

func appsFromContext(ctx context.Context) *apps.Service {
	svc, _ := ctx.Value(appsServiceKey).(*apps.Service)
	return svc
}

// Handler implements MCP tool call handling.
// Services are resolved from context per-request, not stored as fields.
type Handler struct{}

// NewHandler creates a new MCP handler.
// Per-user services are injected via ContextWithServices and resolved from context per-request.
func NewHandler() *Handler {
	return &Handler{}
}

type toolText string

type toolErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// createToolHandler returns a tool handler function for the given tool name.
func (h *Handler) createToolHandler(name string) func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) (result *mcp.CallToolResult, extra any, err error) {
		start := time.Now()
		logger := obs.From(ctx).With("pkg", "internal/mcp")

		reqBytes := len(marshalAny(args))
		errorCode := ""
		ok := false

		defer func() {
			if recovered := recover(); recovered != nil {
				coded := errs.New(errs.Internal, "internal tool panic")
				result = newToolResultError(coded)
				errorCode = string(errs.CodeOf(coded))
			}
			if result == nil {
				coded := errs.New(errs.Internal, "internal tool failure")
				result = newToolResultError(coded)
				errorCode = string(errs.CodeOf(coded))
			}
			respBytes := len(marshalAny(result))
			ok = !result.IsError
			attrs := []any{
				"tool_name", name,
				"dur_ms", float64(time.Since(start).Microseconds()) / 1000.0,
				"ok", ok,
				"req_bytes", reqBytes,
				"resp_bytes", respBytes,
			}
			if errorCode != "" {
				attrs = append(attrs, "error_code", errorCode)
			}
			logger.Debug("mcp_tool", attrs...)
		}()

		payload, callErr := h.HandleToolCall(ctx, name, args)
		if callErr != nil {
			errorCode = string(errs.CodeOf(callErr))
			result = newToolResultError(callErr)
			return result, nil, nil
		}

		switch typed := payload.(type) {
		case toolText:
			result = newToolResultText(string(typed))
		default:
			result = newToolResultText(marshalToolJSON(typed))
		}
		return result, nil, nil
	}
}

// HandleToolCall routes tool calls to appropriate handlers.
func (h *Handler) HandleToolCall(ctx context.Context, name string, arguments map[string]any) (any, error) {
	if name == "app_write" || name == "app_read" {
		bashOnly, _ := ffclient.BoolVariation("BASH_ONLY", ffcontext.NewEvaluationContext("mcp-handlers"), true)
		if bashOnly {
			return nil, errs.New(errs.FailedPrecondition, fmt.Sprintf("%s is temporarily disabled while BASH_ONLY is enabled; use app_exec with tee + stdin instead", name))
		}
	}

	switch name {
	case "note_view":
		return h.handleNoteView(ctx, arguments)
	case "note_create":
		return h.handleNoteCreate(ctx, arguments)
	case "note_update":
		return h.handleNoteUpdate(ctx, arguments)
	case "note_search":
		return h.handleNoteSearch(ctx, arguments)
	case "note_list":
		return h.handleNoteList(ctx, arguments)
	case "note_delete":
		return h.handleNoteDelete(ctx, arguments)
	case "note_edit":
		return h.handleNoteEdit(ctx, arguments)
	case "app_create":
		return h.handleAppCreate(ctx, arguments)
	case "app_write":
		return h.handleAppWrite(ctx, arguments)
	case "app_read":
		return h.handleAppRead(ctx, arguments)
	case "app_exec":
		return h.handleAppExec(ctx, arguments)
	case "app_list":
		return h.handleAppList(ctx)
	case "app_delete":
		return h.handleAppDelete(ctx, arguments)
	default:
		return nil, errs.New(errs.NotFound, fmt.Sprintf("unknown tool: %s", name))
	}
}

func requireNotes(ctx context.Context) (*notes.Service, error) {
	svc := notesFromContext(ctx)
	if svc == nil {
		return nil, errs.New(errs.FailedPrecondition, "notes tools are unavailable on this MCP endpoint")
	}
	return svc, nil
}

func requireApps(ctx context.Context) (*apps.Service, error) {
	svc := appsFromContext(ctx)
	if svc == nil {
		return nil, errs.New(errs.FailedPrecondition, "app tools are unavailable on this MCP endpoint")
	}
	return svc, nil
}

// newToolResultText creates a successful tool result with text content.
func newToolResultText(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
		},
	}
}

func newToolResultError(err error) *mcp.CallToolResult {
	payload := toolErrorPayload{
		Code:    string(errs.CodeOf(err)),
		Message: errs.MessageOf(err),
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: marshalToolJSON(payload)},
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

func marshalAny(value any) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return data
}

func decodeToolArgs(args map[string]any, dst any) error {
	if args == nil {
		args = map[string]any{}
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return errs.Wrap(errs.InvalidArgument, "invalid tool arguments", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errs.New(errs.InvalidArgument, fmt.Sprintf("invalid tool arguments: %v", err))
	}
	return nil
}

func classifyNotesError(err error, action string) error {
	switch {
	case err == nil:
		return nil
	case errs.CodeOf(err) != errs.Internal:
		return err
	case errors.Is(err, notes.ErrNoteNotFound):
		return errs.Wrap(errs.NotFound, err.Error(), err)
	case errors.Is(err, notes.ErrPriorHashRequired),
		errors.Is(err, notes.ErrInvalidPriorHash),
		errors.Is(err, notes.ErrRevisionConflict),
		errors.Is(err, notes.ErrNoMatch),
		errors.Is(err, notes.ErrAmbiguousMatch),
		errors.Is(err, notes.ErrStorageLimitExceeded):
		return errs.Wrap(errs.FailedPrecondition, err.Error(), err)
	default:
		return errs.Wrap(errs.Internal, fmt.Sprintf("failed to %s: %v", action, err), err)
	}
}

func classifyAppsError(err error, action string) error {
	switch {
	case err == nil:
		return nil
	case errs.CodeOf(err) != errs.Internal:
		return err
	case errors.Is(err, apps.ErrAppNotFound):
		return errs.Wrap(errs.NotFound, err.Error(), err)
	default:
		return errs.Wrap(errs.Internal, fmt.Sprintf("failed to %s: %v", action, err), err)
	}
}

type noteViewArgs struct {
	ID        string `json:"id"`
	LineRange []int  `json:"line_range,omitempty"`
}

func (h *Handler) handleNoteView(ctx context.Context, args map[string]any) (any, error) {
	notesSvc, err := requireNotes(ctx)
	if err != nil {
		return nil, err
	}

	var input noteViewArgs
	if err := decodeToolArgs(args, &input); err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.ID) == "" {
		return nil, errs.New(errs.InvalidArgument, "id is required")
	}

	note, err := notesSvc.Read(input.ID)
	if err != nil {
		return nil, classifyNotesError(err, "read note")
	}
	if note.RevisionHash == "" {
		return nil, errs.New(errs.Internal, "failed to read note revision_hash")
	}

	start, end := 0, -1
	if len(input.LineRange) != 0 {
		if len(input.LineRange) != 2 {
			return nil, errs.New(errs.InvalidArgument, "line_range must contain exactly 2 integers")
		}
		start = input.LineRange[0]
		end = input.LineRange[1]
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
	if len(input.LineRange) == 2 {
		result.LineRange = [2]int{start, end}
	}
	return result, nil
}

type noteCreateArgs struct {
	Title   string  `json:"title"`
	Content *string `json:"content,omitempty"`
}

func (h *Handler) handleNoteCreate(ctx context.Context, args map[string]any) (any, error) {
	notesSvc, err := requireNotes(ctx)
	if err != nil {
		return nil, err
	}

	var input noteCreateArgs
	if err := decodeToolArgs(args, &input); err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.Title) == "" {
		return nil, errs.New(errs.InvalidArgument, "title is required")
	}

	content := ""
	if input.Content != nil {
		content = *input.Content
	}

	note, err := notesSvc.Create(notes.CreateNoteParams{
		Title:   input.Title,
		Content: content,
	})
	if err != nil {
		return nil, classifyNotesError(err, "create note")
	}
	if note.RevisionHash == "" {
		return nil, errs.New(errs.Internal, "failed to read created note revision_hash")
	}

	result := notes.NoteCreateResult{
		ID:           note.ID,
		Title:        note.Title,
		TotalLines:   notes.CountLines(note.Content),
		IsPublic:     note.Visibility.IsPublic(),
		CreatedAt:    note.CreatedAt,
		RevisionHash: note.RevisionHash,
	}
	return result, nil
}

type noteUpdateArgs struct {
	ID        string  `json:"id"`
	Title     *string `json:"title,omitempty"`
	Content   *string `json:"content,omitempty"`
	PriorHash string  `json:"prior_hash"`
}

func (h *Handler) handleNoteUpdate(ctx context.Context, args map[string]any) (any, error) {
	notesSvc, err := requireNotes(ctx)
	if err != nil {
		return nil, err
	}

	var input noteUpdateArgs
	if err := decodeToolArgs(args, &input); err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.ID) == "" {
		return nil, errs.New(errs.InvalidArgument, "id is required")
	}
	if strings.TrimSpace(input.PriorHash) == "" {
		return nil, errs.New(errs.FailedPrecondition, "prior_hash is required; call note_view first and pass revision_hash")
	}

	params := notes.UpdateNoteParams{
		Title:     input.Title,
		Content:   input.Content,
		PriorHash: &input.PriorHash,
	}

	note, err := notesSvc.Update(input.ID, params)
	if err != nil {
		return nil, classifyNotesError(err, "update note")
	}
	if note.RevisionHash == "" {
		return nil, errs.New(errs.Internal, "failed to read updated note revision_hash")
	}

	result := notes.NoteUpdateResult{
		ID:           note.ID,
		Title:        note.Title,
		TotalLines:   notes.CountLines(note.Content),
		IsPublic:     note.Visibility.IsPublic(),
		UpdatedAt:    note.UpdatedAt,
		RevisionHash: note.RevisionHash,
	}
	return result, nil
}

type noteSearchArgs struct {
	Query string `json:"query"`
}

func (h *Handler) handleNoteSearch(ctx context.Context, args map[string]any) (any, error) {
	notesSvc, err := requireNotes(ctx)
	if err != nil {
		return nil, err
	}

	var input noteSearchArgs
	if err := decodeToolArgs(args, &input); err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.Query) == "" {
		return nil, errs.New(errs.InvalidArgument, "query is required")
	}

	results, err := notesSvc.SearchWithSnippets(input.Query)
	if err != nil {
		return nil, classifyNotesError(err, "search notes")
	}
	return results, nil
}

type noteListArgs struct {
	Limit  *int `json:"limit,omitempty"`
	Offset *int `json:"offset,omitempty"`
}

func (h *Handler) handleNoteList(ctx context.Context, args map[string]any) (any, error) {
	notesSvc, err := requireNotes(ctx)
	if err != nil {
		return nil, err
	}

	var input noteListArgs
	if err := decodeToolArgs(args, &input); err != nil {
		return nil, err
	}

	limit := 50
	offset := 0
	if input.Limit != nil {
		limit = *input.Limit
	}
	if input.Offset != nil {
		offset = *input.Offset
	}

	results, err := notesSvc.List(limit, offset)
	if err != nil {
		return nil, classifyNotesError(err, "list notes")
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
	return response, nil
}

type noteDeleteArgs struct {
	ID string `json:"id"`
}

func (h *Handler) handleNoteDelete(ctx context.Context, args map[string]any) (any, error) {
	notesSvc, err := requireNotes(ctx)
	if err != nil {
		return nil, err
	}

	var input noteDeleteArgs
	if err := decodeToolArgs(args, &input); err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.ID) == "" {
		return nil, errs.New(errs.InvalidArgument, "id is required")
	}

	if err := notesSvc.Delete(input.ID); err != nil {
		return nil, classifyNotesError(err, "delete note")
	}

	return toolText(fmt.Sprintf("Note %s moved to trash. It will be permanently deleted after 30 days.", input.ID)), nil
}

type noteEditArgs struct {
	ID         string `json:"id"`
	OldString  string `json:"old_string"`
	NewString  string `json:"new_string"`
	ReplaceAll bool   `json:"replace_all,omitempty"`
	PriorHash  string `json:"prior_hash"`
}

func (h *Handler) handleNoteEdit(ctx context.Context, args map[string]any) (any, error) {
	notesSvc, err := requireNotes(ctx)
	if err != nil {
		return nil, err
	}

	var input noteEditArgs
	if err := decodeToolArgs(args, &input); err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.ID) == "" {
		return nil, errs.New(errs.InvalidArgument, "id is required")
	}
	if input.OldString == "" {
		return nil, errs.New(errs.InvalidArgument, "old_string is required")
	}
	if strings.TrimSpace(input.PriorHash) == "" {
		return nil, errs.New(errs.FailedPrecondition, "prior_hash is required; call note_view first and pass revision_hash")
	}

	priorHash := input.PriorHash
	note, meta, err := notesSvc.StrReplace(input.ID, input.OldString, input.NewString, input.ReplaceAll, &priorHash)
	if err != nil {
		return nil, classifyNotesError(err, "edit note")
	}
	if note.RevisionHash == "" {
		return nil, errs.New(errs.Internal, "failed to read edited note revision_hash")
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
	return result, nil
}

type appCreateArgs struct {
	Names []string `json:"names"`
}

func (h *Handler) handleAppCreate(ctx context.Context, args map[string]any) (any, error) {
	appsSvc, err := requireApps(ctx)
	if err != nil {
		return nil, err
	}

	var input appCreateArgs
	if err := decodeToolArgs(args, &input); err != nil {
		return nil, err
	}
	if len(input.Names) == 0 {
		return nil, errs.New(errs.InvalidArgument, "names must be a non-empty array of strings")
	}

	result, err := appsSvc.Create(ctx, input.Names)
	if err != nil {
		return nil, classifyAppsError(err, "create app")
	}
	if !result.Created {
		return nil, errs.New(errs.FailedPrecondition, marshalToolJSON(result))
	}
	return result, nil
}

type appWriteFileArgs struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type appWriteArgs struct {
	App   string             `json:"app"`
	Files []appWriteFileArgs `json:"files"`
}

func (h *Handler) handleAppWrite(ctx context.Context, args map[string]any) (any, error) {
	appsSvc, err := requireApps(ctx)
	if err != nil {
		return nil, err
	}

	var input appWriteArgs
	if err := decodeToolArgs(args, &input); err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.App) == "" {
		return nil, errs.New(errs.InvalidArgument, "app is required")
	}
	if len(input.Files) == 0 {
		return nil, errs.New(errs.InvalidArgument, "files must not be empty")
	}
	if len(input.Files) > maxAppWriteFilesInput {
		return nil, errs.New(errs.InvalidArgument, fmt.Sprintf("files must contain <= %d items", maxAppWriteFilesInput))
	}

	files := make([]apps.AppWriteFileInput, 0, len(input.Files))
	totalBytes := 0
	for i, file := range input.Files {
		if strings.TrimSpace(file.Path) == "" {
			return nil, errs.New(errs.InvalidArgument, fmt.Sprintf("files[%d].path is required", i))
		}
		if len(file.Path) > maxAppWritePathBytesInput {
			return nil, errs.New(errs.InvalidArgument, fmt.Sprintf("files[%d].path must be <= %d bytes", i, maxAppWritePathBytesInput))
		}
		contentBytes := len(file.Content)
		if contentBytes > maxAppWriteFileBytesInput {
			return nil, errs.New(errs.InvalidArgument, fmt.Sprintf("files[%d].content must be <= %d bytes", i, maxAppWriteFileBytesInput))
		}
		totalBytes += contentBytes
		if totalBytes > maxAppWriteTotalBytesInput {
			return nil, errs.New(errs.InvalidArgument, fmt.Sprintf("total file content must be <= %d bytes", maxAppWriteTotalBytesInput))
		}
		files = append(files, apps.AppWriteFileInput{
			Path:    file.Path,
			Content: file.Content,
		})
	}

	result, err := appsSvc.WriteFiles(ctx, input.App, files)
	if err != nil {
		return nil, classifyAppsError(err, "write files")
	}
	return result, nil
}

type appReadFileArgs struct {
	Path string `json:"path"`
}

type appReadArgs struct {
	App   string            `json:"app"`
	Files []appReadFileArgs `json:"files"`
}

func (h *Handler) handleAppRead(ctx context.Context, args map[string]any) (any, error) {
	appsSvc, err := requireApps(ctx)
	if err != nil {
		return nil, err
	}

	var input appReadArgs
	if err := decodeToolArgs(args, &input); err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.App) == "" {
		return nil, errs.New(errs.InvalidArgument, "app is required")
	}
	if len(input.Files) == 0 {
		return nil, errs.New(errs.InvalidArgument, "files must not be empty")
	}
	if len(input.Files) > maxAppWriteFilesInput {
		return nil, errs.New(errs.InvalidArgument, fmt.Sprintf("files must contain <= %d items", maxAppWriteFilesInput))
	}

	paths := make([]string, 0, len(input.Files))
	for i, file := range input.Files {
		if strings.TrimSpace(file.Path) == "" {
			return nil, errs.New(errs.InvalidArgument, fmt.Sprintf("files[%d].path is required", i))
		}
		if len(file.Path) > maxAppWritePathBytesInput {
			return nil, errs.New(errs.InvalidArgument, fmt.Sprintf("files[%d].path must be <= %d bytes", i, maxAppWritePathBytesInput))
		}
		paths = append(paths, file.Path)
	}

	result, err := appsSvc.ReadFiles(ctx, input.App, paths)
	if err != nil {
		return nil, classifyAppsError(err, "read files")
	}
	return result, nil
}

type appExecArgs struct {
	App            string       `json:"app"`
	Command        []string     `json:"command"`
	TimeoutSeconds *json.Number `json:"timeout_seconds,omitempty"`
}

func (h *Handler) handleAppExec(ctx context.Context, args map[string]any) (any, error) {
	appsSvc, err := requireApps(ctx)
	if err != nil {
		return nil, err
	}

	var input appExecArgs
	if err := decodeToolArgs(args, &input); err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.App) == "" {
		return nil, errs.New(errs.InvalidArgument, "app is required")
	}
	if len(input.Command) == 0 {
		return nil, errs.New(errs.InvalidArgument, "command must be a non-empty array")
	}
	argvTotalBytes := 0
	for _, arg := range input.Command {
		argvTotalBytes += len(arg)
	}
	if argvTotalBytes > maxAppExecArgvBytesInput {
		return nil, errs.New(errs.InvalidArgument, fmt.Sprintf("total argv size must be <= %d bytes", maxAppExecArgvBytesInput))
	}

	timeoutSeconds := 0
	if input.TimeoutSeconds != nil {
		parsed, parseErr := input.TimeoutSeconds.Int64()
		if parseErr != nil {
			return nil, errs.New(errs.InvalidArgument, "timeout_seconds must be an integer")
		}
		if parsed < 0 {
			return nil, errs.New(errs.InvalidArgument, "timeout_seconds must be >= 0")
		}
		if parsed > math.MaxInt32 {
			return nil, errs.New(errs.InvalidArgument, "timeout_seconds is too large")
		}
		timeoutSeconds = int(parsed)
	}

	result, err := appsSvc.RunExec(ctx, input.App, input.Command, timeoutSeconds)
	if err != nil {
		return nil, classifyAppsError(err, "run command")
	}
	return result, nil
}

func (h *Handler) handleAppList(ctx context.Context) (any, error) {
	appsSvc, err := requireApps(ctx)
	if err != nil {
		return nil, err
	}

	items, err := appsSvc.List(ctx)
	if err != nil {
		return nil, classifyAppsError(err, "list apps")
	}
	response := struct {
		Apps       []apps.AppMetadata `json:"apps"`
		TotalCount int                `json:"total_count"`
	}{
		Apps:       items,
		TotalCount: len(items),
	}
	return response, nil
}

type appDeleteArgs struct {
	App string `json:"app"`
}

func (h *Handler) handleAppDelete(ctx context.Context, args map[string]any) (any, error) {
	appsSvc, err := requireApps(ctx)
	if err != nil {
		return nil, err
	}

	var input appDeleteArgs
	if err := decodeToolArgs(args, &input); err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.App) == "" {
		return nil, errs.New(errs.InvalidArgument, "app is required")
	}

	result, err := appsSvc.Delete(ctx, input.App)
	if err != nil {
		return nil, classifyAppsError(err, "delete app")
	}
	return result, nil
}
