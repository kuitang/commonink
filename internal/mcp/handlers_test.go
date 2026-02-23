package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kuitang/agent-notes/internal/apps"
	"github.com/kuitang/agent-notes/internal/errs"
	"github.com/kuitang/agent-notes/internal/notes"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"pgregory.net/rapid"
)

func toolResultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if result == nil || len(result.Content) == 0 {
		t.Fatalf("missing tool result content: %#v", result)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("unexpected content type: %T", result.Content[0])
	}
	return text.Text
}

func parseToolErrorPayload(t *testing.T, result *mcp.CallToolResult) toolErrorPayload {
	t.Helper()
	raw := toolResultText(t, result)
	var payload toolErrorPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("invalid tool error payload JSON: %v body=%q", err, raw)
	}
	return payload
}

func testDecodeToolArgs_UnknownFieldsRejected(t *rapid.T) {
	var decoded struct {
		ID string `json:"id"`
	}
	err := decodeToolArgs(map[string]any{
		"id":    "note-1",
		"extra": "unexpected",
	}, &decoded)
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
	if got := errs.CodeOf(err); got != errs.InvalidArgument {
		t.Fatalf("unexpected error code: got=%q want=%q", got, errs.InvalidArgument)
	}
}

func TestDecodeToolArgs_UnknownFieldsRejected(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testDecodeToolArgs_UnknownFieldsRejected)
}

func testDecodeToolArgs_NilMapBehavesAsEmptyObject(t *rapid.T) {
	var decoded struct {
		Optional string `json:"optional,omitempty"`
	}
	if err := decodeToolArgs(nil, &decoded); err != nil {
		t.Fatalf("decodeToolArgs(nil) failed: %v", err)
	}
}

func TestDecodeToolArgs_NilMapBehavesAsEmptyObject(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testDecodeToolArgs_NilMapBehavesAsEmptyObject)
}

func testClassifyNotesError_MapsKnownSentinels(t *rapid.T) {
	known := rapid.SampledFrom([]error{
		notes.ErrPriorHashRequired,
		notes.ErrInvalidPriorHash,
		notes.ErrRevisionConflict,
		notes.ErrNoMatch,
		notes.ErrAmbiguousMatch,
		notes.ErrStorageLimitExceeded,
	}).Draw(t, "known")

	err := classifyNotesError(known, "update note")
	if got := errs.CodeOf(err); got != errs.FailedPrecondition {
		t.Fatalf("unexpected notes error code: got=%q want=%q", got, errs.FailedPrecondition)
	}
}

func TestClassifyNotesError_MapsKnownSentinels(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testClassifyNotesError_MapsKnownSentinels)
}

func testClassifyAppsError_Categories(t *rapid.T) {
	// After removing the legacy string-matching fallback, all untyped errors
	// (i.e., plain errors.New without errs.Wrap) map to errs.Internal.
	// Only typed errors (via errs package) and sentinel errors (apps.ErrAppNotFound)
	// get specific codes.
	msg := rapid.SampledFrom([]string{
		"not found",
		"SPRITE_TOKEN is not configured",
		"path is required",
		"timeout blew up",
	}).Draw(t, "msg")

	err := classifyAppsError(errors.New(msg), "run command")
	got := errs.CodeOf(err)
	if got != errs.Internal {
		t.Fatalf("untyped error %q should map to internal, got=%q", msg, got)
	}
}

func TestClassifyAppsError_Categories(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testClassifyAppsError_Categories)
}

func TestCreateToolHandler_UnknownTool_ShapedNotFoundError(t *testing.T) {
	t.Parallel()
	handler := NewHandler()
	call := handler.createToolHandler("tool_that_does_not_exist")

	// No services in context -- unknown tool should still return not_found
	result, _, err := call(context.Background(), &mcp.CallToolRequest{}, map[string]any{})
	if err != nil {
		t.Fatalf("createToolHandler returned transport error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("expected IsError result, got %#v", result)
	}

	payload := parseToolErrorPayload(t, result)
	if payload.Code != string(errs.NotFound) {
		t.Fatalf("unexpected error code: got=%q want=%q", payload.Code, errs.NotFound)
	}
	if !strings.Contains(strings.ToLower(payload.Message), "unknown tool") {
		t.Fatalf("unexpected error message: %q", payload.Message)
	}
}

func TestCreateToolHandler_NotesUnavailable_ShapedFailedPrecondition(t *testing.T) {
	t.Parallel()
	handler := NewHandler()
	call := handler.createToolHandler("note_list")

	// No notes service in context -> should return FailedPrecondition
	result, _, err := call(context.Background(), &mcp.CallToolRequest{}, map[string]any{})
	if err != nil {
		t.Fatalf("createToolHandler returned transport error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("expected IsError result, got %#v", result)
	}

	payload := parseToolErrorPayload(t, result)
	if payload.Code != string(errs.FailedPrecondition) {
		t.Fatalf("unexpected error code: got=%q want=%q", payload.Code, errs.FailedPrecondition)
	}
	if !strings.Contains(payload.Message, "notes tools are unavailable") {
		t.Fatalf("unexpected error message: %q", payload.Message)
	}
}

func TestCreateToolHandler_AppsUnavailable_ShapedFailedPrecondition(t *testing.T) {
	t.Parallel()
	handler := NewHandler()
	call := handler.createToolHandler("app_list")

	// No apps service in context -> should return FailedPrecondition
	result, _, err := call(context.Background(), &mcp.CallToolRequest{}, map[string]any{})
	if err != nil {
		t.Fatalf("createToolHandler returned transport error: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("expected IsError result, got %#v", result)
	}

	payload := parseToolErrorPayload(t, result)
	if payload.Code != string(errs.FailedPrecondition) {
		t.Fatalf("unexpected error code: got=%q want=%q", payload.Code, errs.FailedPrecondition)
	}
	if !strings.Contains(payload.Message, "app tools are unavailable") {
		t.Fatalf("unexpected error message: %q", payload.Message)
	}
}

func TestMarshalAny_InvalidValue_DoesNotPanic(t *testing.T) {
	t.Parallel()
	ch := make(chan int)
	data := map[string]any{"bad": ch}
	if got := marshalAny(data); got != nil {
		t.Fatalf("expected nil for unmarshalable value, got=%q", string(got))
	}
}

func TestClassifyAppsError_PassthroughCodedError(t *testing.T) {
	t.Parallel()
	input := errs.New(errs.PermissionDenied, "forbidden")
	got := classifyAppsError(input, "delete app")
	if errs.CodeOf(got) != errs.PermissionDenied {
		t.Fatalf("expected passthrough code=%q, got=%q", errs.PermissionDenied, errs.CodeOf(got))
	}
}

func TestClassifyNotesError_PassthroughCodedError(t *testing.T) {
	t.Parallel()
	input := errs.New(errs.NotFound, "missing note")
	got := classifyNotesError(input, "read note")
	if errs.CodeOf(got) != errs.NotFound {
		t.Fatalf("expected passthrough code=%q, got=%q", errs.NotFound, errs.CodeOf(got))
	}
}

func TestNewToolResultError_UsesStableJSONShape(t *testing.T) {
	t.Parallel()
	result := newToolResultError(errs.New(errs.InvalidArgument, "bad input"))
	if result == nil || !result.IsError {
		t.Fatalf("expected IsError tool result, got %#v", result)
	}
	payload := parseToolErrorPayload(t, result)
	if payload.Code != string(errs.InvalidArgument) || payload.Message != "bad input" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestHandleToolCall_UnknownToolReturnsCodedError(t *testing.T) {
	t.Parallel()
	handler := NewHandler()
	_, err := handler.HandleToolCall(context.Background(), "does_not_exist", map[string]any{})
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
	if errs.CodeOf(err) != errs.NotFound {
		t.Fatalf("unexpected code: got=%q want=%q", errs.CodeOf(err), errs.NotFound)
	}
}

func TestRequireNotesAndApps(t *testing.T) {
	t.Parallel()
	// Without services in context, require should fail
	ctx := context.Background()
	if _, err := requireNotes(ctx); errs.CodeOf(err) != errs.FailedPrecondition {
		t.Fatalf("requireNotes code mismatch: got=%q want=%q", errs.CodeOf(err), errs.FailedPrecondition)
	}
	if _, err := requireApps(ctx); errs.CodeOf(err) != errs.FailedPrecondition {
		t.Fatalf("requireApps code mismatch: got=%q want=%q", errs.CodeOf(err), errs.FailedPrecondition)
	}

	// With services in context, require should succeed
	ctx = ContextWithServices(ctx, &notes.Service{}, &apps.Service{})
	if _, err := requireNotes(ctx); err != nil {
		t.Fatalf("requireNotes unexpected error: %v", err)
	}
	if _, err := requireApps(ctx); err != nil {
		t.Fatalf("requireApps unexpected error: %v", err)
	}
}
