package mcp

import "github.com/modelcontextprotocol/go-sdk/mcp"

// Toolset controls which tool families are mounted for a route.
type Toolset string

const (
	ToolsetAll   Toolset = "all"
	ToolsetNotes Toolset = "notes"
	ToolsetApps  Toolset = "apps"
)

// ToolDefinitions returns tool definitions for the requested toolset.
func ToolDefinitions(toolset Toolset) []*mcp.Tool {
	notesTools := NoteToolDefinitions()
	appTools := AppToolDefinitions()

	switch toolset {
	case ToolsetNotes:
		return notesTools
	case ToolsetApps:
		return appTools
	default:
		all := make([]*mcp.Tool, 0, len(notesTools)+len(appTools))
		all = append(all, notesTools...)
		all = append(all, appTools...)
		return all
	}
}

// NoteToolDefinitions returns the notes MCP tool definitions.
func NoteToolDefinitions() []*mcp.Tool {
	return []*mcp.Tool{
		{
			Name:        "note_view",
			Description: "Read a note's full content with line numbers (tab-separated, 1-indexed) for reference. Optionally pass line_range as [start, end] (1-indexed, inclusive; end=-1 means end of file) to view a specific portion. The response includes total_lines and revision_hash (a content-based hash for optimistic concurrency control). Use this after note_list or note_search to read complete content.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "The unique identifier of the note to retrieve",
					},
					"line_range": map[string]any{
						"type":        "array",
						"description": "Optional [start, end] line range (1-indexed, inclusive). end=-1 means end of file.",
						"items":       map[string]any{"type": "integer"},
						"minItems":    2,
						"maxItems":    2,
					},
				},
				"required": []string{"id"},
			},
		},
		{
			Name:        "note_create",
			Description: "Create a new note with a title and optional content. Returns the assigned ID, title, line count, and creation timestamp (not the content, since you already know it). Use note_view to read back content. Content can be omitted to create an empty note for later editing with note_update or note_edit.",
			InputSchema: map[string]any{
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
				"required": []string{"title"},
			},
		},
		{
			Name:        "note_update",
			Description: "Replace a note's title and/or content entirely. Pass 'title' to change the title, 'content' to replace the full body, or both. For surgical edits to specific text within a note, use note_edit instead. prior_hash is REQUIRED: call note_view first, then pass its revision_hash as prior_hash. If prior_hash mismatches current content, update fails with a revision conflict. Returns the ID, title, line count, updated timestamp, and new revision_hash.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "The unique identifier of the note to update",
					},
					"title": map[string]any{
						"type":        "string",
						"description": "The new title for the note (optional)",
					},
					"content": map[string]any{
						"type":        "string",
						"description": "The new content for the note (optional)",
					},
					"prior_hash": map[string]any{
						"type":        "string",
						"description": "Required revision hash from note_view (revision_hash) to enforce optimistic concurrency",
					},
				},
				"required": []string{"id", "prior_hash"},
			},
		},
		{
			Name:        "note_edit",
			Description: "Make a surgical text edit within a note using find-and-replace. Pass 'old_string' (the exact text to find) and 'new_string' (the replacement). The edit fails if old_string is not found or matches multiple locations. Set 'replace_all' to true to replace every occurrence (default false). prior_hash is REQUIRED: call note_view first, then pass its revision_hash as prior_hash. Mismatches fail with revision conflict. Returns the ID, updated timestamp, replacement count, snippet around the edit site, and new revision_hash. For full content replacement, use note_update instead.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "The unique identifier of the note to edit",
					},
					"old_string": map[string]any{
						"type":        "string",
						"description": "The exact text to find in the note content",
					},
					"new_string": map[string]any{
						"type":        "string",
						"description": "The replacement text",
					},
					"replace_all": map[string]any{
						"type":        "boolean",
						"description": "Replace all occurrences of old_string (default false)",
					},
					"prior_hash": map[string]any{
						"type":        "string",
						"description": "Required revision hash from note_view (revision_hash) to enforce optimistic concurrency",
					},
				},
				"required": []string{"id", "old_string", "new_string", "prior_hash"},
			},
		},
		{
			Name:        "note_search",
			Description: "Search notes across titles and content. Supports FTS5 syntax: AND, OR, NOT, prefix*, NEAR(), column filters (title:, content:). Simple queries work as implicit AND. Title matches are weighted 5x higher than content matches. Returns ranked results with a contextual snippet (matched terms in **bold**). Use note_view to read full content.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "The search query. Supports FTS5 syntax (AND, OR, NOT, prefix*, NEAR) or plain text.",
					},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        "note_list",
			Description: "List notes with title, a short preview (first 2 lines of content), and total line count. Returns paginated results ordered by most recently updated. Use note_view to read a complete note. Accepts optional limit (default 50, max 1000) and offset (default 0) for pagination.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit": map[string]any{
						"type":        "integer",
						"description": "Maximum number of notes to return (default: 50, max: 1000)",
					},
					"offset": map[string]any{
						"type":        "integer",
						"description": "Number of notes to skip for pagination (default: 0)",
					},
				},
			},
		},
		{
			Name:        "note_delete",
			Description: "Move a note to trash by its ID. The note becomes invisible but is retained for 30 days and can be restored. After 30 days, it is permanently deleted. Returns a confirmation message on success, or an error if the note does not exist.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "The unique identifier of the note to delete",
					},
				},
				"required": []string{"id"},
			},
		},
	}
}

// AppToolDefinitions returns the app deployment MCP tool definitions.
func AppToolDefinitions() []*mcp.Tool {
	return []*mcp.Tool{
		{
			Name:        "app_create",
			Description: "Create a public Fly Sprite app by trying candidate names in order. Pass an ordered array of candidate names. The server returns the chosen name or structured rejections for each candidate. If all are rejected, try another name. After create, use app_write for files, then app_bash to install dependencies and launch service on port 8080. If user does not specify a stack (e.g., says 'make me a todo list app'), default to a minimal Flask app: app.py + requirements.txt, then register sprite-env service on port 8080.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"names": map[string]any{
						"type":        "array",
						"description": "Ordered candidate app names to try on Fly Sprites.",
						"items":       map[string]any{"type": "string"},
						"minItems":    1,
					},
				},
				"required": []string{"names"},
			},
		},
		{
			Name:        "app_write",
			Description: "Write a file on the app Sprite. Path is relative to /home/sprite. Use this for source code, templates, config, and static assets.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app": map[string]any{
						"type":        "string",
						"description": "App name returned by app_create.",
					},
					"path": map[string]any{
						"type":        "string",
						"description": "Path relative to /home/sprite.",
					},
					"content": map[string]any{
						"type":        "string",
						"description": "Full file content to write.",
					},
				},
				"required": []string{"app", "path", "content"},
			},
		},
		{
			Name:        "app_read",
			Description: "Read a file from the app Sprite. Path is relative to /home/sprite.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app": map[string]any{
						"type":        "string",
						"description": "App name returned by app_create.",
					},
					"path": map[string]any{
						"type":        "string",
						"description": "Path relative to /home/sprite.",
					},
				},
				"required": []string{"app", "path"},
			},
		},
		{
			Name:        "app_bash",
			Description: "Run a shell command on the app Sprite. Use for install/build/debug/deploy operations. Optional timeout_seconds defaults to 120 and maxes at 600. Response includes runtime_ms. The app must listen on port 8080. To register persistent runtime: sprite-env services create <name> --cmd '<command>' --http-port 8080. When stack is unspecified, use Flask conventions and verify with curl http://localhost:8080.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app": map[string]any{
						"type":        "string",
						"description": "App name returned by app_create.",
					},
					"command": map[string]any{
						"type":        "string",
						"description": "Command to run on the sprite shell.",
					},
					"timeout_seconds": map[string]any{
						"type":        "integer",
						"description": "Optional command timeout in seconds (default 120, max 600).",
					},
				},
				"required": []string{"app", "command"},
			},
		},
		{
			Name:        "app_list",
			Description: "List all apps for the current user with status and public URL.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "app_delete",
			Description: "Delete an app and destroy its Fly Sprite. This cannot be undone.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app": map[string]any{
						"type":        "string",
						"description": "App name to delete.",
					},
				},
				"required": []string{"app"},
			},
		},
	}
}
