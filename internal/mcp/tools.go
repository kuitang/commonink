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
			Description: "Notes tool. Read a note's full content with line numbers (tab-separated, 1-indexed) for reference. Optionally pass line_range as [start, end] (1-indexed, inclusive; end=-1 means end of file) to view a specific portion. The response includes total_lines and revision_hash (a content-based hash for optimistic concurrency control). Use this after note_list or note_search to read complete content.",
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
			Description: "Notes tool. Create a new note with a title and optional content. Use this when the user wants a note (not an app). Users can create either notes or apps; app creation is handled by app_create. Returns the assigned ID, title, line count, and creation timestamp (not the content, since you already know it). Use note_view to read back content. Content can be omitted to create an empty note for later editing with note_update or note_edit.",
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
			Description: "Notes tool. Replace a note's title and/or content entirely. Pass 'title' to change the title, 'content' to replace the full body, or both. For surgical edits to specific text within a note, use note_edit instead. prior_hash is REQUIRED: call note_view first, then pass its revision_hash as prior_hash. If prior_hash mismatches current content, update fails with a revision conflict. Returns the ID, title, line count, updated timestamp, and new revision_hash.",
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
			Description: "Notes tool. Make a surgical text edit within a note using find-and-replace. Pass 'old_string' (the exact text to find) and 'new_string' (the replacement). The edit fails if old_string is not found or matches multiple locations. Set 'replace_all' to true to replace every occurrence (default false). prior_hash is REQUIRED: call note_view first, then pass its revision_hash as prior_hash. Mismatches fail with revision conflict. Returns the ID, updated timestamp, replacement count, snippet around the edit site, and new revision_hash. For full content replacement, use note_update instead.",
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
			Description: "Notes tool. Search notes across titles and content. Supports FTS5 syntax: AND, OR, NOT, prefix*, NEAR(), column filters (title:, content:). Simple queries work as implicit AND. Title matches are weighted 5x higher than content matches. Returns ranked results with a contextual snippet (matched terms in **bold**). Use note_view to read full content.",
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
			Description: "Notes tool. List notes with title, a short preview (first 2 lines of content), and total line count. Returns paginated results ordered by most recently updated. Use note_view to read a complete note. Accepts optional limit (default 50, max 1000) and offset (default 0) for pagination.",
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
			Description: "Notes tool. Move a note to trash by its ID. The note becomes invisible but is retained for 30 days and can be restored. After 30 days, it is permanently deleted. Returns a confirmation message on success, or an error if the note does not exist.",
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
			Description: "Apps tool. Create a public Fly Sprite app by trying candidate names in order. Use this when the user wants an app (not a note). Users can create either notes or apps; note creation is handled by note_create. Pass an ordered array of candidate names. The server returns the chosen name or structured rejections for each candidate. If all are rejected, try another name. The app workspace root is /home/sprite. After create, use app_write for files, then app_bash to install dependencies and launch service on port 8080. If user does not specify a stack (e.g., says 'make me a todo list app'), default to a minimal Flask app: app.py + requirements.txt, then register sprite-env service on port 8080.",
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
			Description: "Apps tool. Write one or more files on the app Sprite in a single request. Paths are always rooted under /home/sprite (the runtime workspace root). Use this for source code, templates, config, and static assets.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app": map[string]any{
						"type":        "string",
						"description": "App name returned by app_create.",
					},
					"files": map[string]any{
						"type":        "array",
						"description": "Files to write. Each path is relative to /home/sprite.",
						"minItems":    1,
						"maxItems":    64,
						"items": map[string]any{
							"type":                 "object",
							"additionalProperties": false,
							"properties": map[string]any{
								"path": map[string]any{
									"type":        "string",
									"description": "Path relative to /home/sprite.",
									"maxLength":   1024,
								},
								"content": map[string]any{
									"type":        "string",
									"description": "Full file content to write.",
									"maxLength":   1048576,
								},
							},
							"required": []string{"path", "content"},
						},
					},
				},
				"required": []string{"app", "files"},
			},
		},
		{
			Name:        "app_read",
			Description: "Apps tool. Read one or more files from the app Sprite. Paths are always rooted under /home/sprite. The response shape matches app_write input: {app, files:[{path,content}]}.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app": map[string]any{
						"type":        "string",
						"description": "App name returned by app_create.",
					},
					"files": map[string]any{
						"type":        "array",
						"description": "Files to read. Each item identifies one path relative to /home/sprite.",
						"minItems":    1,
						"maxItems":    64,
						"items": map[string]any{
							"type":                 "object",
							"additionalProperties": false,
							"properties": map[string]any{
								"path": map[string]any{
									"type":        "string",
									"description": "Path relative to /home/sprite.",
									"maxLength":   1024,
								},
							},
							"required": []string{"path"},
						},
					},
				},
				"required": []string{"app", "files"},
			},
		},
		{
			Name:        "app_bash",
			Description: "Apps tool. Run a shell command on the app Sprite. Every app_bash invocation starts in /home/sprite; directory changes (cd) do not persist across separate app_bash calls. Use for install/build/debug/deploy operations. Optional timeout_seconds defaults to 120 and maxes at 600. Response includes runtime_ms and bounded stdout/stderr (with truncation flags when output is clipped). app_bash does not auto-append filesystem listings. The app must listen on port 8080. For persistent runtime, pass command and arguments separately (do not pass a space-joined shell string to --cmd). Examples to run via app_bash: sprite-env services list ; sprite-env services create web --cmd python3 --args /home/sprite/server.py --http-port 8080 ; curl -sf http://localhost:8080 ; tail -n 100 /.sprite/logs/services/web.log. When stack is unspecified, use Flask conventions and verify with curl http://localhost:8080.",
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
						"maxLength":   32768,
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
			Description: "Apps tool. List all apps for the current user with status and public URL.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "app_delete",
			Description: "Apps tool. Delete an app and destroy its Fly Sprite. This cannot be undone.",
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
