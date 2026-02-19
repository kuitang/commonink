package mcp

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ToolDefinitions returns all 7 MCP tool definitions for notes operations
func ToolDefinitions() []*mcp.Tool {
	return []*mcp.Tool{
		{
			Name:        "note_view",
			Description: "Read a note's full content with line numbers (tab-separated, 1-indexed) for reference. Optionally pass line_range as [start, end] (1-indexed, inclusive; end=-1 means end of file) to view a specific portion. The response includes total_lines so you know the full document length. Use this after note_list or note_search to read complete content.",
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
			Description: "Replace a note's title and/or content entirely. Pass 'title' to change the title, 'content' to replace the full body, or both. For surgical edits to specific text within a note, use note_edit instead. Returns the ID, title, line count, and updated timestamp as confirmation (not the content).",
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
				},
				"required": []string{"id"},
			},
		},
		{
			Name:        "note_edit",
			Description: "Make a surgical text edit within a note using find-and-replace. Pass 'old_string' (the exact text to find) and 'new_string' (the replacement). The edit fails if old_string is not found or matches multiple locations. Set 'replace_all' to true to replace every occurrence. Returns the ID, updated timestamp, replacement count, and a line-numbered snippet around the edit site. For full content replacement, use note_update instead.",
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
				},
				"required": []string{"id", "old_string", "new_string"},
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
