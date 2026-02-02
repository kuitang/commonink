package mcp

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ToolDefinitions returns all 6 MCP tool definitions for notes CRUD
func ToolDefinitions() []*mcp.Tool {
	return []*mcp.Tool{
		{
			Name:        "note_view",
			Description: "Retrieve a single note by its ID",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "The unique identifier of the note to retrieve",
					},
				},
				"required": []string{"id"},
			},
		},
		{
			Name:        "note_create",
			Description: "Create a new note with a title and optional content",
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
			Description: "Update an existing note's title and/or content",
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
			Name:        "note_search",
			Description: "Search notes using full-text search (FTS5)",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "The search query to match against note titles and content",
					},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        "note_list",
			Description: "List notes with pagination support",
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
			Description: "Delete a note by its ID",
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
