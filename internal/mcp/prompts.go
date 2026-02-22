package mcp

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const accountWorkflowPromptName = "account_workflow"

func registerPrompts(mcpServer *mcp.Server, toolset Toolset) {
	for _, prompt := range PromptDefinitions(toolset) {
		promptCopy := prompt
		mcpServer.AddPrompt(promptCopy, promptHandler(toolset))
	}
}

// PromptDefinitions returns MCP prompt definitions for the selected toolset.
func PromptDefinitions(toolset Toolset) []*mcp.Prompt {
	return []*mcp.Prompt{
		{
			Name:        accountWorkflowPromptName,
			Title:       "Notes and apps workflow",
			Description: promptDescription(toolset),
		},
	}
}

func promptHandler(toolset Toolset) mcp.PromptHandler {
	description := promptDescription(toolset)
	text := promptText(toolset)

	return func(_ context.Context, _ *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{
			Description: description,
			Messages: []*mcp.PromptMessage{
				{
					Role:    mcp.Role("user"),
					Content: &mcp.TextContent{Text: text},
				},
			},
		}, nil
	}
}

func promptDescription(toolset Toolset) string {
	switch toolset {
	case ToolsetNotes:
		return "Decide whether the user needs note or app workflows; this endpoint serves notes."
	case ToolsetApps:
		return "Decide whether the user needs note or app workflows; this endpoint serves apps."
	default:
		return "Brief routing guidance for notes and deployable apps."
	}
}

func promptText(toolset Toolset) string {
	switch toolset {
	case ToolsetNotes:
		return "The user has one account that stores notes and apps. First decide if the request is about notes or apps. This endpoint is notes-only, so use note_* tools for note work and direct app work to app tools on the apps endpoint."
	case ToolsetApps:
		return "The user has one account that stores notes and apps. First decide if the request is about notes or apps. This endpoint is apps-only, so use app_* tools. For apps, install dependencies and deploy/run services with app_bash, and keep the service on port 8080."
	default:
		return "The user has one account that stores notes and apps. First decide if the request is about notes or apps. Use note_* tools for notes. Use app_* tools for apps; for apps, install dependencies and deploy/run services with app_bash on port 8080."
	}
}
