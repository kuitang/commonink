//go:build sprite
// +build sprite

package claude

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kuitang/agent-notes/tests/e2e/testutil"
)

func TestClaude_AppTools_Targeted(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}
	if strings.TrimSpace(os.Getenv("SPRITE_TOKEN")) == "" {
		t.Skip("SPRITE_TOKEN not set")
	}

	srv := testutil.GetServer(t)
	creds := testutil.PerformOAuthFlow(t, srv.BaseURL, "ClaudeAppTargeted")
	mcpClient := testutil.NewMCPClient(srv.BaseURL, creds.AccessToken)
	assertClaudePromptExists(t, mcpClient)
	mcpConfig := getAuthenticatedMCPConfig(t, creds.AccessToken)

	base := fmt.Sprintf("%s-%d", testutil.PrefixWithRunID("cl-target"), time.Now().UnixNano()%1000000)
	nameA := base + "-a"
	nameB := base + "-b"
	prompt := fmt.Sprintf(
		"Test app tools in order: 0) app_list and report currently active apps; 1) app_create with candidate names ['%s','%s']; 2) app_list; 3) app_bash with command 'echo tool-check'; 4) app_delete for the created app.",
		nameA, nameB,
	)

	resp, toolCalls := runOneShotClaude(t, mcpConfig, prompt)
	t.Logf("Response: %s", resp)
	t.Logf("Tool calls: %d", len(toolCalls))

	for _, expected := range []string{"app_create", "app_list", "app_bash", "app_delete"} {
		if !hasClaudeToolCall(toolCalls, expected) {
			t.Fatalf("Expected Claude to call %s, calls=%+v", expected, toolCalls)
		}
	}
}

func TestClaude_AppWorkflow_OneShot(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}
	if strings.TrimSpace(os.Getenv("SPRITE_TOKEN")) == "" {
		t.Skip("SPRITE_TOKEN not set")
	}

	srv := testutil.GetServer(t)
	creds := testutil.PerformOAuthFlow(t, srv.BaseURL, "ClaudeAppWorkflow")
	mcpClient := testutil.NewMCPClient(srv.BaseURL, creds.AccessToken)
	assertClaudePromptExists(t, mcpClient)
	mcpConfig := getAuthenticatedMCPConfig(t, creds.AccessToken)

	base := fmt.Sprintf("%s-%d", testutil.PrefixWithRunID("cl-workflow"), time.Now().UnixNano()%1000000)
	nameA := base + "-a"
	nameB := base + "-b"
	prompt := fmt.Sprintf(
		"make me a todo list app. Use app_create with candidate names ['%s','%s'] before writing code.",
		nameA, nameB,
	)

	resp, toolCalls := runOneShotClaude(t, mcpConfig, prompt)
	t.Logf("Response: %s", resp)
	t.Logf("Tool calls: %d", len(toolCalls))

	for _, expected := range []string{"app_create", "app_write", "app_bash"} {
		if !hasClaudeToolCall(toolCalls, expected) {
			t.Fatalf("Expected Claude to call %s, calls=%+v", expected, toolCalls)
		}
	}

	assertClaudeAppURLLive(t, mcpClient, base)
}
