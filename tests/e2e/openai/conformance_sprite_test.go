//go:build sprite
// +build sprite

package openai

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kuitang/agent-notes/tests/e2e/testutil"
)

func TestOpenAI_AppTools_Targeted(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping OpenAI test in short mode")
	}
	if strings.TrimSpace(os.Getenv("SPRITE_TOKEN")) == "" {
		t.Skip("SPRITE_TOKEN not set")
	}

	env := setupTestEnv(t)
	assertOpenAIPromptExists(t, env)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	base := fmt.Sprintf("oa-target-%d", time.Now().UnixNano()%1000000)
	nameA := base + "-a"
	nameB := base + "-b"
	prompt := fmt.Sprintf(
		"Test app tools in order: 0) app_list and report currently active apps; 1) app_create with candidate names ['%s','%s']; 2) app_list; 3) app_bash with command 'echo tool-check'; 4) app_delete for the created app.",
		nameA, nameB,
	)

	resp, toolCalls, _, err := env.runConversation(ctx, t, prompt, "")
	if err != nil {
		t.Fatalf("Targeted app tool test failed: %v", err)
	}
	t.Logf("Response: %s", resp)
	t.Logf("Tool calls: %d", len(toolCalls))

	for _, expected := range []string{"app_create", "app_list", "app_bash", "app_delete"} {
		if !hasOpenAIToolCall(toolCalls, expected) {
			t.Fatalf("Expected OpenAI to call %s, calls=%+v", expected, toolCalls)
		}
	}
}

func TestOpenAI_AppWorkflow_Integration(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping OpenAI test in short mode")
	}
	if strings.TrimSpace(os.Getenv("SPRITE_TOKEN")) == "" {
		t.Skip("SPRITE_TOKEN not set")
	}

	env := setupTestEnv(t)
	assertOpenAIPromptExists(t, env)
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	base := fmt.Sprintf("oa-workflow-%d", time.Now().UnixNano()%1000000)
	nameA := base + "-a"
	nameB := base + "-b"
	prompt := fmt.Sprintf(
		"make me a todo list app. Use app_create with candidate names ['%s','%s'] before writing code.",
		nameA, nameB,
	)

	resp, toolCalls, _, err := env.runConversation(ctx, t, prompt, "")
	if err != nil {
		t.Fatalf("App workflow failed: %v", err)
	}
	t.Logf("Response: %s", resp)
	t.Logf("Tool calls: %d", len(toolCalls))

	for _, expected := range []string{"app_create", "app_write", "app_bash"} {
		if !hasOpenAIToolCall(toolCalls, expected) {
			t.Fatalf("Expected OpenAI to call %s, calls=%+v", expected, toolCalls)
		}
	}

	assertOpenAIAppURLLive(t, env, base)
}
