//go:build sprite
// +build sprite

package browser

import (
	"strings"
	"testing"

	"github.com/kuitang/agent-notes/tests/browser/internal/appseed"
	"github.com/playwright-community/playwright-go"

	"github.com/kuitang/agent-notes/tests/browser/internal/spriteutil"
)

func TestBrowser_AppDetail_LogsShowPost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	env := SetupBrowserTestEnv(t)
	if env.SpriteToken == "" {
		t.Skip("SPRITE_TOKEN required")
	}
	env.InitBrowser(t)

	ctx := env.NewContext(t)
	defer ctx.Close()

	emailAddr := GenerateUniqueEmail("logs-app")
	userID := env.LoginUser(t, ctx, emailAddr)
	sessionID := env.LoginAs(t, userID)

	appName := GenerateUniqueAppName("logs")
	publicURL := appseed.SeedApp(t, env.BaseURL, sessionID, appName)

	postPage, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	postPage.SetDefaultTimeout(spriteutil.SpriteTimeoutMS)
	postPage.SetDefaultNavigationTimeout(spriteutil.SpriteTimeoutMS)

	_, err = postPage.Goto(publicURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		Timeout:   playwright.Float(spriteutil.SpriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to navigate to public URL: %v", err)
	}

	msgInput := postPage.Locator("input#msg")
	err = msgInput.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteutil.SpriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Message input not visible: %v", err)
	}
	msgInput.Fill("logtest")
	postPage.Locator("button#send").Click()
	postPage.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateDomcontentloaded,
	})
	postPage.Close()

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()
	page.SetDefaultTimeout(spriteutil.SpriteTimeoutMS)
	page.SetDefaultNavigationTimeout(spriteutil.SpriteTimeoutMS)

	spriteutil.NavigateSprite(t, page, env.BaseURL, "/apps/"+appName)

	logOutput := page.Locator("#log-output")
	_, err = page.WaitForFunction(`() => {
		const el = document.getElementById('log-output');
		return el && el.textContent.includes('POST');
	}`, nil, playwright.PageWaitForFunctionOptions{
		Timeout: playwright.Float(spriteutil.SpriteTimeoutMS),
	})
	if err != nil {
		logText, _ := logOutput.TextContent()
		t.Fatalf("Log output does not contain 'POST' (got: %s): %v", logText, err)
	}

	logText, _ := logOutput.TextContent()
	if !strings.Contains(logText, "POST") || !strings.Contains(logText, "msg=") {
		t.Errorf("Logs should show POST with msg=, got: %s", logText)
	}
}
