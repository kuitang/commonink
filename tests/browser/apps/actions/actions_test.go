package browser

import (
	"strings"
	"testing"

	"github.com/kuitang/agent-notes/tests/browser/internal/appseed"
	"github.com/playwright-community/playwright-go"
)

const spriteTimeoutMS = 5000

func navigateSprite(t *testing.T, page playwright.Page, baseURL, path string) {
	t.Helper()
	_, err := page.Goto(baseURL+path, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		Timeout:   playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Failed to navigate to %s: %v", path, err)
	}
}

func TestBrowser_AppDetail_ActionButtons(t *testing.T) {
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

	emailAddr := GenerateUniqueEmail("action-app")
	userID := env.LoginUser(t, ctx, emailAddr)
	sessionID := env.LoginAs(t, userID)

	appName := GenerateUniqueAppName("action")
	appseed.SeedApp(t, env.BaseURL, sessionID, appName)

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer page.Close()
	page.SetDefaultTimeout(spriteTimeoutMS)
	page.SetDefaultNavigationTimeout(spriteTimeoutMS)

	navigateSprite(t, page, env.BaseURL, "/apps/"+appName)

	startBtn := page.Locator("#btn-start")
	err = startBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Start button not visible: %v", err)
	}

	restartBtn := page.Locator("#btn-restart")
	err = restartBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Restart button not visible: %v", err)
	}

	stopBtn := page.Locator("#btn-stop")
	err = stopBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(spriteTimeoutMS),
	})
	if err != nil {
		t.Fatalf("Stop button not visible: %v", err)
	}

	actionOutput := page.Locator("#action-result pre")
	waitForAction := func(action string) string {
		_, err = page.WaitForFunction(`(act) => {
			const el = document.querySelector('#action-result pre');
			if (!el) return false;
			const text = (el.textContent || '').toLowerCase();
			if (!text) return false;
			return text.indexOf(('running ' + act + '...').toLowerCase()) === -1;
		}`, action, playwright.PageWaitForFunctionOptions{
			Timeout: playwright.Float(spriteTimeoutMS),
		})
		if err != nil {
			text, _ := actionOutput.TextContent()
			t.Fatalf("Action %q did not complete (output: %q): %v", action, text, err)
		}
		text, _ := actionOutput.TextContent()
		lower := strings.ToLower(text)
		if strings.Contains(lower, "error") || strings.Contains(lower, "service not found") || strings.Contains(lower, "requested url returned error") {
			t.Fatalf("Action %q failed: %q", action, text)
		}
		return text
	}

	if err := stopBtn.Click(); err != nil {
		t.Fatalf("Failed to click stop: %v", err)
	}
	waitForAction("stop")

	if err := startBtn.Click(); err != nil {
		t.Fatalf("Failed to click start: %v", err)
	}
	waitForAction("start")

	if err := restartBtn.Click(); err != nil {
		t.Fatalf("Failed to click restart: %v", err)
	}
	waitForAction("restart")
}
